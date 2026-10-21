package catalog

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/rakeshnitb23/opfence/internal/classes"
	"github.com/rakeshnitb23/opfence/internal/decode"
)

// ProviderForHost returns the provider that owns host (lower case, no
// port): an exact host first, then the longest matching wildcard.
func (c *Catalog) ProviderForHost(host string) *Provider {
	var best *Provider
	bestLen := 0
	for _, p := range c.Providers {
		for _, h := range p.Hosts {
			if h == host {
				return p
			}
			if strings.HasPrefix(h, "*.") && strings.HasSuffix(host, h[1:]) && len(h) > bestLen {
				best, bestLen = p, len(h)
			}
		}
	}
	return best
}

// ProviderForMCPName returns the MCP provider users commonly name name.
func (c *Catalog) ProviderForMCPName(name string) *Provider {
	for _, p := range c.Providers {
		if p.MCP == nil {
			continue
		}
		for _, n := range p.MCP.Names {
			if n == name {
				return p
			}
		}
	}
	return nil
}

// Hints tells the decoder what the provider speaks on host.
func (p *Provider) Hints(host string) decode.Hints {
	return decode.Hints{GraphQLPaths: p.GraphQL, SigV4: p.SigV4, MCP: p.MCP != nil, Git: slices.Contains(p.Git, host)}
}

// Match returns the rule for op and any path parameters it captured, or nil
// when no rule applies. Draft rules are skipped unless includeDraft is set.
// Operations the decoder could not read never match.
func (p *Provider) Match(op decode.Operation, includeDraft bool) (*Rule, map[string]string) {
	if op.Error != "" {
		return nil, nil
	}
	var best *Rule
	var bestParams map[string]string
	var bestTmpl *Template
	bestGitRefs := false
	for _, r := range p.Rules {
		if r.Status == Draft && !includeDraft {
			continue
		}
		m := r.Match
		switch {
		case m.REST != nil && op.Protocol == decode.REST:
			if m.REST.Method != op.Method || m.REST.Template == nil {
				continue
			}
			params, ok := m.REST.Template.Match(op.Path)
			if ok && (bestTmpl == nil || m.REST.Template.MoreSpecific(bestTmpl)) {
				best, bestParams, bestTmpl = r, params, m.REST.Template
			}
		case m.GraphQL != nil && op.Protocol == decode.GraphQL:
			if m.GraphQL.Type == op.GraphQLType && m.GraphQL.Field == op.Field {
				return r, nil
			}
		case m.MCP != nil && op.Protocol == decode.MCP:
			if op.Tool != "" && m.MCP.Tool == op.Tool {
				return r, nil
			}
		case m.AWS != nil && op.Protocol == decode.AWS:
			if m.AWS.Service != op.Service {
				continue
			}
			if m.AWS.Action != "" {
				if op.Action == m.AWS.Action {
					return r, nil
				}
				continue
			}
			if op.Action != "" || m.AWS.Method != op.Method || m.AWS.Template == nil {
				continue
			}
			params, ok := m.AWS.Template.Match(op.Path)
			if ok && (bestTmpl == nil || m.AWS.Template.MoreSpecific(bestTmpl)) {
				best, bestParams, bestTmpl = r, params, m.AWS.Template
			}
		case m.Git != nil && op.Protocol == decode.Git:
			if m.Git.Service != op.Service || m.Git.Command != op.Action {
				continue
			}
			if len(m.Git.Refs) == 0 {
				if best == nil {
					best = r
				}
				continue
			}
			// Validation keeps ref patterns of one command from overlapping.
			if ref, _ := op.Args["ref"].(string); m.Git.MatchesRef(ref) && !bestGitRefs {
				best, bestGitRefs = r, true
			}
		}
	}
	return best, bestParams
}

var awsReadPrefixes = []string{"Describe", "Get", "List", "Head", "BatchGet"}

// IsAWSReadAction reports whether an AWS action is a read by its name:
// Describe*, Get*, List*, Head*, BatchGet*, Scan or Query.
func IsAWSReadAction(action string) bool {
	if action == "Scan" || action == "Query" {
		return true
	}
	for _, pre := range awsReadPrefixes {
		if strings.HasPrefix(action, pre) && len(action) > len(pre) {
			return true
		}
	}
	return false
}

// DefaultClass classifies an operation no rule matched, from the provider's
// defaults and the MCP protocol. It returns Unknown when nothing applies.
func (p *Provider) DefaultClass(op decode.Operation) (classes.Class, string) {
	if op.Error != "" {
		return classes.Unknown, "decoder: " + op.Error
	}
	d := p.Defaults
	switch op.Protocol {
	case decode.GraphQL:
		if op.GraphQLType == "query" && d.GraphQLQuery != "" {
			return d.GraphQLQuery, "provider default for GraphQL queries"
		}
	case decode.REST:
		if (op.Method == "GET" || op.Method == "HEAD" || op.Method == "OPTIONS") && d.RESTSafeMethods != "" {
			return d.RESTSafeMethods, "provider default for " + op.Method
		}
	case decode.AWS:
		if d.AWSReadActions != "" && IsAWSReadAction(op.Action) {
			return d.AWSReadActions, "provider default for AWS read actions"
		}
	case decode.MCP:
		switch {
		case op.MCPMethod == "tools/call":
		case decode.IsMCPReadMethod(op.MCPMethod), op.MCPMethod == decode.MCPResponse,
			op.MCPMethod == "http GET", op.MCPMethod == "http DELETE", op.MCPMethod == "http HEAD":
			return classes.Read, "MCP protocol message"
		}
	}
	return classes.Unknown, "no rule matches"
}

// ClassesFor returns the classes a matched rule assigns to an operation whose
// arguments are args, and why. Most rules return one class; SQL
// classification can return several, one per kind of statement.
func (r *Rule) ClassesFor(op decode.Operation, args map[string]any) ([]classes.Class, string) {
	if op.BodyErr != "" && r.readsBody() {
		return []classes.Class{classes.Unknown}, "rule depends on a body that could not be read: " + op.BodyErr
	}
	// Every condition that holds contributes its class, so the order of
	// when entries never hides a stricter one.
	var hit []classes.Class
	var why []string
	for i, w := range r.When {
		if w.If.Eval(args) {
			if !slices.Contains(hit, w.Class) {
				hit = append(hit, w.Class)
			}
			why = append(why, fmt.Sprintf("%d (%s)", i+1, w.If.String()))
		}
	}
	if len(hit) > 0 {
		label := "rule condition "
		if len(why) > 1 {
			label = "rule conditions "
		}
		return hit, label + strings.Join(why, ", ")
	}
	if r.Classify != nil && len(r.Classify.SQL) > 0 {
		out := r.Classify.classes(args)
		if out == nil {
			return []classes.Class{r.Class}, "rule class (no SQL in " + r.Classify.String() + ")"
		}
		// A rule's class is its worst case, and SQL Opfence cannot read
		// gets it: classifying SQL never decides more loosely than the
		// rule would without it.
		if slices.Contains(out, classes.Unknown) && !slices.Contains(out, r.Class) {
			out = append(out, r.Class)
		}
		return out, "SQL in " + r.Classify.String()
	}
	return []classes.Class{r.Class}, "rule class"
}

// classes classifies the SQL in args, or returns nil when there is none or
// an argument holds something other than SQL.
func (c *Classify) classes(args map[string]any) []classes.Class {
	var out []classes.Class
	add := func(cs []classes.Class) {
		for _, x := range cs {
			if !slices.Contains(out, x) {
				out = append(out, x)
			}
		}
	}
	if c.Format == FormatLibSQL {
		v, _ := Lookup(args, c.SQL[0])
		texts, unread, ok := decode.LibSQLStatements(v)
		if !ok {
			return nil
		}
		for _, t := range texts {
			add(decode.ClassifySQLite(t))
		}
		if unread {
			add([]classes.Class{classes.Unknown})
		}
		if out == nil {
			out = []classes.Class{classes.Read} // only closes, autocommit checks and describes
		}
		return out
	}
	var texts []string
	found := false
	for _, p := range c.SQL {
		v, ok := Lookup(args, p)
		if !ok {
			continue
		}
		found = true
		t, ok := sqlTexts(v)
		if !ok {
			return nil
		}
		texts = append(texts, t...)
	}
	if !found {
		return nil
	}
	for _, t := range texts {
		for _, d := range c.Dialects() {
			add(decode.ClassifySQLDialect(d, t))
		}
	}
	return out // nil for an empty list of statements: the rule's class
}

// sqlTexts reads an argument holding SQL: one string, or a list of strings
// (a transaction's statements), each classified on its own so an
// unterminated quote in one cannot hide the next.
func sqlTexts(v any) ([]string, bool) {
	switch t := v.(type) {
	case string:
		return []string{t}, true
	case []any:
		out := make([]string, 0, len(t))
		for _, el := range t {
			s, ok := el.(string)
			if !ok {
				return nil, false
			}
			out = append(out, s)
		}
		return out, true
	}
	return nil, false
}

func (r *Rule) readsBody() bool {
	if r.Classify != nil {
		for _, p := range r.Classify.SQL {
			if p == "body" || strings.HasPrefix(p, "body.") {
				return true
			}
		}
	}
	for _, w := range r.When {
		if w.If.Arg == "body" || strings.HasPrefix(w.If.Arg, "body.") {
			return true
		}
	}
	return false
}

// Lookup follows a dotted path through nested maps. A list on the way is
// looked through: the path continues into every element and the values found
// are returned as a list, so "refUpdates.force" finds the force flag of each
// update in a batch.
func Lookup(args map[string]any, path string) (any, bool) {
	return lookup(args, strings.Split(path, "."))
}

func lookup(cur any, parts []string) (any, bool) {
	if len(parts) == 0 {
		return cur, true
	}
	switch t := cur.(type) {
	case map[string]any:
		next, ok := t[parts[0]]
		if !ok {
			return nil, false
		}
		return lookup(next, parts[1:])
	case []any:
		var found []any
		for _, el := range t {
			v, ok := lookup(el, parts)
			if !ok {
				continue
			}
			if l, isList := v.([]any); isList {
				found = append(found, l...)
			} else {
				found = append(found, v)
			}
		}
		if found == nil {
			return nil, false
		}
		return found, true
	}
	return nil, false
}

// Scalar renders a scalar argument as text, reporting false for lists,
// objects and null.
func Scalar(v any) (string, bool) {
	switch t := v.(type) {
	case string:
		return t, true
	case json.Number:
		return t.String(), true
	case bool:
		if t {
			return "true", true
		}
		return "false", true
	case int:
		return fmt.Sprint(t), true
	case int64:
		return fmt.Sprint(t), true
	case float64:
		return fmt.Sprint(t), true
	}
	return "", false
}

// Eval reports whether the condition holds for args. Comparisons are
// case-insensitive, so "True" cannot slip past equals: "true". When the
// argument is a list (a repeated query parameter, or a value found inside a
// list), the condition holds if it holds for any element: a request cannot
// hide "decrypt=true" behind an earlier "decrypt=false". Rules therefore use
// conditions to make a class stricter, never to relax it.
func (c *Condition) Eval(args map[string]any) bool {
	v, ok := Lookup(args, c.Arg)
	vals := []any{v}
	if l, isList := v.([]any); isList {
		vals = l
	}
	// An explicit null counts as present: in a PATCH body it usually clears
	// the setting ("ssoProtection": null turns protection off).
	present := ok
	switch {
	case c.Present:
		return present
	case c.Absent:
		return !present
	case c.Empty:
		return isEmpty(v)
	}
	for _, el := range vals {
		if s, isScalar := Scalar(el); isScalar && c.match(s) {
			return true
		}
	}
	return false
}

// isEmpty reports whether v selects or sets nothing: a missing value, null,
// "", {} or []. An empty filter matches every document, so "filter": {} is
// as bad as no filter.
func isEmpty(v any) bool {
	switch t := v.(type) {
	case nil:
		return true
	case string:
		return t == ""
	case map[string]any:
		return len(t) == 0
	case []any:
		return len(t) == 0
	}
	return false
}

func (c *Condition) match(s string) bool {
	switch {
	case c.Equals != nil:
		return strings.EqualFold(s, *c.Equals)
	case c.In != nil:
		for _, want := range c.In {
			if strings.EqualFold(s, want) {
				return true
			}
		}
		return false
	case c.re != nil:
		return c.re.MatchString(s)
	}
	return false
}

// String describes the condition for explanations.
func (c *Condition) String() string {
	switch {
	case c.Present:
		return c.Arg + " is present"
	case c.Absent:
		return c.Arg + " is absent"
	case c.Empty:
		return c.Arg + " is empty"
	case c.Equals != nil:
		return fmt.Sprintf("%s = %q", c.Arg, *c.Equals)
	case c.In != nil:
		return fmt.Sprintf("%s in %q", c.Arg, c.In)
	case c.Matches != "":
		return fmt.Sprintf("%s matches %q", c.Arg, c.Matches)
	}
	return c.Arg
}
