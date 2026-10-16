package catalog

import (
	"encoding/json"
	"fmt"
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

// Hints tells the decoder what the provider speaks.
func (p *Provider) Hints() decode.Hints {
	return decode.Hints{GraphQLPaths: p.GraphQL, SigV4: p.SigV4, MCP: p.MCP != nil}
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
		}
	}
	return best, bestParams
}

var awsReadPrefixes = []string{"Describe", "Get", "List", "Head", "BatchGet"}

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
		if d.AWSReadActions != "" && op.Action != "" {
			if op.Action == "Scan" || op.Action == "Query" {
				return d.AWSReadActions, "provider default for AWS read actions"
			}
			for _, pre := range awsReadPrefixes {
				if strings.HasPrefix(op.Action, pre) && len(op.Action) > len(pre) {
					return d.AWSReadActions, "provider default for AWS read actions"
				}
			}
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
	for i, w := range r.When {
		if w.If.Eval(args) {
			return []classes.Class{w.Class}, fmt.Sprintf("rule condition %d (%s)", i+1, w.If.String())
		}
	}
	if r.Classify != nil && r.Classify.SQL != "" {
		v, ok := Lookup(args, r.Classify.SQL)
		s, isStr := v.(string)
		if !ok || !isStr {
			return []classes.Class{r.Class}, "rule class (no SQL in " + r.Classify.SQL + ")"
		}
		return decode.ClassifySQL(s), "SQL in " + r.Classify.SQL
	}
	return []classes.Class{r.Class}, "rule class"
}

func (r *Rule) readsBody() bool {
	if r.Classify != nil && strings.HasPrefix(r.Classify.SQL, "body.") {
		return true
	}
	for _, w := range r.When {
		if w.If.Arg == "body" || strings.HasPrefix(w.If.Arg, "body.") {
			return true
		}
	}
	return false
}

// Lookup follows a dotted path through nested maps.
func Lookup(args map[string]any, path string) (any, bool) {
	var cur any = args
	for _, part := range strings.Split(path, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		if cur, ok = m[part]; !ok {
			return nil, false
		}
	}
	return cur, true
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
// case-insensitive, so "True" cannot slip past equals: "true".
func (c *Condition) Eval(args map[string]any) bool {
	v, ok := Lookup(args, c.Arg)
	present := ok && v != nil
	switch {
	case c.Present:
		return present
	case c.Absent:
		return !present
	}
	s, isScalar := Scalar(v)
	if !present || !isScalar {
		return false
	}
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
	case c.Equals != nil:
		return fmt.Sprintf("%s = %q", c.Arg, *c.Equals)
	case c.In != nil:
		return fmt.Sprintf("%s in %q", c.Arg, c.In)
	case c.Matches != "":
		return fmt.Sprintf("%s matches %q", c.Arg, c.Matches)
	}
	return c.Arg
}
