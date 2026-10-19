// Package drift compares catalog rules with the published schemas they were
// built from (`opfence catalog check-sources`, docs/ARCHITECTURE.md §4.7):
// rules whose operation has left the schema are stale, and operations the
// schema gained that no rule matches are uncovered.
package drift

import (
	"context"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/rakeshnitb23/opfence/internal/catalog"
)

// Op is one operation a schema defines.
type Op struct {
	// Kind is rest, graphql or aws.
	Kind string
	// REST and botocore REST-protocol operations: method and path template
	// (with the schema's base path).
	Method, Path string
	// GraphQL: query, mutation or subscription, and the root field.
	Type, Field string
	// AWS: the SigV4 service and the action name.
	Service, Action string
	// Partial marks operations from a coverage: partial schema, which are
	// listed but do not fail the check when uncovered.
	Partial bool
	// Foreign marks an OpenAPI operation whose own servers are on hosts the
	// provider does not list; it is left out of the comparison.
	Foreign bool
	// Ref is the URL of the file an OpenAPI operation is a $ref to. Its
	// servers are read only when the operation would be uncovered.
	Ref string
}

func (o Op) String() string {
	switch o.Kind {
	case "graphql":
		return o.Type + " " + o.Field
	case "aws":
		if o.Path != "" {
			return o.Service + " " + o.Action + " (" + o.Method + " " + o.Path + ")"
		}
		return o.Service + " " + o.Action
	}
	return o.Method + " " + o.Path
}

// Fetcher downloads a schema.
type Fetcher func(ctx context.Context, url string) ([]byte, error)

// Finding is one problem in a provider.
type Finding struct {
	Rule *catalog.Rule // stale rules and unlisted rules now in the schema
	Op   *Op           // uncovered operations
	// Partial: an uncovered operation of a partial schema, listed only.
	Partial bool
	Note    string
}

// ProviderReport is the result for one provider.
type ProviderReport struct {
	Provider  *catalog.Provider
	Schemas   int
	Ops       int
	Compared  int // rules compared with the schemas
	Stale     []Finding
	Uncovered []Finding
	Listed    []Finding // unlisted rules whose operation the schema now has
	Foreign   int       // operations served on hosts the provider does not list
	Err       error
}

// Failed reports whether the provider fails the check.
func (r ProviderReport) Failed() bool {
	if r.Err != nil || len(r.Stale) > 0 {
		return true
	}
	for _, f := range r.Uncovered {
		if !f.Partial {
			return true
		}
	}
	return false
}

// Check compares every provider that lists schemas, or only the named ones.
func Check(ctx context.Context, c *catalog.Catalog, fetch Fetcher, only []string) []ProviderReport {
	var out []ProviderReport
	for _, p := range c.Providers {
		if len(p.Schemas) == 0 || (len(only) > 0 && !slices.Contains(only, p.ID)) {
			continue
		}
		out = append(out, CheckProvider(ctx, p, fetch))
	}
	return out
}

// CheckProvider compares one provider's rules with its schemas.
func CheckProvider(ctx context.Context, p *catalog.Provider, fetch Fetcher) ProviderReport {
	rep := ProviderReport{Provider: p, Schemas: len(p.Schemas)}
	var ops []Op
	for _, sc := range p.Schemas {
		data, err := fetch(ctx, sc.URL)
		if err != nil {
			rep.Err = fmt.Errorf("%s: %w", sc.URL, err)
			return rep
		}
		got, err := Extract(sc, p.Hosts, data)
		if err != nil {
			rep.Err = fmt.Errorf("%s: %w", sc.URL, err)
			return rep
		}
		for _, o := range got {
			if o.Foreign {
				rep.Foreign++
				continue
			}
			ops = append(ops, o)
		}
	}
	rep.Ops = len(ops)
	idx := newIndex(ops)

	covered := make([]bool, len(ops))
	for _, r := range p.Rules {
		kind := ruleKind(r)
		if kind == "" || !idx.has(kind, r) {
			continue // a matcher the schemas do not describe (MCP, git)
		}
		hits := idx.overlapping(r)
		for _, i := range idx.covering(r) {
			covered[i] = true
		}
		if r.Unlisted != "" {
			if len(hits) > 0 {
				rep.Listed = append(rep.Listed, Finding{Rule: r, Note: "the schema now has " + ops[hits[0]].String()})
			}
			continue
		}
		rep.Compared++
		if len(hits) == 0 {
			rep.Stale = append(rep.Stale, Finding{Rule: r, Note: "no operation in the schema matches " + describeRule(r)})
		}
	}
	for i, o := range ops {
		if covered[i] || readOnly(p, o) {
			continue
		}
		note := ""
		if o.Ref != "" {
			foreign, err := refForeign(ctx, fetch, o.Ref, p.Hosts)
			if err != nil {
				note = "could not read " + o.Ref + ": " + err.Error()
			} else if foreign {
				rep.Foreign++
				continue
			}
		}
		o := o
		rep.Uncovered = append(rep.Uncovered, Finding{Op: &o, Partial: o.Partial, Note: note})
	}
	sort.SliceStable(rep.Uncovered, func(i, j int) bool { return rep.Uncovered[i].Op.String() < rep.Uncovered[j].Op.String() })
	return rep
}

// refForeign reads the file an operation is a $ref to and reports whether
// its servers are all on other hosts.
func refForeign(ctx context.Context, fetch Fetcher, ref string, hosts []string) (bool, error) {
	data, err := fetch(ctx, ref)
	if err != nil {
		return false, err
	}
	doc, err := decodeDoc(data)
	if err != nil {
		return false, err
	}
	servers, _ := doc["servers"].([]any)
	if servers == nil {
		return false, nil
	}
	_, ok := serverBase(servers, hosts)
	return !ok, nil
}

// readOnly reports whether an uncovered operation needs no rule: a GET or
// HEAD (the provider's safe-method default classifies it), a query or
// subscription field, or an AWS read action.
func readOnly(p *catalog.Provider, o Op) bool {
	switch o.Kind {
	case "rest":
		return o.Method == "GET" || o.Method == "HEAD" || o.Method == "OPTIONS"
	case "graphql":
		return o.Type != "mutation"
	case "aws":
		return catalog.IsAWSReadAction(o.Action)
	}
	return false
}

func ruleKind(r *catalog.Rule) string {
	switch {
	case r.Match.REST != nil:
		return "rest"
	case r.Match.GraphQL != nil:
		return "graphql"
	case r.Match.AWS != nil:
		return "aws"
	}
	return ""
}

func describeRule(r *catalog.Rule) string {
	m := r.Match
	switch {
	case m.REST != nil:
		return m.REST.Method + " " + m.REST.Path
	case m.GraphQL != nil:
		return m.GraphQL.Type + " " + m.GraphQL.Field
	case m.AWS != nil && m.AWS.Action != "":
		return m.AWS.Service + " " + m.AWS.Action
	case m.AWS != nil:
		return m.AWS.Service + " " + m.AWS.Method + " " + m.AWS.Path
	}
	return r.ID
}

// index groups a provider's schema operations for matching.
type index struct {
	ops   []Op
	paths []*pathPattern // per op, for rest and aws path operations
	kinds map[string]bool
	aws   map[string]bool // services with a model
}

func newIndex(ops []Op) *index {
	x := &index{ops: ops, paths: make([]*pathPattern, len(ops)), kinds: map[string]bool{}, aws: map[string]bool{}}
	for i, o := range ops {
		x.kinds[o.Kind] = true
		if o.Kind == "aws" {
			x.aws[o.Service] = true
		}
		if o.Path != "" {
			x.paths[i] = compilePath(o.Path)
		}
	}
	return x
}

// has reports whether the schemas describe r's kind of operation at all
// (an AWS rule needs its own service's model).
func (x *index) has(kind string, r *catalog.Rule) bool {
	if kind == "aws" {
		return x.aws[r.Match.AWS.Service]
	}
	return x.kinds[kind]
}

// overlapping returns the operations r could be about: same method and a
// path either one matches in the other.
func (x *index) overlapping(r *catalog.Rule) []int {
	var out []int
	for i, o := range x.ops {
		if x.overlaps(r, i, o, false) {
			out = append(out, i)
		}
	}
	return out
}

// covering returns the operations r matches every request to.
func (x *index) covering(r *catalog.Rule) []int {
	var out []int
	for i, o := range x.ops {
		if x.overlaps(r, i, o, true) {
			out = append(out, i)
		}
	}
	return out
}

func (x *index) overlaps(r *catalog.Rule, i int, o Op, cover bool) bool {
	m := r.Match
	switch {
	case m.REST != nil:
		if o.Kind != "rest" || o.Method != m.REST.Method {
			return false
		}
		return pathsOverlap(m.REST.Template, x.paths[i], cover)
	case m.GraphQL != nil:
		return o.Kind == "graphql" && o.Type == m.GraphQL.Type && o.Field == m.GraphQL.Field
	case m.AWS != nil:
		if o.Kind != "aws" || o.Service != m.AWS.Service {
			return false
		}
		if m.AWS.Action != "" {
			return o.Action == m.AWS.Action
		}
		return o.Method == m.AWS.Method && x.paths[i] != nil && pathsOverlap(m.AWS.Template, x.paths[i], cover)
	}
	return false
}

// pathsOverlap compares a rule's template with a schema path. Covering
// means the rule matches the schema path's sample (every request to the
// operation); overlapping also accepts the schema path matching the rule's
// sample (a literal rule inside a parameterised schema path).
func pathsOverlap(t *catalog.Template, p *pathPattern, cover bool) bool {
	if t == nil || p == nil {
		return false
	}
	if _, ok := t.Match(p.sample); ok {
		return true
	}
	return !cover && p.re.MatchString(templateSample(t))
}

// pathPattern is a schema path: a regexp that matches the paths it
// describes, and a sample path with a value for each parameter.
type pathPattern struct {
	re     *regexp.Regexp
	sample string
}

var braceRe = regexp.MustCompile(`\{[^{}]*\}`)

// compilePath turns a schema path template ({id}, {(%23...)} in Heroku's
// hyper-schema, {Key+} in botocore) into a pathPattern.
func compilePath(path string) *pathPattern {
	var re, sample strings.Builder
	re.WriteString("^")
	last := 0
	for _, loc := range braceRe.FindAllStringIndex(path, -1) {
		re.WriteString(regexp.QuoteMeta(path[last:loc[0]]))
		sample.WriteString(path[last:loc[0]])
		inner := path[loc[0]+1 : loc[1]-1]
		if strings.HasSuffix(inner, "+") || strings.HasSuffix(inner, "*") {
			re.WriteString(".+")
			sample.WriteString("x1/x2")
		} else {
			re.WriteString("[^/]+")
			sample.WriteString("x1")
		}
		last = loc[1]
	}
	re.WriteString(regexp.QuoteMeta(path[last:]))
	sample.WriteString(path[last:])
	re.WriteString("/?$")
	return &pathPattern{re: regexp.MustCompile(re.String()), sample: sample.String()}
}

// templateSample is a path a rule's template matches, with a sample value
// for each parameter.
func templateSample(t *catalog.Template) string {
	var b strings.Builder
	for _, s := range t.Segments {
		b.WriteString("/")
		switch {
		case s.Rest:
			b.WriteString("x1")
		case s.Param != "":
			b.WriteString("x1" + s.Suffix)
		default:
			b.WriteString(s.Literal)
		}
	}
	if b.Len() == 0 {
		return "/"
	}
	return b.String()
}
