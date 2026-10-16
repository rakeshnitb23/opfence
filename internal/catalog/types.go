// Package catalog loads, validates and queries the Opfence catalog: per-provider
// YAML files that classify API operations by risk.
//
// The file format is described in docs/ARCHITECTURE.md §4. This package does
// no network access; the embedded catalog snapshot is in the top-level
// catalog package.
package catalog

import (
	"io/fs"
	"regexp"

	"github.com/rakeshnitb23/opfence/internal/classes"
)

// Catalog is a loaded and validated set of providers.
type Catalog struct {
	Providers []*Provider // sorted by ID
	FS        fs.FS       // the files it was loaded from, for reading fixtures

	rules map[string]*Rule // by id and alias
}

// Provider describes one API or MCP server: where it lives, how it
// authenticates, and how to classify its operations.
type Provider struct {
	ID       string   `yaml:"provider"`
	Title    string   `yaml:"title"`
	Docs     string   `yaml:"docs"`
	Hosts    []string `yaml:"hosts"`
	GraphQL  []string `yaml:"graphql"` // request paths that carry GraphQL
	SigV4    bool     `yaml:"sigv4"`   // requests are AWS SigV4-signed
	Auth     []Auth   `yaml:"auth"`
	Detect   Detect   `yaml:"detect"`
	Defaults Defaults `yaml:"defaults"`
	MCP      *MCPInfo `yaml:"mcp"`

	Rules []*Rule `yaml:"-"` // in file order, files sorted by name
	Dir   string  `yaml:"-"` // folder within the catalog FS
}

// Auth says where a provider's credential travels in a request. Exactly one
// of Header, Query or Basic is set.
type Auth struct {
	Header string `yaml:"header"` // header name, e.g. Authorization
	Scheme string `yaml:"scheme"` // optional prefix in the header value, e.g. Bearer
	Query  string `yaml:"query"`  // query parameter name
	Basic  string `yaml:"basic"`  // "username" or "password" in HTTP Basic auth
}

// Detect tells `opfence init` how to find this provider's credentials.
type Detect struct {
	Env      []string `yaml:"env"`      // environment variable names
	Prefixes []string `yaml:"prefixes"` // token prefixes, e.g. "ghp_"
}

// Defaults classify operations that no rule matches.
type Defaults struct {
	GraphQLQuery    classes.Class `yaml:"graphql_query"`     // class for any GraphQL query
	RESTSafeMethods classes.Class `yaml:"rest_safe_methods"` // class for GET, HEAD and OPTIONS
	AWSReadActions  classes.Class `yaml:"aws_read_actions"`  // class for Describe*, Get*, List*, Head*, BatchGet*, Scan, Query
}

// MCPInfo identifies an MCP server.
type MCPInfo struct {
	Names   []string `yaml:"names"`   // names users commonly give the server in MCP configs
	Package string   `yaml:"package"` // npm or PyPI package, for documentation
}

// Status is how far a rule has been checked.
type Status string

// Rule statuses.
const (
	Verified  Status = "verified"  // has a primary source, a fixture and a verified date
	Community Status = "community" // reviewed, not yet proven by a fixture
	Draft     Status = "draft"     // proposed; not used for decisions by default
)

// Rule classifies one operation.
type Rule struct {
	ID       string        `yaml:"id"`
	Aliases  []string      `yaml:"aliases"`
	Match    Match         `yaml:"match"`
	Class    classes.Class `yaml:"class"`
	When     []When        `yaml:"when"`
	Classify *Classify     `yaml:"classify"`
	Resource *Resource     `yaml:"resource"`
	Card     string        `yaml:"card"`
	Status   Status        `yaml:"status"`
	Verified string        `yaml:"verified"` // YYYY-MM-DD
	Sources  []string      `yaml:"sources"`
	Notes    string        `yaml:"notes"`
	Tests    []Test        `yaml:"tests"`

	Provider *Provider `yaml:"-"`
	File     string    `yaml:"-"` // path within the catalog FS
	Line     int       `yaml:"-"`
}

// Match selects the operations a rule applies to. Exactly one field is set.
type Match struct {
	REST    *RESTMatch    `yaml:"rest"`
	GraphQL *GraphQLMatch `yaml:"graphql"`
	MCP     *MCPMatch     `yaml:"mcp"`
	AWS     *AWSMatch     `yaml:"aws"`
	CLI     *CLIMatch     `yaml:"cli"`
}

// RESTMatch matches an HTTP method and a path template.
type RESTMatch struct {
	Method string `yaml:"method"`
	Path   string `yaml:"path"`

	Template *Template `yaml:"-"`
}

// GraphQLMatch matches a root field of a GraphQL operation.
type GraphQLMatch struct {
	Type  string `yaml:"type"` // query, mutation or subscription
	Field string `yaml:"field"`
}

// MCPMatch matches an MCP tool of the rule's provider.
type MCPMatch struct {
	Tool string `yaml:"tool"`
}

// AWSMatch matches an AWS API call by service and either the action name
// (Query and JSON protocol services, and S3) or the method and path
// (REST-JSON services such as Lambda).
type AWSMatch struct {
	Service string `yaml:"service"` // SigV4 signing name, e.g. rds
	Action  string `yaml:"action"`
	Method  string `yaml:"method"`
	Path    string `yaml:"path"`

	Template *Template `yaml:"-"`
}

// CLIMatch names a shell command. It is advisory: exporters may use it to
// write command rules, but the proxy never relies on it.
type CLIMatch struct {
	Command string `yaml:"command"`
}

// When overrides a rule's class when its condition holds. The first matching
// When wins.
type When struct {
	If    Condition     `yaml:"if"`
	Class classes.Class `yaml:"class"`
}

// Condition tests one argument of an operation. Exactly one test is set.
type Condition struct {
	Arg     string   `yaml:"arg"` // dotted path into the operation's args
	Equals  *string  `yaml:"equals"`
	In      []string `yaml:"in"`
	Present bool     `yaml:"present"`
	Absent  bool     `yaml:"absent"`
	Matches string   `yaml:"matches"` // RE2, unanchored

	re *regexp.Regexp
}

// Classify derives the class from an argument's content.
type Classify struct {
	SQL string `yaml:"sql"` // argument holding SQL text
}

// Resource names the argument that identifies what the operation acts on.
type Resource struct {
	Arg  string `yaml:"arg"`
	Kind string `yaml:"kind"`
}

// Test is a recorded request that the rule must classify as Expect.
type Test struct {
	Fixture  string        `yaml:"fixture"` // path relative to the provider folder
	Expect   classes.Class `yaml:"expect"`
	Resource string        `yaml:"resource"` // optional expected resource value
}

// Matcher returns the protocol name of the rule's matcher.
func (m Match) Matcher() string {
	switch {
	case m.REST != nil:
		return "rest"
	case m.GraphQL != nil:
		return "graphql"
	case m.MCP != nil:
		return "mcp"
	case m.AWS != nil:
		return "aws"
	case m.CLI != nil:
		return "cli"
	}
	return ""
}

// Rule returns the rule with the given id or alias, or nil.
func (c *Catalog) Rule(id string) *Rule {
	return c.rules[id]
}

// Provider returns the provider with the given id, or nil.
func (c *Catalog) Provider(id string) *Provider {
	for _, p := range c.Providers {
		if p.ID == id {
			return p
		}
	}
	return nil
}

// Rules returns every rule in provider order.
func (c *Catalog) Rules() []*Rule {
	var out []*Rule
	for _, p := range c.Providers {
		out = append(out, p.Rules...)
	}
	return out
}

// PossibleClasses returns every class the rule can produce: its base class,
// each When class, and Unknown plus the SQL classes when it classifies SQL.
// Exporters that cannot evaluate conditions use the strictest of these.
func (r *Rule) PossibleClasses() []classes.Class {
	seen := map[classes.Class]bool{}
	var out []classes.Class
	add := func(c classes.Class) {
		if !seen[c] {
			seen[c] = true
			out = append(out, c)
		}
	}
	add(r.Class)
	for _, w := range r.When {
		add(w.Class)
	}
	if r.Classify != nil && r.Classify.SQL != "" {
		for _, c := range []classes.Class{classes.Read, classes.Write, classes.Delete, classes.Irreversible, classes.Access, classes.Unknown} {
			add(c)
		}
	}
	return out
}
