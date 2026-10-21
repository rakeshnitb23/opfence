// Package catalog loads, validates and queries the Opfence catalog: per-provider
// YAML files that classify API operations by risk.
//
// The file format is described in docs/ARCHITECTURE.md §4. This package does
// no network access; the embedded catalog snapshot is in the top-level
// catalog package.
package catalog

import (
	"fmt"
	"io/fs"
	"regexp"
	"slices"
	"strings"
	"sync"

	"go.yaml.in/yaml/v3"

	"github.com/rakeshnitb23/opfence/internal/classes"
)

// Catalog is a loaded and validated set of providers.
type Catalog struct {
	Providers []*Provider // sorted by ID
	FS        fs.FS       // the files it was loaded from, for reading fixtures

	rules map[string]*Rule // by id and alias
	// lazy says providers' rules are loaded on first use (LoadLazy); mu
	// guards rules while they are.
	lazy bool
	mu   sync.Mutex
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
	Git      []string `yaml:"git"`     // hosts that serve git's smart HTTP protocol and Git LFS
	Auth     []Auth   `yaml:"auth"`
	Detect   Detect   `yaml:"detect"`
	Defaults Defaults `yaml:"defaults"`
	MCP      *MCPInfo `yaml:"mcp"`
	// HeaderArgs turn the non-secret parts of request headers into
	// arguments rules can name (resource, conditions, cards), such as the
	// database host in a connection string. Passwords are never read.
	HeaderArgs []HeaderArg `yaml:"header_args"`
	// DatabasePorts are ports where the provider's hosts speak a database's
	// own protocol (MySQL on 3306), which Opfence cannot read. The proxy
	// handles them as it handles hosts outside the catalog, instead of
	// refusing every port but 443.
	DatabasePorts []int `yaml:"database_ports"`
	// Schemas are the published schemas the rules were built from, which
	// `opfence catalog check-sources` compares them with.
	Schemas []SchemaSource `yaml:"schemas"`

	Rules []*Rule `yaml:"-"` // in file order, files sorted by name
	Dir   string  `yaml:"-"` // folder within the catalog FS

	lazy *lazyRules // set in a lazily loaded catalog
}

// HeaderArg names a header and how to read its non-secret parts: url
// (host, port, user, database) or basic (the Basic-auth username).
type HeaderArg struct {
	Header string `yaml:"header"`
	Arg    string `yaml:"arg"`
	Parse  string `yaml:"parse"`
}

// lazyRules loads a provider's rules once, on first use.
type lazyRules struct {
	once sync.Once
	err  error
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
	// GraphQLSecretFields names fields that hold secrets wherever they
	// appear; an operation that selects one at any depth is also credential.
	GraphQLSecretFields []string `yaml:"graphql_secret_fields"`
}

// SchemaSource is one published schema of a provider's API.
type SchemaSource struct {
	Kind string `yaml:"kind"` // openapi, graphql, heroku or botocore
	URL  string `yaml:"url"`
	// Prefix is put in front of every path, when the schema's own base
	// path (Swagger basePath, the first OpenAPI server URL) is missing or
	// wrong.
	Prefix string `yaml:"prefix"`
	// Service is the SigV4 service a botocore model's rules match.
	Service string `yaml:"service"`
	// Coverage is full (the default: rules claim every operation that is
	// not a read) or partial (rules cover the risky parts only).
	Coverage string `yaml:"coverage"`
}

// Schema kinds.
var SchemaKinds = []string{"openapi", "graphql", "heroku", "botocore"}

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
	Response *Response     `yaml:"response"`
	Resource *Resource     `yaml:"resource"`
	Card     string        `yaml:"card"`
	// Unlisted says why the operation is not in the provider's schemas
	// (a CLI-only endpoint, an older schema version); the drift check then
	// skips it.
	Unlisted string   `yaml:"unlisted"`
	Status   Status   `yaml:"status"`
	Verified string   `yaml:"verified"` // YYYY-MM-DD
	Sources  []string `yaml:"sources"`
	Notes    string   `yaml:"notes"`
	Tests    []Test   `yaml:"tests"`

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
	Git     *GitMatch     `yaml:"git"`
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

// GitMatch matches a git smart HTTP or Git LFS request by service and
// command, and optionally by the ref a push updates. A rule with refs is
// more specific than one without.
type GitMatch struct {
	Service string   `yaml:"service"` // upload-pack, receive-pack or lfs
	Command string   `yaml:"command"` // see decode.Git* and decode.LFS*
	Refs    []string `yaml:"refs"`    // full ref names; a trailing * matches any rest
}

// MatchesRef reports whether ref matches one of m's patterns.
func (m *GitMatch) MatchesRef(ref string) bool {
	for _, p := range m.Refs {
		if p == ref || strings.HasSuffix(p, "*") && strings.HasPrefix(ref, p[:len(p)-1]) {
			return true
		}
	}
	return false
}

// CLIMatch names a shell command. It is advisory: exporters may use it to
// write command rules, but the proxy never relies on it.
type CLIMatch struct {
	Command string `yaml:"command"`
}

// When overrides a rule's class when its condition holds. Every matching
// When contributes its class; the strictest decision among them applies.
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
	Empty   bool     `yaml:"empty"`   // absent, null, "", {} or []
	Matches string   `yaml:"matches"` // RE2, unanchored

	re *regexp.Regexp
}

// Classify derives the class from an argument's content.
type Classify struct {
	// SQL lists the arguments holding SQL text: each a string, or a list of
	// strings classified one by one (a transaction's statements).
	SQL Strings `yaml:"sql"`
	// Dialect is the SQL the server speaks: postgres (the default), mysql
	// or sqlite. Several mean the server may speak any of them and Opfence
	// cannot tell which, so every dialect's classes count.
	Dialect Strings `yaml:"dialect"`
	// Format says how the argument holds the SQL: empty for SQL text, or
	// libsql for a libSQL (Turso) HTTP request body, whose statements are
	// SQLite.
	Format string `yaml:"format"`
}

// SQL dialects and formats classify understands.
const (
	DialectPostgres = "postgres"
	DialectMySQL    = "mysql"
	DialectSQLite   = "sqlite"
	FormatLibSQL    = "libsql"
)

// Dialects returns the dialects to read the SQL in.
func (c *Classify) Dialects() []string {
	switch {
	case c.Format == FormatLibSQL:
		return []string{DialectSQLite}
	case len(c.Dialect) == 0:
		return []string{DialectPostgres}
	}
	return c.Dialect
}

// String describes where the SQL comes from and how it is read, for cards
// and listings: "query", "body.sql, body.batch.sql (sqlite)".
func (c *Classify) String() string {
	s := strings.Join(c.SQL, ", ")
	switch {
	case c.Format != "":
		s += " (" + c.Format + ")"
	case len(c.Dialect) > 0:
		s += " (" + strings.Join(c.Dialect, " or ") + ")"
	}
	return s
}

// Strings is a list in YAML that may also be written as a single string.
type Strings []string

// UnmarshalYAML implements yaml.Unmarshaler.
func (s *Strings) UnmarshalYAML(n *yaml.Node) error {
	switch n.Kind {
	case yaml.ScalarNode:
		var v string
		if err := n.Decode(&v); err != nil {
			return err
		}
		*s = Strings{v}
		return nil
	case yaml.SequenceNode:
		var v []string
		if err := n.Decode(&v); err != nil {
			return err
		}
		*s = v
		return nil
	}
	return fmt.Errorf("line %d: want a string or a list of strings", n.Line)
}

// Paths are every path the response transform acts on.
func (x *Response) Paths() []string {
	return slices.Concat(x.Redact, x.Clear, x.Mint)
}

// Response describes what the proxy does to the response of a read that
// returns secrets (docs/ARCHITECTURE.md §8.4). Only the proxy can do it, so
// only the proxy uses Class; everything else keeps the rule's own class.
type Response struct {
	// Redact lists JSON paths whose strings, at any depth below, are
	// replaced with RedactedValue.
	Redact []string `yaml:"redact"`
	// Clear lists JSON paths whose values are replaced with the empty value
	// of the same type ({}, [] or ""), for secrets in places redaction
	// cannot reach, such as an object keyed by its tokens.
	Clear []string `yaml:"clear"`
	// Mint lists JSON paths of tokens the response creates. Each is
	// replaced with a placeholder, and the real value is held for the
	// session like a stored secret of the provider.
	Mint []string `yaml:"mint"`
	// Class is the operation's class when the proxy transforms the
	// response.
	Class classes.Class `yaml:"class"`
}

// RedactedValue replaces redacted strings in responses.
const RedactedValue = "[redacted by opfence]"

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
	// Response is a recorded JSON response body; the test checks that every
	// path in the rule's response transform finds something in it.
	Response string `yaml:"response"`
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
	case m.Git != nil:
		return "git"
	case m.CLI != nil:
		return "cli"
	}
	return ""
}

// Rule returns the rule with the given id or alias, or nil. In a lazily
// loaded catalog it finds only the rules of providers loaded so far.
func (c *Catalog) Rule(id string) *Rule {
	if c.lazy {
		c.mu.Lock()
		defer c.mu.Unlock()
	}
	return c.rules[id]
}

// Lazy reports whether the catalog loads providers' rules on first use.
func (c *Catalog) Lazy() bool { return c.lazy }

// Provider returns the provider with the given id, or nil.
func (c *Catalog) Provider(id string) *Provider {
	for _, p := range c.Providers {
		if p.ID == id {
			return p
		}
	}
	return nil
}

// Rules returns every rule in provider order. In a lazily loaded catalog it
// returns the rules of providers loaded so far, and must not be called while
// another goroutine may be loading one.
func (c *Catalog) Rules() []*Rule {
	var out []*Rule
	for _, p := range c.Providers {
		out = append(out, p.Rules...)
	}
	return out
}

// PossibleClasses returns every class the rule can produce: its base class,
// each When class, and every class SQL can have when it classifies SQL.
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
	if r.Classify != nil && len(r.Classify.SQL) > 0 {
		for _, c := range []classes.Class{classes.Read, classes.Write, classes.Delete, classes.Irreversible, classes.Access, classes.Unknown} {
			add(c)
		}
		// Postgres SQL can read Supabase Vault's secrets and MySQL the
		// password hashes in mysql.user; SQLite has no such table.
		for _, d := range r.Classify.Dialects() {
			if d != DialectSQLite {
				add(classes.Credential)
			}
		}
	}
	if r.Match.GraphQL != nil && r.Provider != nil && len(r.Provider.Defaults.GraphQLSecretFields) > 0 {
		add(classes.Credential) // the selection set can reach a secret field
	}
	return out
}
