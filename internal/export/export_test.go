package export

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"

	"go.yaml.in/yaml/v3"

	"github.com/rakeshnitb23/opfence/internal/catalog"
	"github.com/rakeshnitb23/opfence/internal/classes"
	"github.com/rakeshnitb23/opfence/internal/policy"
)

var update = flag.Bool("update", false, "rewrite golden files")

// A small catalog covering every shape the exporters handle.
var testFS = fstest.MapFS{
	"gq/provider.yaml": {Data: []byte(`provider: gq
title: GQ
hosts: [api.gq.example]
graphql: [/graphql]
defaults:
  graphql_query: read
  rest_safe_methods: read
`)},
	"gq/rules.yaml": {Data: []byte(`operations:
  - id: gq.thing.delete
    match: { graphql: { type: mutation, field: thingDelete } }
    class: irreversible
    card: "Test irreversible operation"
    status: community
  - id: gq.thing.create
    match: { graphql: { type: mutation, field: thingCreate } }
    class: read
    status: community
  - id: gq.token.create
    match: { graphql: { type: mutation, field: tokenCreate } }
    class: credential
    card: "Test credential operation"
    status: community
  - id: gq.secret.read
    match: { graphql: { type: query, field: secret } }
    class: credential
    card: "Test credential operation"
    status: community
  - id: gq.env.list
    match: { rest: { method: GET, path: "/v1/projects/{id}/env" } }
    class: read
    when:
      - if: { arg: query.decrypt, equals: "true" }
        class: credential
    status: community
  - id: gq.export.read
    match: { rest: { method: GET, path: "/v1/export" } }
    class: money
    card: "Test money operation"
    status: community
  - id: gq.files.put
    match: { rest: { method: PUT, path: "/v1/files/{path*}" } }
    class: read
    status: community
  - id: gq.files.delete-one
    match: { rest: { method: PUT, path: "/v1/files/locked/{name}" } }
    class: delete
    card: "Test delete operation"
    status: community
`)},
	"mc/provider.yaml": {Data: []byte(`provider: mc
title: MC
hosts: [mcp.mc.example]
mcp: { names: [mc] }
`)},
	"mc/rules.yaml": {Data: []byte(`operations:
  - id: mc.item.list
    match: { mcp: { tool: list_items } }
    class: read
    status: community
  - id: mc.item.drop
    match: { mcp: { tool: drop_items } }
    class: irreversible
    card: "Test irreversible operation"
    status: community
  - id: mc.key.reveal
    match: { mcp: { tool: reveal_key } }
    class: credential
    card: "Test credential operation"
    status: community
  - id: mc.sql.run
    match: { mcp: { tool: run_sql } }
    class: unknown
    card: "Test unknown operation"
    classify: { sql: query }
    status: community
  - id: mc.money.spend
    match: { mcp: { tool: spend } }
    class: money
    card: "Test money operation"
    status: community
`)},
	"aw/provider.yaml": {Data: []byte(`provider: aw
title: AW
hosts: ["*.aw.example"]
sigv4: true
`)},
}

func testCatalog(t *testing.T) *catalog.Catalog {
	t.Helper()
	c, err := catalog.Load(testFS)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func golden(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *update {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run go test ./internal/export -update)", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("%s differs from golden file; run go test ./internal/export -update and review the diff\n%s", name, got)
	}
}

func TestGolden(t *testing.T) {
	c := testCatalog(t)
	for _, env := range policy.Environments {
		out, err := OpenShell(c, nil, env)
		if err != nil {
			t.Fatal(err)
		}
		golden(t, "openshell-"+env+".yaml", out)
	}
	out, err := ClaudeCode(c, nil, ClaudeCodeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "claude-code.json", out)
	if out, err = MCPAnnotations(c, nil); err != nil {
		t.Fatal(err)
	}
	golden(t, "mcp-annotations.json", out)
}

func TestDeterministic(t *testing.T) {
	c, err := catalog.Embedded()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		a, _ := OpenShell(c, nil, policy.Production)
		b, _ := OpenShell(c, nil, policy.Production)
		x, _ := ClaudeCode(c, nil, ClaudeCodeOptions{})
		y, _ := ClaudeCode(c, nil, ClaudeCodeOptions{})
		if !bytes.Equal(a, b) || !bytes.Equal(x, y) {
			t.Fatal("export output is not deterministic")
		}
	}
}

// --- OpenShell schema ------------------------------------------------------

// These types mirror the OpenShell policy schema reference (checked
// 2026-10-16) for the parts the exporter writes. Decoding with KnownFields
// rejects any key the schema does not have.
type osPolicy struct {
	Version         int                        `yaml:"version"`
	NetworkPolicies map[string]osNetworkPolicy `yaml:"network_policies"`
}

type osNetworkPolicy struct {
	Name      string       `yaml:"name"`
	Endpoints []osEndpoint `yaml:"endpoints"`
}

type osEndpoint struct {
	Host        string      `yaml:"host"`
	Port        int         `yaml:"port"`
	Ports       []int       `yaml:"ports"`
	Path        string      `yaml:"path"`
	Protocol    string      `yaml:"protocol"`
	TLS         string      `yaml:"tls"`
	Enforcement string      `yaml:"enforcement"`
	Access      string      `yaml:"access"`
	Rules       []osRule    `yaml:"rules"`
	DenyRules   []osMatcher `yaml:"deny_rules"`
}

type osRule struct {
	Allow osMatcher `yaml:"allow"`
}

type osMatcher struct {
	Method        string         `yaml:"method"`
	Path          string         `yaml:"path"`
	Query         map[string]any `yaml:"query"`
	OperationType string         `yaml:"operation_type"`
	OperationName string         `yaml:"operation_name"`
	Fields        []string       `yaml:"fields"`
	Tool          any            `yaml:"tool"`
}

func checkOpenShell(t *testing.T, out []byte) osPolicy {
	t.Helper()
	var pol osPolicy
	dec := yaml.NewDecoder(bytes.NewReader(out))
	dec.KnownFields(true)
	if err := dec.Decode(&pol); err != nil {
		t.Fatalf("output does not fit the OpenShell schema: %v\n%s", err, out)
	}
	if pol.Version != 1 {
		t.Errorf("version %d", pol.Version)
	}
	oneOf := func(v string, allowed ...string) bool {
		for _, a := range allowed {
			if v == a {
				return true
			}
		}
		return false
	}
	for key, np := range pol.NetworkPolicies {
		if strings.HasPrefix(key, "_provider_") {
			t.Errorf("%s: reserved prefix", key)
		}
		for i, ep := range np.Endpoints {
			where := key + "/" + ep.Host + ep.Path
			if ep.Host == "" || (ep.Port == 0) == (len(ep.Ports) == 0) {
				t.Errorf("%s[%d]: needs a host and exactly one of port, ports", where, i)
			}
			if !oneOf(ep.Protocol, "rest", "websocket", "graphql", "mcp", "json-rpc", "tcp") {
				t.Errorf("%s: protocol %q", where, ep.Protocol)
			}
			if !oneOf(ep.Enforcement, "", "audit", "enforce") || !oneOf(ep.TLS, "", "automatic", "skip") {
				t.Errorf("%s: enforcement %q tls %q", where, ep.Enforcement, ep.TLS)
			}
			if ep.Access != "" && len(ep.Rules) > 0 {
				t.Errorf("%s: access and rules cannot be combined", where)
			}
			if (ep.Protocol == "mcp" || ep.Protocol == "graphql") && len(ep.Rules) == 0 && ep.Access == "" {
				t.Errorf("%s: %s endpoints need rules", where, ep.Protocol)
			}
			ms := append([]osMatcher{}, ep.DenyRules...)
			for _, r := range ep.Rules {
				ms = append(ms, r.Allow)
			}
			for _, m := range ms {
				switch ep.Protocol {
				case "rest":
					if m.Method == "" || !strings.HasPrefix(m.Path, "/") {
						t.Errorf("%s: rest matcher needs method and path: %+v", where, m)
					}
				case "graphql":
					if !oneOf(m.OperationType, "query", "mutation", "subscription") {
						t.Errorf("%s: graphql matcher operation_type %q", where, m.OperationType)
					}
				case "mcp":
					if m.Method == "" {
						t.Errorf("%s: mcp matcher needs method", where)
					}
					switch tool := m.Tool.(type) {
					case nil, string:
					case map[string]any:
						if _, ok := tool["any"].([]any); !ok || len(tool) != 1 {
							t.Errorf("%s: tool must be a string or {any: [...]}", where)
						}
					default:
						t.Errorf("%s: tool has type %T", where, tool)
					}
				}
			}
		}
	}
	return pol
}

func TestOpenShellFitsSchema(t *testing.T) {
	c, err := catalog.Embedded()
	if err != nil {
		t.Fatal(err)
	}
	for _, env := range policy.Environments {
		out, err := OpenShell(c, nil, env)
		if err != nil {
			t.Fatal(err)
		}
		checkOpenShell(t, out)
	}
	out, _ := OpenShell(testCatalog(t), nil, policy.Production)
	checkOpenShell(t, out)
}

// TestOpenShellNeverLooser checks, for every rule in the embedded catalog and
// every environment, that the export never allows what Opfence would not.
func TestOpenShellNeverLooser(t *testing.T) {
	c, err := catalog.Embedded()
	if err != nil {
		t.Fatal(err)
	}
	p := policy.Resolve(nil, nil)
	for _, env := range policy.Environments {
		out, _ := OpenShell(c, p, env)
		pol := checkOpenShell(t, out)
		for _, prov := range c.Providers {
			np, ok := pol.NetworkPolicies["opfence_"+strings.ReplaceAll(prov.ID, "-", "_")]
			if !ok {
				continue
			}
			for _, r := range sortedRules(p, prov) {
				if Ceiling(p, r, env) == classes.Allow {
					continue
				}
				for _, ep := range np.Endpoints {
					if allowed(ep, r) && !denied(ep, r) {
						t.Errorf("%s: %s is %s in %s but the OpenShell export allows it",
							env, r.ID, Ceiling(p, r, env), ep.Host)
					}
				}
			}
		}
	}
}

func allowed(ep osEndpoint, r *catalog.Rule) bool {
	for _, rule := range ep.Rules {
		if matches(ep, rule.Allow, r, true) {
			return true
		}
	}
	return false
}

func denied(ep osEndpoint, r *catalog.Rule) bool {
	for _, m := range ep.DenyRules {
		if matches(ep, m, r, false) {
			return true
		}
	}
	return false
}

// matches is a model of OpenShell matching good enough for the rules the
// exporter writes.
func matches(ep osEndpoint, m osMatcher, r *catalog.Rule, isAllow bool) bool {
	switch {
	case ep.Protocol == "graphql" && r.Match.GraphQL != nil:
		if m.OperationType != r.Match.GraphQL.Type {
			return false
		}
		return len(m.Fields) == 0 || contains(m.Fields, r.Match.GraphQL.Field)
	case ep.Protocol == "rest" && r.Match.REST != nil:
		return m.Method == r.Match.REST.Method && globsOverlap(m.Path, templateGlob(r.Match.REST.Path))
	case ep.Protocol == "mcp" && r.Match.MCP != nil:
		if m.Method != "tools/call" {
			return false
		}
		switch tool := m.Tool.(type) {
		case string:
			return tool == r.Match.MCP.Tool
		case map[string]any:
			for _, x := range tool["any"].([]any) {
				if x == r.Match.MCP.Tool {
					return true
				}
			}
		}
	}
	return false
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

func TestClaudeCodeFloor(t *testing.T) {
	c := testCatalog(t)
	out, err := ClaudeCode(c, nil, ClaudeCodeOptions{HookCommand: "/usr/local/bin/opfence hook claude-code"})
	if err != nil {
		t.Fatal(err)
	}
	var s claudeSettings
	if err := json.Unmarshal(out, &s); err != nil {
		t.Fatal(err)
	}
	// irreversible is ask in development and confirm in production, so it is
	// ask everywhere; money is ask everywhere; credential is ask outside
	// production; read and SQL can be allowed, so they get no static rule.
	wantAsk := []string{"mcp__mc__drop_items", "mcp__mc__reveal_key", "mcp__mc__spend"}
	if strings.Join(s.Permissions.Ask, ",") != strings.Join(wantAsk, ",") || len(s.Permissions.Deny) != 0 {
		t.Errorf("ask %v deny %v, want ask %v", s.Permissions.Ask, s.Permissions.Deny, wantAsk)
	}
	h := s.Hooks["PreToolUse"][0]
	if h.Matcher != "^mcp__" || h.Hooks[0].OnFailure != "block" || h.Hooks[0].Command != "/usr/local/bin/opfence hook claude-code" {
		t.Errorf("hook %+v", h)
	}

	// A user who denies credential everywhere gets a static deny, and their
	// server aliases get rules too.
	u, err := policy.Parse([]byte("version: 1\nservers: {mc-prod: mc}\ndecisions:\n  development: {credential: deny}\n  staging: {credential: deny}\n"), "config.yaml")
	if err != nil {
		t.Fatal(err)
	}
	out, _ = ClaudeCode(c, policy.Resolve(u, nil), ClaudeCodeOptions{})
	if !strings.Contains(string(out), `"deny": [
      "mcp__mc-prod__reveal_key",
      "mcp__mc__reveal_key"`) {
		t.Errorf("credential deny with alias missing:\n%s", out)
	}
}

func TestAnnotations(t *testing.T) {
	out, err := MCPAnnotations(testCatalog(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]map[string]Annotation
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatal(err)
	}
	mc := got["mc"]
	if !mc["list_items"].ReadOnlyHint || mc["list_items"].DestructiveHint {
		t.Errorf("list_items: %+v", mc["list_items"])
	}
	if mc["drop_items"].ReadOnlyHint || !mc["drop_items"].DestructiveHint {
		t.Errorf("drop_items: %+v", mc["drop_items"])
	}
	if mc["run_sql"].ReadOnlyHint || !mc["run_sql"].DestructiveHint {
		t.Errorf("run_sql can be destructive: %+v", mc["run_sql"])
	}
}

func TestGlobsOverlap(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"/v1/files/**", "/v1/files/locked/*", true},
		{"/v1/files/*", "/v1/files/locked/*", false},
		{"/repos/*/*", "/repos/acme/shop", true},
		{"/repos/*/*", "/repos/*/*/keys", false},
		{"/a/b", "/a/c", false},
		{"/**", "/", true},
	}
	for _, c := range cases {
		if got := globsOverlap(c.a, c.b); got != c.want {
			t.Errorf("globsOverlap(%q, %q) = %v", c.a, c.b, got)
		}
	}
}
