package catalog

import (
	"errors"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/rakeshnitb23/opfence/internal/classes"
)

const goodProvider = `provider: acme
title: Acme Cloud
docs: https://docs.acme.dev/api
hosts: [api.acme.dev]
graphql: [/graphql]
auth:
  - header: Authorization
    scheme: Bearer
detect:
  env: [ACME_TOKEN]
  prefixes: [acme_]
defaults:
  graphql_query: read
`

const goodRules = `operations:
  - id: acme.db.delete
    match: { rest: { method: DELETE, path: "/v1/dbs/{id}" } }
    class: irreversible
    resource: { arg: id, kind: database }
    card: "Delete database {id}"
    status: verified
    verified: 2026-10-16
    sources: [https://docs.acme.dev/api/dbs]
    tests:
      - fixture: fixtures/db-delete.http
        expect: irreversible
  - id: acme.db.wipe
    match: { graphql: { type: mutation, field: dbWipe } }
    class: delete
    when:
      - if: { arg: hard, equals: "true" }
        class: irreversible
    card: "Wipe database {input.id}"
    status: community
`

func goodFS() fstest.MapFS {
	return fstest.MapFS{
		"acme/provider.yaml":           {Data: []byte(goodProvider)},
		"acme/db.yaml":                 {Data: []byte(goodRules)},
		"acme/fixtures/db-delete.http": {Data: []byte("DELETE /v1/dbs/x HTTP/1.1\nHost: api.acme.dev\n\n")},
		"embed.go":                     {Data: []byte("package catalog")},
	}
}

// An MCP server sharing its host with a REST API: rules for both.
func TestLoadMCPPaths(t *testing.T) {
	fs := goodFS()
	replace("acme/provider.yaml", "graphql_query: read", "graphql_query: read\nmcp:\n  names: [acme]\n  paths: [/mcp]")(fs)
	c, err := Load(fs)
	if err != nil {
		t.Fatal(err)
	}
	h := c.Provider("acme").Hints("api.acme.dev")
	if !h.MCP || len(h.MCPPaths) != 1 || h.MCPPaths[0] != "/mcp" {
		t.Fatalf("hints = %+v", h)
	}
}

func TestLoadGood(t *testing.T) {
	c, err := Load(goodFS())
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Providers) != 1 || c.Providers[0].ID != "acme" {
		t.Fatalf("providers = %+v", c.Providers)
	}
	r := c.Rule("acme.db.delete")
	if r == nil {
		t.Fatal("rule not found")
	}
	if r.Match.REST.Template == nil || r.Line != 2 || r.File != "acme/db.yaml" {
		t.Errorf("rule = %+v", r)
	}
	if got := c.Rule("acme.db.wipe").PossibleClasses(); len(got) != 2 || got[1] != classes.Irreversible {
		t.Errorf("PossibleClasses = %v", got)
	}
	if len(c.Rules()) != 2 {
		t.Errorf("Rules() = %d", len(c.Rules()))
	}
}

// TestLoadInvalid changes one thing in a good catalog and checks that the
// loader reports it.
func TestLoadInvalid(t *testing.T) {
	cases := []struct {
		name  string
		edit  func(fstest.MapFS)
		wants string
	}{
		{"missing provider file", func(m fstest.MapFS) { delete(m, "acme/provider.yaml") }, "missing provider.yaml"},
		{"unknown provider field", replace("acme/provider.yaml", "title:", "titel: x\ntitle:"), "field titel not found"},
		{"folder mismatch", replace("acme/provider.yaml", "provider: acme", "provider: acme2"), "must match its folder"},
		{"bad host", replace("acme/provider.yaml", "api.acme.dev]", "https://api.acme.dev]"), "lower-case DNS name"},
		{"bad auth", replace("acme/provider.yaml", "scheme: Bearer", "scheme: Bearer\n    query: token"), "exactly one of header, query, basic or form"},
		{"bad env", replace("acme/provider.yaml", "ACME_TOKEN", "acme-token"), "not an environment variable"},
		{"bad default", replace("acme/provider.yaml", "graphql_query: read", "graphql_query: safe"), "unknown class"},
		{"unknown rule field", replace("acme/db.yaml", "class: delete", "class: delete\n    severity: high"), "field severity not found"},
		{"bad rule id", replace("acme/db.yaml", "id: acme.db.delete", "id: AcmeDelete"), "provider.resource.verb"},
		{"rule id wrong provider", replace("acme/db.yaml", "id: acme.db.delete", "id: other.db.delete"), "must start with its provider"},
		{"duplicate id", replace("acme/db.yaml", "id: acme.db.wipe", "id: acme.db.delete"), "already used"},
		{"two matchers", replace("acme/db.yaml", `match: { graphql: { type: mutation, field: dbWipe } }`, `match: { graphql: { type: mutation, field: dbWipe }, mcp: { tool: x } }`), "exactly one of"},
		{"bad method", replace("acme/db.yaml", "method: DELETE", "method: delete"), "upper-case HTTP method"},
		{"bad template", replace("acme/db.yaml", `"/v1/dbs/{id}"`, `"/v1/dbs/{id}.json"`), "whole {param}"},
		{"bad graphql type", replace("acme/db.yaml", "type: mutation", "type: mutate"), "graphql.type"},
		{"graphql without paths", replace("acme/provider.yaml", "graphql: [/graphql]\n", ""), "graphql rules need graphql paths"},
		{"mcp without block", replace("acme/db.yaml", `match: { graphql: { type: mutation, field: dbWipe } }`, `match: { mcp: { tool: wipe } }`), "need an mcp block"},
		{"aws without sigv4", replace("acme/db.yaml", `match: { graphql: { type: mutation, field: dbWipe } }`, `match: { aws: { service: rds, action: DeleteDBInstance } }`), "sigv4: true"},
		{"aws action and path", func(m fstest.MapFS) {
			replace("acme/provider.yaml", "hosts: [api.acme.dev]", "hosts: [api.acme.dev]\nsigv4: true")(m)
			replace("acme/db.yaml", `match: { graphql: { type: mutation, field: dbWipe } }`, `match: { aws: { service: lambda, action: DeleteFunction, method: DELETE, path: /f } }`)(m)
		}, "either action, or method and path"},
		{"git without git hosts", replace("acme/db.yaml", `match: { graphql: { type: mutation, field: dbWipe } }`, `match: { git: { service: receive-pack, command: delete } }`), "need git hosts"},
		{"git host not a host", replace("acme/provider.yaml", "hosts: [api.acme.dev]", "hosts: [api.acme.dev]\ngit: [git.acme.dev]"), "must be one of the provider's hosts"},
		{"git bad command", gitRule(`{ service: upload-pack, command: push }`), "git.command for upload-pack"},
		{"git bad service", gitRule(`{ service: archive, command: fetch }`), "git.service must be"},
		{"git refs on fetch", gitRule(`{ service: upload-pack, command: fetch, refs: [refs/heads/main] }`), "only applies to receive-pack"},
		{"git bad ref", gitRule(`{ service: receive-pack, command: update, refs: ["heads/*/x"] }`), "must be a full ref name"},
		{"git overlapping refs", func(m fstest.MapFS) {
			gitRule(`{ service: receive-pack, command: update, refs: ["refs/heads/*"] }`)(m)
			m["acme/more.yaml"] = &fstest.MapFile{Data: []byte("operations:\n  - id: acme.git.main\n    match: { git: { service: receive-pack, command: update, refs: [refs/heads/main] } }\n    class: delete\n    card: x\n    status: draft\n")}
		}, "can both match refs/heads/main"},
		{"bad schema kind", replace("acme/provider.yaml", "graphql_query: read", "graphql_query: read\nschemas:\n  - kind: swagger\n    url: https://acme.dev/s.json"), "kind \"swagger\" must be one of"},
		{"http schema url", replace("acme/provider.yaml", "graphql_query: read", "graphql_query: read\nschemas:\n  - kind: openapi\n    url: http://acme.dev/s.json"), "url must be an https URL"},
		{"bad schema prefix", replace("acme/provider.yaml", "graphql_query: read", "graphql_query: read\nschemas:\n  - kind: openapi\n    url: https://acme.dev/s.json\n    prefix: /v1/"), "must start with / and not end with one"},
		{"bad schema coverage", replace("acme/provider.yaml", "graphql_query: read", "graphql_query: read\nschemas:\n  - kind: openapi\n    url: https://acme.dev/s.json\n    coverage: most"), "coverage must be full or partial"},
		{"botocore without service", replace("acme/provider.yaml", "graphql_query: read", "graphql_query: read\nschemas:\n  - kind: botocore\n    url: https://acme.dev/s.json"), "service is required for botocore"},
		{"aws read default without sigv4", replace("acme/provider.yaml", "graphql_query: read", "graphql_query: read\n  aws_read_actions: read"), "needs sigv4"},
		{"mcp tools default read", replace("acme/provider.yaml", "graphql_query: read", "graphql_query: read\n  mcp_tools: read"), "mcp_tools may not be read"},
		{"mcp tools default without mcp", replace("acme/provider.yaml", "graphql_query: read", "graphql_query: read\n  mcp_tools: irreversible"), "mcp_tools needs an mcp block"},
		{"mcp tools default bad class", replace("acme/provider.yaml", "graphql_query: read", "graphql_query: read\n  mcp_tools: risky"), "defaults.mcp_tools: unknown class"},
		{"secrets from itself", replace("acme/provider.yaml", "graphql_query: read", "graphql_query: read\nsecrets_from: [acme]"), "names the provider itself"},
		{"secrets from nobody", replace("acme/provider.yaml", "graphql_query: read", "graphql_query: read\nsecrets_from: [nope]"), "no provider nope"},
		{"duplicate detect env", func(m fstest.MapFS) {
			m["other/provider.yaml"] = &fstest.MapFile{Data: []byte("provider: other\ntitle: Other\ndocs: https://other.dev\nhosts: [api.other.dev]\nauth:\n  - header: Authorization\ndetect:\n  env: [ACME_TOKEN]\n")}
		}, "detect.env ACME_TOKEN is already detected by provider acme"},
		{"overlapping detect prefix", func(m fstest.MapFS) {
			m["other/provider.yaml"] = &fstest.MapFile{Data: []byte("provider: other\ntitle: Other\ndocs: https://other.dev\nhosts: [api.other.dev]\nauth:\n  - header: Authorization\ndetect:\n  prefixes: [acme_live_]\n")}
		}, "overlaps acme_ detected by provider acme"},
		{"rest on mcp host without paths", replace("acme/provider.yaml", "graphql_query: read", "graphql_query: read\nmcp:\n  names: [acme]"), "need mcp.paths"},
		{"rest under mcp path", replace("acme/provider.yaml", "graphql_query: read", "graphql_query: read\nmcp:\n  names: [acme]\n  paths: [/v1/dbs]"), "is under mcp path /v1/dbs"},
		{"bad mcp path", replace("acme/provider.yaml", "graphql_query: read", "graphql_query: read\nmcp:\n  names: [acme]\n  paths: [/mcp/]"), "must be an absolute path"},
		{"dot mcp path", replace("acme/provider.yaml", "graphql_query: read", "graphql_query: read\nmcp:\n  names: [acme]\n  paths: [/a/../mcp]"), "must be an absolute path"},
		{"duplicate mcp path", replace("acme/provider.yaml", "graphql_query: read", "graphql_query: read\nmcp:\n  names: [acme]\n  paths: [/mcp, /mcp]"), "listed twice"},
		{"mcp paths without hosts", replace("acme/provider.yaml", "hosts: [api.acme.dev]", "mcp:\n  names: [acme]\n  paths: [/mcp]"), "mcp.paths needs provider hosts"},
		{"tool default status in yaml", replace("acme/db.yaml", "status: community", "status: provider default"), "unknown status"},
		{"bad class", replace("acme/db.yaml", "class: irreversible\n    resource", "class: dangerous\n    resource"), "unknown class \"dangerous\""},
		{"bad when class", replace("acme/db.yaml", "        class: irreversible", "        class: fatal"), "when[0]: unknown class"},
		{"when two tests", replace("acme/db.yaml", `equals: "true"`, `equals: "true", present: true`), "exactly one of equals"},
		{"when bad regex", replace("acme/db.yaml", `equals: "true"`, `matches: "("`), "missing closing"},
		{"missing card", replace("acme/db.yaml", `card: "Delete database {id}"`, ``), "card is required"},
		{"bad card placeholder", replace("acme/db.yaml", `{input.id}`, `{input id}`), "not an argument path"},
		{"missing status", replace("acme/db.yaml", "status: community", ""), "status is required"},
		{"bad status", replace("acme/db.yaml", "status: community", "status: done"), "unknown status"},
		{"verified needs tests", replace("acme/db.yaml", "    tests:\n      - fixture: fixtures/db-delete.http\n        expect: irreversible\n", ""), "need at least one test"},
		{"verified needs source", replace("acme/db.yaml", "sources: [https://docs.acme.dev/api/dbs]", ""), "need at least one source"},
		{"bad date", replace("acme/db.yaml", "verified: 2026-10-16", "verified: 16 Oct 2026"), "verified must be a date"},
		{"http source", replace("acme/db.yaml", "https://docs.acme.dev/api/dbs", "http://docs.acme.dev/api/dbs"), "must be an https URL"},
		{"missing fixture", replace("acme/db.yaml", "fixtures/db-delete.http", "fixtures/nope.http"), "not found"},
		{"escaping fixture", replace("acme/db.yaml", "fixtures/db-delete.http", "../other/x.http"), "clean path under fixtures/"},
		{"unreferenced fixture", func(m fstest.MapFS) { m["acme/fixtures/extra.http"] = &fstest.MapFile{Data: []byte("x")} }, "not referenced"},
		{"bad expect", replace("acme/db.yaml", "expect: irreversible", "expect: bad"), "unknown expected class"},
		{"ambiguous rest", func(m fstest.MapFS) {
			m["acme/more.yaml"] = &fstest.MapFile{Data: []byte("operations:\n  - id: acme.db.remove\n    match: { rest: { method: DELETE, path: \"/v1/dbs/{name}\" } }\n    class: delete\n    card: x\n    status: draft\n")}
		}, "matches the same operations"},
		{"duplicate host", func(m fstest.MapFS) {
			m["beta/provider.yaml"] = &fstest.MapFile{Data: []byte("provider: beta\ntitle: Beta\nhosts: [api.acme.dev]\n")}
		}, "already claimed"},
		{"overlapping wildcard host", func(m fstest.MapFS) {
			m["beta/provider.yaml"] = &fstest.MapFile{Data: []byte("provider: beta\ntitle: Beta\nhosts: [\"*.acme.dev\"]\n")}
		}, "overlaps"},
		{"yml extension", func(m fstest.MapFS) { m["acme/x.yml"] = &fstest.MapFile{Data: []byte("operations: []")} }, "use the .yaml extension"},
		{"two documents", replace("acme/db.yaml", "operations:", "operations: []\n---\noperations:"), "only one YAML document"},
		{"empty rule file", func(m fstest.MapFS) { m["acme/empty.yaml"] = &fstest.MapFile{Data: []byte("")} }, "empty file"},
		{"stray folder", func(m fstest.MapFS) { m["acme/tests/x.http"] = &fstest.MapFile{Data: []byte("x")} }, "unexpected folder"},
		{"response without paths", responseRule(`{ class: read }`), "needs redact, clear, mint or hold"},
		{"held and redacted", responseRule(`{ redact: [env], hold: [env], class: read }`), "is held and also redacted"},
		{"hold on graphql", replace("acme/db.yaml", "    card: \"Wipe database {input.id}\"", "    response: { hold: [env], class: read }\n    card: \"Wipe database {input.id}\""), "response.hold is for rest rules"},
		{"restore on DELETE", replace("acme/db.yaml", "    resource: { arg: id, kind: database }", "    restore: [env.value]\n    response: { hold: [env.value], class: read }\n    resource: { arg: id, kind: database }"), "restore is for rest rules that match PUT, PATCH or POST"},
		{"restore without hold", func(m fstest.MapFS) {
			replace("acme/db.yaml", "method: DELETE", "method: PUT")(m)
			replace("acme/db.yaml", "    resource: { arg: id, kind: database }", "    restore: [env.value]\n    resource: { arg: id, kind: database }")(m)
		}, "needs response.hold"},
		{"restore bad path", func(m fstest.MapFS) {
			replace("acme/db.yaml", "method: DELETE", "method: PATCH")(m)
			replace("acme/db.yaml", "    resource: { arg: id, kind: database }", "    restore: [\"a b\"]\n    response: { hold: [env], class: read }\n    resource: { arg: id, kind: database }")(m)
		}, "restore path \"a b\" is not a dotted path"},
		{"response path ending in **", responseRule(`{ redact: ["env.**"], class: read }`), "not a dotted path"},
		{"response path with *", responseRule(`{ redact: ["env.*.value"], class: read }`), "not a dotted path"},
		{"fallback with an exact host", replace("acme/provider.yaml", "hosts: [api.acme.dev]", "hosts: [api.acme.dev]\nfallback: true"), "fallback provider's hosts must all be *. patterns"},
		{"fallback with graphql", replace("acme/provider.yaml", "hosts: [api.acme.dev]", "hosts: [\"*.acme.dev\"]\nfallback: true"), "takes REST defaults and auth only"},
		{"two fallbacks overlap", func(m fstest.MapFS) {
			replace("acme/provider.yaml", "graphql: [/graphql]", "")(m)
			replace("acme/provider.yaml", "graphql_query: read", "rest_safe_methods: read")(m)
			replace("acme/db.yaml", "  - id: acme.db.wipe", "  - id: acme.db.wipe-unused")(m)
			m["acme/provider.yaml"].Data = []byte(strings.Replace(string(m["acme/provider.yaml"].Data), "hosts: [api.acme.dev]", "hosts: [\"*.acme.dev\"]\nfallback: true", 1))
			m["beta/provider.yaml"] = &fstest.MapFile{Data: []byte("provider: beta\ntitle: Beta\nhosts: [\"*.x.acme.dev\"]\nfallback: true\n")}
		}, "overlaps"},
		{"form auth bad name", replace("acme/provider.yaml", "  - header: Authorization\n    scheme: Bearer", "  - form: \"refresh token\""), "must be a plain field name"},
		{"batch path without slash", replace("acme/provider.yaml", "graphql: [/graphql]", "graphql: [/graphql]\nbatch: [batch/v1]"), "batch path \"batch/v1\" must start with /"},
		{"batch path is graphql", replace("acme/provider.yaml", "graphql: [/graphql]", "graphql: [/graphql]\nbatch: [/graphql]"), "is also a graphql path"},
		{"response bad class", responseRule(`{ redact: [secret], class: fine }`), "response.class"},
		{"response bad path", responseRule(`{ redact: ["a b"], class: read }`), "not a dotted path"},
		{"response untested", responseRule(`{ redact: [secret], class: read }`), "needs a test with a recorded response"},
		{"host pattern with two wildcards", replace("acme/provider.yaml", "hosts: [api.acme.dev]", `hosts: ["api.*.*.acme.dev"]`), "must be a lower-case DNS name"},
		{"host pattern ending in a wildcard", replace("acme/provider.yaml", "hosts: [api.acme.dev]", `hosts: ["api.*"]`), "must be a lower-case DNS name"},
		{"host pattern overlap", func(m fstest.MapFS) {
			replace("acme/provider.yaml", "hosts: [api.acme.dev]", `hosts: ["api.*.acme.dev"]`)(m)
			m["other/provider.yaml"] = &fstest.MapFile{Data: []byte("provider: other\ntitle: Other\nhosts: [api.eu.acme.dev]\n")}
			m["other/r.yaml"] = &fstest.MapFile{Data: []byte("operations:\n  - id: other.x.read\n    match: { rest: { method: GET, path: /x } }\n    class: read\n    status: community\n")}
		}, `overlaps "api.eu.acme.dev"`},
		{"wildcard git host", replace("acme/provider.yaml", "hosts: [api.acme.dev]", "hosts: [\"git.*.acme.dev\"]\ngit: [\"git.*.acme.dev\"]"), "without a wildcard"},
		{"header arg bad header", replace("acme/provider.yaml", "hosts: [api.acme.dev]", "hosts: [api.acme.dev]\nheader_args: [{header: \"Bad Header\", arg: conn, parse: url}]"), "bad header name"},
		{"header arg named body", replace("acme/provider.yaml", "hosts: [api.acme.dev]", "hosts: [api.acme.dev]\nheader_args: [{header: X-Conn, arg: body, parse: url}]"), "other than query and body"},
		{"header arg bad parse", replace("acme/provider.yaml", "hosts: [api.acme.dev]", "hosts: [api.acme.dev]\nheader_args: [{header: X-Conn, arg: conn, parse: json}]"), "must be url or basic"},
		{"header arg twice", replace("acme/provider.yaml", "hosts: [api.acme.dev]", "hosts: [api.acme.dev]\nheader_args: [{header: X-A, arg: conn, parse: url}, {header: X-B, arg: conn, parse: basic}]"), "is used twice"},
		{"header arg shadows a path parameter", replace("acme/provider.yaml", "hosts: [api.acme.dev]", "hosts: [api.acme.dev]\nheader_args: [{header: X-Conn, arg: id, parse: url}]"), "has the name of a header_args arg"},
		{"database port 443", replace("acme/provider.yaml", "hosts: [api.acme.dev]", "hosts: [api.acme.dev]\ndatabase_ports: [443]"), "other than 443"},
		{"database port 0", replace("acme/provider.yaml", "hosts: [api.acme.dev]", "hosts: [api.acme.dev]\ndatabase_ports: [0]"), "from 1 to 65535"},
		{"database port twice", replace("acme/provider.yaml", "hosts: [api.acme.dev]", "hosts: [api.acme.dev]\ndatabase_ports: [3306, 3306]"), "lists 3306 twice"},
		{"classify without sql", classifyRule(`{ dialect: sqlite }`), "classify needs sql"},
		{"classify sql and redis", classifyRule(`{ sql: q, redis: commands }`), "takes one of sql, redis, aws_cli and postgrest"},
		{"classify sql and postgrest", classifyRule(`{ sql: q, postgrest: query }`), "takes one of sql, redis, aws_cli and postgrest"},
		{"classify postgrest on a mutation", classifyRule(`{ postgrest: query }`), "is for PATCH and DELETE rules"},
		{"classify postgrest with a dialect", classifyRule(`{ postgrest: query, dialect: mysql }`), "takes no dialect"},
		{"classify postgrest bad path", classifyRule(`{ postgrest: "a..b" }`), "not an argument path"},
		{"host arg named query", replace("acme/provider.yaml", "hosts: [api.acme.dev]", "hosts: [\"*.acme.dev\"]\nhost_arg: query"), "other than query and body"},
		{"host arg without a wildcard host", replace("acme/provider.yaml", "hosts: [api.acme.dev]", "hosts: [api.acme.dev]\nhost_arg: ref"), "starts with *."},
		{"host arg is a header arg", replace("acme/provider.yaml", "hosts: [api.acme.dev]", "hosts: [\"*.acme.dev\"]\nhost_arg: conn\nheader_args: [{header: X-Conn, arg: conn, parse: url}]"), "also a header_args arg"},
		{"host arg shadows a path parameter", replace("acme/provider.yaml", "hosts: [api.acme.dev]", "hosts: [\"*.acme.dev\"]\nhost_arg: id"), "has the name of the host_arg"},
		{"classify aws_cli without provider", classifyRule(`{ aws_cli: cli_command }`), "needs provider"},
		{"classify provider without aws_cli", classifyRule(`{ sql: q, provider: aws }`), "provider is for aws_cli"},
		{"classify aws_cli to a missing provider", classifyRule(`{ aws_cli: cli_command, provider: nope }`), `"nope" is not a sigv4 provider`},
		{"classify aws_cli with a dialect", classifyRule(`{ aws_cli: cli_command, provider: acme, dialect: mysql }`), "are for sql"},
		{"classify redis with a dialect", classifyRule(`{ redis: commands, dialect: mysql }`), "are for sql"},
		{"classify redis twice", classifyRule(`{ redis: [c, c] }`), `classify.redis lists "c" twice`},
		{"classify bad path", classifyRule(`{ sql: "a b" }`), "not an argument path"},
		{"classify path twice", classifyRule(`{ sql: [q, q] }`), "lists \"q\" twice"},
		{"classify bad dialect", classifyRule(`{ sql: q, dialect: oracle }`), "is not postgres, mysql, sqlite or googlesql"},
		{"classify dialect twice", classifyRule(`{ sql: q, dialect: [mysql, mysql] }`), "lists \"mysql\" twice"},
		{"classify bad format", classifyRule(`{ sql: body, format: hrana }`), "is not libsql"},
		{"classify libsql two paths", classifyRule(`{ sql: [body, query], format: libsql }`), "reads one argument"},
		{"classify libsql dialect", classifyRule(`{ sql: body, format: libsql, dialect: sqlite }`), "always sqlite"},
		{"classify sql not a list", classifyRule(`{ sql: { a: b } }`), "want a string or a list"},
		{"test response without transform", func(m fstest.MapFS) {
			replace("acme/db.yaml", "        expect: irreversible\n", "        expect: irreversible\n        response: fixtures/db-delete.json\n")(m)
			m["acme/fixtures/db-delete.json"] = &fstest.MapFile{Data: []byte("{}")}
		}, "for rules with a response transform"},
		{"test response not json", func(m fstest.MapFS) {
			responseRule(`{ redact: [secret], class: read }`)(m)
			replace("acme/db.yaml", "        expect: irreversible\n", "        expect: irreversible\n        response: fixtures/db-delete.http\n")(m)
		}, "clean .json path"},
		{"test response missing", func(m fstest.MapFS) {
			responseRule(`{ redact: [secret], class: read }`)(m)
			replace("acme/db.yaml", "        expect: irreversible\n", "        expect: irreversible\n        response: fixtures/nope.json\n")(m)
		}, "fixtures/nope.json not found"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := goodFS()
			c.edit(m)
			_, err := Load(m)
			var ve *ValidationError
			if !errors.As(err, &ve) {
				t.Fatalf("got %v, want a validation error", err)
			}
			if !strings.Contains(err.Error(), c.wants) {
				t.Fatalf("error does not mention %q:\n%v", c.wants, err)
			}
		})
	}
}

// classifyRule gives acme.db.wipe a classify block.
func classifyRule(x string) func(fstest.MapFS) {
	return replace("acme/db.yaml", `    card: "Wipe database {input.id}"`, "    classify: "+x+"\n    card: \"Wipe database {input.id}\"")
}

// responseRule gives acme.db.delete a response transform.
func responseRule(x string) func(fstest.MapFS) {
	return replace("acme/db.yaml", "    resource: { arg: id, kind: database }", "    response: "+x+"\n    resource: { arg: id, kind: database }")
}

// gitRule makes acme.db.wipe a git rule on a git host.
func gitRule(match string) func(fstest.MapFS) {
	return func(m fstest.MapFS) {
		replace("acme/provider.yaml", "hosts: [api.acme.dev]", "hosts: [api.acme.dev]\ngit: [api.acme.dev]")(m)
		replace("acme/db.yaml", `match: { graphql: { type: mutation, field: dbWipe } }`, "match: { git: "+match+" }")(m)
	}
}

func replace(file, old, new string) func(fstest.MapFS) {
	return func(m fstest.MapFS) {
		s := string(m[file].Data)
		if !strings.Contains(s, old) {
			panic("test setup: " + file + " does not contain " + old)
		}
		m[file] = &fstest.MapFile{Data: []byte(strings.Replace(s, old, new, 1))}
	}
}

func TestErrorsHaveLocations(t *testing.T) {
	m := goodFS()
	replace("acme/db.yaml", "class: delete", "class: nope")(m)
	_, err := Load(m)
	if err == nil || !strings.Contains(err.Error(), "acme/db.yaml:13:") {
		t.Fatalf("error lacks file:line: %v", err)
	}
}

func TestEmbedded(t *testing.T) {
	c, err := Embedded()
	if err != nil {
		t.Fatal(err)
	}
	if c.Rule("railway.volume.delete") == nil {
		t.Fatal("embedded catalog lacks railway.volume.delete")
	}
}
