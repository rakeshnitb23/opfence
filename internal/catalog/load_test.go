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
		{"bad auth", replace("acme/provider.yaml", "scheme: Bearer", "scheme: Bearer\n    query: token"), "exactly one of header, query or basic"},
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
		{"response without paths", responseRule(`{ class: read }`), "needs redact or mint"},
		{"response bad class", responseRule(`{ redact: [secret], class: fine }`), "response.class"},
		{"response bad path", responseRule(`{ redact: ["a b"], class: read }`), "not a dotted path"},
		{"response untested", responseRule(`{ redact: [secret], class: read }`), "needs a test with a recorded response"},
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
