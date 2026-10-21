package fixture

import (
	"strings"
	"testing"
	"testing/fstest"

	catalogdata "github.com/rakeshnitb23/opfence/catalog"
	"github.com/rakeshnitb23/opfence/internal/catalog"
)

func load(t *testing.T, rules string, fixtures map[string]string) *catalog.Catalog {
	t.Helper()
	m := fstest.MapFS{
		"acme/provider.yaml": {Data: []byte("provider: acme\ntitle: Acme\nhosts: [api.acme.dev]\ngraphql: [/graphql]\n")},
		"acme/r.yaml":        {Data: []byte(rules)},
	}
	for name, body := range fixtures {
		m["acme/fixtures/"+name] = &fstest.MapFile{Data: []byte(body)}
	}
	c, err := catalog.Load(m)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

const delReq = "DELETE /v1/dbs/main HTTP/1.1\nHost: api.acme.dev\n\n"

func TestRunPasses(t *testing.T) {
	c := load(t, `operations:
  - id: acme.db.delete
    match: { rest: { method: DELETE, path: "/v1/dbs/{id}" } }
    class: irreversible
    resource: { arg: id, kind: db }
    card: x
    status: draft
    tests: [{ fixture: fixtures/del.http, expect: irreversible, resource: main }]
`, map[string]string{"del.http": delReq})
	rep := Run(c)
	if rep.Failed != 0 || len(rep.Outcomes) != 1 || !rep.Outcomes[0].Pass {
		t.Fatalf("report = %+v", rep)
	}
}

func TestRunFailures(t *testing.T) {
	cases := map[string]struct {
		rules, fixture, want string
	}{
		"wrong class": {`operations:
  - { id: acme.db.delete, match: { rest: { method: DELETE, path: "/v1/dbs/{id}" } }, class: delete, card: x, status: community, tests: [{ fixture: fixtures/f.http, expect: irreversible }] }
`, delReq, "classified delete, want irreversible"},
		"no match": {`operations:
  - { id: acme.db.delete, match: { rest: { method: DELETE, path: "/v2/dbs/{id}" } }, class: delete, card: x, status: community, tests: [{ fixture: fixtures/f.http, expect: delete }] }
`, delReq, "no operation matched acme.db.delete; saw unmatched DELETE /v1/dbs/main"},
		"wrong resource": {`operations:
  - { id: acme.db.delete, match: { rest: { method: DELETE, path: "/v1/dbs/{id}" } }, class: delete, resource: { arg: id, kind: db }, card: x, status: community, tests: [{ fixture: fixtures/f.http, expect: delete, resource: other }] }
`, delReq, `resource "main", want "other"`},
		"foreign host": {`operations:
  - { id: acme.db.delete, match: { rest: { method: DELETE, path: "/v1/dbs/{id}" } }, class: delete, card: x, status: community, tests: [{ fixture: fixtures/f.http, expect: delete }] }
`, strings.Replace(delReq, "api.acme.dev", "api.other.dev", 1), "belongs to no provider"},
		"bad fixture": {`operations:
  - { id: acme.db.delete, match: { rest: { method: DELETE, path: "/v1/dbs/{id}" } }, class: delete, card: x, status: community, tests: [{ fixture: fixtures/f.http, expect: delete }] }
`, "garbage", "fixture request"},
		"decode error": {`operations:
  - { id: acme.db.wipe, match: { graphql: { type: mutation, field: dbWipe } }, class: delete, card: x, status: community, tests: [{ fixture: fixtures/f.http, expect: delete }] }
`, "POST /graphql HTTP/1.1\nHost: api.acme.dev\nContent-Type: application/json\n\n{bad", "decode error"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			rep := Run(load(t, c.rules, map[string]string{"f.http": c.fixture}))
			if rep.Failed != 1 || !strings.Contains(rep.Outcomes[0].Problem, c.want) {
				t.Fatalf("problem %q, want it to contain %q", rep.Outcomes[0].Problem, c.want)
			}
		})
	}
}

func TestEmbeddedCatalogPasses(t *testing.T) {
	c, err := catalog.Embedded()
	if err != nil {
		t.Fatal(err)
	}
	rep := Run(c)
	for _, o := range rep.Outcomes {
		if !o.Pass {
			t.Errorf("%s %s: %s", o.Rule.ID, o.Fixture, o.Problem)
		}
	}
}

// The embedded catalog loaded lazily, as the hooks load it, passes every
// fixture the full load does.
func TestEmbeddedCatalogPassesLazy(t *testing.T) {
	full, err := catalog.Embedded()
	if err != nil {
		t.Fatal(err)
	}
	c, err := catalog.LoadLazy(catalogdata.FS)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range c.Providers {
		if err := c.LoadRules(p); err != nil {
			t.Fatalf("%s: %v", p.ID, err)
		}
	}
	rep := Run(c)
	if want := len(Run(full).Outcomes); len(rep.Outcomes) != want {
		t.Fatalf("%d fixtures ran lazily, %d in full", len(rep.Outcomes), want)
	}
	for _, o := range rep.Outcomes {
		if !o.Pass {
			t.Errorf("%s %s: %s", o.Rule.ID, o.Fixture, o.Problem)
		}
	}
}

func TestToolCallFixture(t *testing.T) {
	m := fstest.MapFS{
		"local-mcp/provider.yaml": {Data: []byte("provider: local-mcp\ntitle: Local\nmcp: { names: [local] }\n")},
		"local-mcp/r.yaml": {Data: []byte(`operations:
  - id: local-mcp.app.destroy
    match: { mcp: { tool: apps-destroy } }
    class: irreversible
    when:
      - if: { arg: dry_run, equals: "true" }
        class: read
    resource: { arg: name, kind: app }
    card: x
    status: draft
    tests:
      - { fixture: fixtures/destroy.json, expect: irreversible, resource: web }
      - { fixture: fixtures/destroy-dry.json, expect: read, resource: web }
`)},
		"local-mcp/fixtures/destroy.json":     {Data: []byte(`{"description": "Destroy web", "tool": "apps-destroy", "arguments": {"name": "web"}}`)},
		"local-mcp/fixtures/destroy-dry.json": {Data: []byte(`{"tool": "apps-destroy", "arguments": {"name": "web", "dry_run": true}}`)},
	}
	c, err := catalog.Load(m)
	if err != nil {
		t.Fatal(err)
	}
	if rep := Run(c); rep.Failed != 0 || len(rep.Outcomes) != 2 {
		t.Fatalf("%+v", rep)
	}
	m["local-mcp/fixtures/destroy.json"] = &fstest.MapFile{Data: []byte(`{"tool": "apps-destroy", "arguments": {"name": "web"}, "extra": 1}`)}
	c, _ = catalog.Load(m)
	if rep := Run(c); rep.Failed != 1 || !strings.Contains(rep.Outcomes[0].Problem, "unknown field") {
		t.Fatalf("unknown field accepted: %+v", rep.Outcomes[0])
	}
}
