package fixture

import (
	"strings"
	"testing"
	"testing/fstest"

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
