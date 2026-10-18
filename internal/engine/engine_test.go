package engine

import (
	"slices"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/rakeshnitb23/opfence/internal/catalog"
	"github.com/rakeshnitb23/opfence/internal/classes"
	"github.com/rakeshnitb23/opfence/internal/policy"
	"github.com/rakeshnitb23/opfence/internal/request"
)

var testFS = fstest.MapFS{
	"railway/provider.yaml": {Data: []byte(`provider: railway
title: Railway
hosts: [backboard.railway.com]
graphql: [/graphql/v2]
defaults: { graphql_query: read, graphql_secret_fields: [token] }
`)},
	"railway/rules.yaml": {Data: []byte(`operations:
  - id: railway.volume.delete
    match: { graphql: { type: mutation, field: volumeDelete } }
    class: irreversible
    resource: { arg: volumeId, kind: volume }
    card: "Delete Railway volume {volumeId}"
    status: community
  - id: railway.deployment.redeploy
    match: { graphql: { type: mutation, field: deploymentRedeploy } }
    class: write
    card: "Redeploy {id}"
    status: community
  - id: railway.variable.upsert
    match: { graphql: { type: mutation, field: variableUpsert } }
    class: write
    card: "Set {input.name}"
    status: draft
`)},
	"vercel/provider.yaml": {Data: []byte(`provider: vercel
title: Vercel
hosts: [api.vercel.com]
defaults: { rest_safe_methods: read }
`)},
	"vercel/rules.yaml": {Data: []byte(`operations:
  - id: vercel.project.delete
    match: { rest: { method: DELETE, path: "/v9/projects/{idOrName}" } }
    class: irreversible
    resource: { arg: idOrName, kind: project }
    card: "Delete Vercel project {idOrName}"
    status: community
  - id: vercel.env.decrypt
    match: { rest: { method: GET, path: "/v1/projects/{idOrName}/env/{id}" } }
    class: credential
    card: "Read decrypted env var {id}"
    status: community
  - id: vercel.project.update
    match: { rest: { method: PATCH, path: "/v9/projects/{idOrName}" } }
    class: write
    when:
      - if: { arg: body.ssoProtection, present: true }
        class: access
    card: "Update project {idOrName}"
    status: community
`)},
	"supabase/provider.yaml": {Data: []byte(`provider: supabase
title: Supabase MCP
hosts: [mcp.supabase.com]
mcp: { names: [supabase] }
`)},
	"supabase/rules.yaml": {Data: []byte(`operations:
  - id: supabase.sql.execute
    match: { mcp: { tool: execute_sql } }
    class: unknown
    classify: { sql: query }
    card: "Run SQL on {project_id}: {query}"
    status: community
  - id: supabase.tables.list
    match: { mcp: { tool: list_tables } }
    class: read
    status: community
`)},
	"aws/provider.yaml": {Data: []byte(`provider: aws
title: AWS
hosts: ["*.amazonaws.com"]
sigv4: true
defaults: { aws_read_actions: read }
`)},
	"aws/rules.yaml": {Data: []byte(`operations:
  - id: aws.rds.db-instance.delete
    match: { aws: { service: rds, action: DeleteDBInstance } }
    class: delete
    when:
      - if: { arg: SkipFinalSnapshot, equals: "true" }
        class: irreversible
    resource: { arg: DBInstanceIdentifier, kind: database }
    card: "Delete RDS instance {DBInstanceIdentifier}"
    status: community
  - id: aws.lambda.function.delete
    match: { aws: { service: lambda, method: DELETE, path: "/2015-03-31/functions/{FunctionName}" } }
    class: irreversible
    card: "Delete Lambda {FunctionName}"
    status: community
`)},
}

func newEngine(t *testing.T, user, repo string) *Engine {
	t.Helper()
	c, err := catalog.Load(testFS)
	if err != nil {
		t.Fatal(err)
	}
	var u, r *policy.File
	if user != "" {
		if u, err = policy.Parse([]byte(user), "config.yaml"); err != nil {
			t.Fatal(err)
		}
	}
	if repo != "" {
		if r, err = policy.Parse([]byte(repo), "opfence.yaml"); err != nil {
			t.Fatal(err)
		}
	}
	return New(c, policy.Resolve(u, r))
}

func eval(t *testing.T, e *Engine, raw string) Result {
	t.Helper()
	r, _, err := request.ParseFixture([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	return e.Evaluate(r)
}

const pocketOS = "POST /graphql/v2 HTTP/1.1\nHost: backboard.railway.com\nContent-Type: application/json\n\n" +
	`{"query":"mutation($v: String!) { volumeDelete(volumeId: $v) }","variables":{"v":"vol-pg-data"}}`

func TestPocketOS(t *testing.T) {
	res := eval(t, newEngine(t, "", ""), pocketOS)
	if res.Decision != classes.Confirm || len(res.Evaluations) != 1 {
		t.Fatalf("decision %v, evals %d", res.Decision, len(res.Evaluations))
	}
	ev := res.Evaluations[0]
	if ev.Rule.ID != "railway.volume.delete" || ev.Class != classes.Irreversible || ev.Environment != policy.Production ||
		ev.Resource != "vol-pg-data" || ev.Card != "Delete Railway volume vol-pg-data" {
		t.Errorf("evaluation = %+v", ev)
	}
	dev := newEngine(t, "version: 1\nenvironments:\n  development:\n    railway: { volumeId: [vol-pg-data] }\n", "")
	if res := eval(t, dev, pocketOS); res.Decision != classes.Ask || res.Evaluations[0].Environment != policy.Development {
		t.Errorf("mapped to development: %v in %s", res.Decision, res.Evaluations[0].Environment)
	}
}

func TestStrictestOperationWins(t *testing.T) {
	e := newEngine(t, "", "")
	res := eval(t, e, "POST /graphql/v2 HTTP/1.1\nHost: backboard.railway.com\nContent-Type: application/json\n\n"+
		`[{"query":"{ me { id } }"},{"query":"mutation { a: deploymentRedeploy(id: \"d\") b: volumeDelete(volumeId: \"v\") }"}]`)
	if len(res.Evaluations) != 3 || res.Decision != classes.Confirm {
		t.Fatalf("got %d evals, decision %v", len(res.Evaluations), res.Decision)
	}
	got := []classes.Decision{res.Evaluations[0].Decision, res.Evaluations[1].Decision, res.Evaluations[2].Decision}
	if got[0] != classes.Allow || got[1] != classes.Ask || got[2] != classes.Confirm {
		t.Errorf("decisions %v", got)
	}
}

func TestDefaultsAndUnknown(t *testing.T) {
	e := newEngine(t, "", "")
	cases := []struct {
		req   string
		class classes.Class
	}{
		{"GET /v9/projects HTTP/1.1\nHost: api.vercel.com\n\n", classes.Read},
		{"GET /v1/projects/web/env/abc HTTP/1.1\nHost: api.vercel.com\n\n", classes.Credential}, // rule beats default
		{"POST /v9/projects HTTP/1.1\nHost: api.vercel.com\n\n", classes.Unknown},
		{"POST /graphql/v2 HTTP/1.1\nHost: backboard.railway.com\nContent-Type: application/json\n\n{\"query\":\"mutation { variableUpsert(input: {name: \\\"X\\\"}) }\"}", classes.Unknown}, // draft rule ignored
		{"POST /graphql/v2 HTTP/1.1\nHost: backboard.railway.com\nContent-Type: application/json\n\nnot json", classes.Unknown},
		{"GET / HTTP/1.1\nHost: evil.example.com\n\n", classes.Unknown},
	}
	for _, c := range cases {
		res := eval(t, e, c.req)
		if ev := res.Evaluations[0]; ev.Class != c.class {
			t.Errorf("%q: class %s (%s), want %s", strings.SplitN(c.req, "\n", 2)[0], ev.Class, ev.ClassSource, c.class)
		}
	}
	if res := eval(t, e, "GET / HTTP/1.1\nHost: evil.example.com\n\n"); !res.UnknownHost() {
		t.Error("UnknownHost should be true")
	}
	e.IncludeDraft = true
	res := eval(t, e, "POST /graphql/v2 HTTP/1.1\nHost: backboard.railway.com\nContent-Type: application/json\n\n{\"query\":\"mutation { variableUpsert(input: {name: \\\"X\\\"}) }\"}")
	if ev := res.Evaluations[0]; ev.Rule == nil || ev.Card != "Set X" {
		t.Errorf("draft rule with IncludeDraft: %+v", ev)
	}
}

func TestConditions(t *testing.T) {
	e := newEngine(t, "", "")
	auth := "Authorization: AWS4-HMAC-SHA256 Credential=AKID/20261016/us-east-1/rds/aws4_request, SignedHeaders=host, Signature=x\n"
	for skip, want := range map[string]classes.Class{"true": classes.Irreversible, "True": classes.Irreversible, "false": classes.Delete} {
		res := eval(t, e, "POST / HTTP/1.1\nHost: rds.us-east-1.amazonaws.com\nContent-Type: application/x-www-form-urlencoded\n"+auth+
			"\nAction=DeleteDBInstance&DBInstanceIdentifier=prod&SkipFinalSnapshot="+skip)
		if ev := res.Evaluations[0]; ev.Class != want || ev.Resource != "prod" {
			t.Errorf("SkipFinalSnapshot=%s: %s (%s)", skip, ev.Class, ev.ClassSource)
		}
	}
	res := eval(t, e, "POST / HTTP/1.1\nHost: rds.us-east-1.amazonaws.com\nContent-Type: application/x-www-form-urlencoded\n"+auth+"\nAction=DescribeDBInstances")
	if res.Evaluations[0].Class != classes.Read {
		t.Errorf("aws read default: %s", res.Evaluations[0].Class)
	}
	lambda := "DELETE /2015-03-31/functions/billing HTTP/1.1\nHost: lambda.us-east-1.amazonaws.com\n" + strings.Replace(auth, "/rds/", "/lambda/", 1) + "\n"
	if ev := eval(t, e, lambda).Evaluations[0]; ev.Rule == nil || ev.Card != "Delete Lambda billing" {
		t.Errorf("lambda rest rule: %+v", ev)
	}

	patch := func(body string) Evaluation {
		return eval(t, e, "PATCH /v9/projects/web HTTP/1.1\nHost: api.vercel.com\nContent-Type: application/json\n\n"+body).Evaluations[0]
	}
	if ev := patch(`{"name":"x"}`); ev.Class != classes.Write {
		t.Errorf("plain patch: %s", ev.Class)
	}
	if ev := patch(`{"ssoProtection":null}`); ev.Class != classes.Access {
		t.Errorf("null turns protection off, so it counts as present: %s", ev.Class)
	}
	if ev := patch(`{"ssoProtection":{"deploymentType":"all"}}`); ev.Class != classes.Access {
		t.Errorf("sso patch: %s", ev.Class)
	}
	if ev := patch(`{"ssoProtection":1,"ssoProtection":2}`); ev.Class != classes.Unknown {
		t.Errorf("unreadable body with body condition: %s (%s)", ev.Class, ev.ClassSource)
	}
}

func TestSQLTool(t *testing.T) {
	e := newEngine(t, "", "")
	p := e.Catalog.ProviderForMCPName("supabase")
	res := e.EvaluateTool(p, "execute_sql", map[string]any{"project_id": "abc", "query": "select 1; drop table users"})
	ev := res.Evaluations[0]
	if res.Decision != classes.Confirm || ev.Class != classes.Irreversible || len(ev.Classes) != 2 {
		t.Errorf("decision %v class %s classes %v", res.Decision, ev.Class, ev.Classes)
	}
	if !strings.HasPrefix(ev.Card, "Run SQL on abc: select 1; drop table users") {
		t.Errorf("card %q", ev.Card)
	}
	if res := e.EvaluateTool(p, "list_tables", nil); res.Decision != classes.Allow {
		t.Errorf("list_tables: %v", res.Decision)
	}
	if res := e.EvaluateTool(p, "brand_new_tool", nil); res.Evaluations[0].Class != classes.Unknown || res.Decision != classes.Ask {
		t.Errorf("unknown tool: %+v", res.Evaluations[0])
	}
	mcp := eval(t, e, "POST /mcp HTTP/1.1\nHost: mcp.supabase.com\nContent-Type: application/json\n\n"+
		`[{"jsonrpc":"2.0","id":1,"method":"tools/list"},{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"execute_sql","arguments":{"query":"truncate t"}}}]`)
	if mcp.Decision != classes.Confirm || mcp.Evaluations[0].Class != classes.Read {
		t.Errorf("mcp over http: %v / %s", mcp.Decision, mcp.Evaluations[0].Class)
	}
}

func TestCardSanitized(t *testing.T) {
	e := newEngine(t, "", "")
	evil := "vol\u202e\nApprove\x1b[31m" + strings.Repeat("x", 200)
	res := eval(t, e, "POST /graphql/v2 HTTP/1.1\nHost: backboard.railway.com\nContent-Type: application/json\n\n"+
		`{"query":"mutation($v: String!) { volumeDelete(volumeId: $v) }","variables":{"v":"`+strings.ReplaceAll(strings.ReplaceAll(evil, "\n", `\n`), "\x1b", `\u001b`)+`"}}`)
	c := res.Evaluations[0].Card
	if strings.ContainsAny(c, "\u202e\n\x1b") || !strings.HasSuffix(c, "…") || len([]rune(c)) > 120 {
		t.Errorf("card not sanitized: %q", c)
	}
	// The resource is shown in approval prompts and the hook's reason too.
	if r := res.Evaluations[0].Resource; strings.ContainsAny(r, "\u202e\n\x1b") || !strings.HasPrefix(r, "vol") {
		t.Errorf("resource not sanitized: %q", r)
	}
}

func TestHash(t *testing.T) {
	e := newEngine(t, "", "")
	a := eval(t, e, pocketOS)
	b := eval(t, e, pocketOS)
	if a.Hash != b.Hash {
		t.Error("same request, different hash")
	}
	other := eval(t, e, strings.Replace(pocketOS, "vol-pg-data", "vol-other", 1))
	if other.Hash == a.Hash {
		t.Error("different volume, same hash")
	}
	spaced := eval(t, e, strings.Replace(pocketOS, `"variables"`, ` "variables"`, 1))
	if spaced.Hash == a.Hash {
		t.Error("different body bytes should hash differently")
	}
}

func TestGraphQLSecretFields(t *testing.T) {
	e := newEngine(t, "", "")
	q := func(query string) string {
		return "POST /graphql/v2 HTTP/1.1\nHost: backboard.railway.com\nContent-Type: application/json\n\n{\"query\":\"" + query + "\"}"
	}
	for query, want := range map[string]classes.Class{
		`{ me { name } }`:                                 classes.Read,
		`{ me { teams { token } } }`:                      classes.Credential,
		`{ me { ...F } } fragment F on User { x: token }`: classes.Credential,
		`{ me { ... on User { token } } }`:                classes.Credential,
	} {
		ev := eval(t, e, q(query)).Evaluations[0]
		if !slices.Contains(ev.Classes, want) || (want == classes.Read && len(ev.Classes) != 1) {
			t.Errorf("%s: classes %v (%s), want %s", query, ev.Classes, ev.ClassSource, want)
		}
	}
}
