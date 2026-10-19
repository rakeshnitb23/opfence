package drift

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/rakeshnitb23/opfence/internal/catalog"
)

const provider = `provider: acme
title: Acme Cloud
hosts: [api.acme.dev]
graphql: [/graphql]
defaults:
  rest_safe_methods: read
  graphql_query: read
mcp:
  names: [acme]
schemas:
  - kind: openapi
    url: https://schemas.acme.dev/openapi.yaml
  - kind: graphql
    url: https://schemas.acme.dev/schema.graphql
`

const rules = `operations:
  - id: acme.db.create
    match: { rest: { method: POST, path: "/v1/dbs" } }
    class: money
    card: "Do it"
    status: community
  - id: acme.db.delete
    match: { rest: { method: DELETE, path: "/v1/dbs/{id}" } }
    class: irreversible
    card: "Do it"
    status: community
  - id: acme.db.secret
    match: { rest: { method: GET, path: "/v1/dbs/{id}/password" } }
    class: credential
    card: "Do it"
    status: community
  - id: acme.db.restore
    match: { rest: { method: POST, path: "/v1/dbs/{id}/restore" } }
    class: write
    card: "Do it"
    status: community
  - id: acme.backup.run
    match: { rest: { method: POST, path: "/v1/backups" } }
    unlisted: "used by the acme CLI, not in the OpenAPI file"
    class: write
    card: "Do it"
    status: community
  - id: acme.blob.put
    match: { rest: { method: PUT, path: "/v1/blobs/{key}" } }
    unlisted: "the blobs API is documented separately"
    class: write
    card: "Do it"
    status: community
  - id: acme.project.delete
    match: { graphql: { type: mutation, field: projectDelete } }
    class: irreversible
    card: "Do it"
    status: community
  - id: acme.tool.run
    match: { mcp: { tool: run } }
    class: irreversible
    card: "Do it"
    status: community
`

const openapi = `openapi: 3.0.0
servers:
  - url: https://api.acme.dev/v1
paths:
  /dbs:
    get: {}
    post: {}
  /dbs/{db_id}:
    get: {}
    delete: {}
  /dbs/{db_id}/password:
    get: {}
  /dbs/{db_id}/resize:
    post: {}
  /blobs/{key}:
    put: {}
  /chat:
    post:
      servers:
        - url: https://inference.acme.run
  /upload:
    put:
      $ref: ops/upload.yaml
  /export:
    post:
      $ref: ops/export.yaml
`

const graphql = `type Query { project(id: ID!): String }
type Mutation {
  projectDelete(id: ID!): Boolean
  projectCreate(name: String!): ID
}
`

func testCatalog(t *testing.T) *catalog.Catalog {
	t.Helper()
	c, err := catalog.Load(fstest.MapFS{
		"acme/provider.yaml": {Data: []byte(provider)},
		"acme/rules.yaml":    {Data: []byte(rules)},
		"embed.go":           {Data: []byte("package catalog")},
	})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func fakeFetcher(files map[string]string) Fetcher {
	return func(_ context.Context, url string) ([]byte, error) {
		s, ok := files[url]
		if !ok {
			return nil, errors.New("HTTP 404 Not Found")
		}
		return []byte(s), nil
	}
}

var schemaFiles = map[string]string{
	"https://schemas.acme.dev/openapi.yaml":    openapi,
	"https://schemas.acme.dev/schema.graphql":  graphql,
	"https://schemas.acme.dev/ops/upload.yaml": "servers:\n  - url: \"https://\"\n",
	"https://schemas.acme.dev/ops/export.yaml": "summary: Export\n",
}

func ids(fs []Finding) []string {
	var out []string
	for _, f := range fs {
		if f.Rule != nil {
			out = append(out, f.Rule.ID)
		} else {
			out = append(out, f.Op.String())
		}
	}
	return out
}

func TestCheckProvider(t *testing.T) {
	c := testCatalog(t)
	reps := Check(context.Background(), c, fakeFetcher(schemaFiles), nil)
	if len(reps) != 1 {
		t.Fatalf("got %d reports", len(reps))
	}
	r := reps[0]
	if r.Err != nil {
		t.Fatal(r.Err)
	}
	if got, want := ids(r.Stale), []string{"acme.db.restore"}; !slices.Equal(got, want) {
		t.Errorf("stale = %v, want %v", got, want)
	}
	// /chat is on another host, /upload's $ref has a hostless server;
	// /export's $ref has no servers, so it is on the provider's host.
	if got, want := ids(r.Uncovered), []string{"POST /v1/dbs/{db_id}/resize", "POST /v1/export", "mutation projectCreate"}; !slices.Equal(got, want) {
		t.Errorf("uncovered = %v, want %v", got, want)
	}
	if r.Foreign != 2 {
		t.Errorf("foreign = %d, want 2", r.Foreign)
	}
	if got, want := ids(r.Listed), []string{"acme.blob.put"}; !slices.Equal(got, want) {
		t.Errorf("listed = %v, want %v", got, want)
	}
	// Five rules compared: the unlisted ones and the MCP rule are not.
	if r.Compared != 5 {
		t.Errorf("compared = %d, want 5", r.Compared)
	}
	if !r.Failed() {
		t.Error("report did not fail")
	}
}

func TestPartialCoverage(t *testing.T) {
	c := testCatalog(t)
	p := c.Providers[0]
	p.Schemas = []catalog.SchemaSource{{Kind: "graphql", URL: "https://schemas.acme.dev/schema.graphql", Coverage: "partial"}}
	r := CheckProvider(context.Background(), p, fakeFetcher(schemaFiles))
	if len(r.Stale) != 0 || len(r.Uncovered) != 1 || !r.Uncovered[0].Partial {
		t.Fatalf("stale %v, uncovered %v", ids(r.Stale), ids(r.Uncovered))
	}
	if r.Failed() {
		t.Error("partial coverage failed the check")
	}
}

func TestFetchError(t *testing.T) {
	c := testCatalog(t)
	r := CheckProvider(context.Background(), c.Providers[0], fakeFetcher(nil))
	if r.Err == nil || !r.Failed() {
		t.Fatalf("err = %v, failed = %v", r.Err, r.Failed())
	}
}

func TestExtract(t *testing.T) {
	tests := []struct {
		name string
		sc   catalog.SchemaSource
		data string
		want []string
		err  string
	}{
		{
			name: "swagger base path",
			sc:   catalog.SchemaSource{Kind: "openapi"},
			data: `{"swagger": "2.0", "basePath": "/api/v1", "paths": {"/sites/{id}": {"delete": {}, "parameters": []}}}`,
			want: []string{"DELETE /api/v1/sites/{id}"},
		},
		{
			name: "prefix overrides the servers",
			sc:   catalog.SchemaSource{Kind: "openapi", Prefix: "/v2"},
			data: "openapi: 3.1.0\nservers: [{url: 'https://{region}.acme.dev/api'}]\npaths:\n  /x:\n    post: {}\n",
			want: []string{"POST /v2/x"},
		},
		{
			name: "path item in another file",
			sc:   catalog.SchemaSource{Kind: "openapi"},
			data: "openapi: 3.0.0\npaths:\n  /x:\n    $ref: paths/x.yaml\n",
			err:  "bundled schema",
		},
		{
			name: "not openapi",
			sc:   catalog.SchemaSource{Kind: "openapi"},
			data: "paths: {}\n",
			err:  "not an OpenAPI",
		},
		{
			name: "graphql schema definition",
			sc:   catalog.SchemaSource{Kind: "graphql"},
			data: "schema { query: Q mutation: M }\ntype Q { a: Int }\ntype M { b: Int }\nextend type M { c: Int }\n",
			want: []string{"query a", "mutation b", "mutation c"},
		},
		{
			name: "graphql introspection",
			sc:   catalog.SchemaSource{Kind: "graphql"},
			data: `{"data": {"__schema": {"queryType": {"name": "Query"}, "mutationType": {"name": "Mutation"}, "types": [{"name": "Mutation", "fields": [{"name": "appDelete"}]}, {"name": "App", "fields": [{"name": "id"}]}]}}}`,
			want: []string{"mutation appDelete"},
		},
		{
			name: "heroku hyper-schema",
			sc:   catalog.SchemaSource{Kind: "heroku"},
			data: `{"definitions": {"app": {"links": [{"href": "/apps/{(%23%2Fdefinitions%2Fapp%2Fdefinitions%2Fidentity)}", "method": "DELETE"}, {"href": "/apps", "method": "GET"}]}}}`,
			want: []string{"DELETE /apps/{(%23%2Fdefinitions%2Fapp%2Fdefinitions%2Fidentity)}", "GET /apps"},
		},
		{
			name: "botocore rest protocol",
			sc:   catalog.SchemaSource{Kind: "botocore", Service: "lambda"},
			data: `{"metadata": {"protocol": "rest-json"}, "operations": {"DeleteFunction": {"http": {"method": "DELETE", "requestUri": "/2015-03-31/functions/{FunctionName}?Qualifier"}}}}`,
			want: []string{"lambda DeleteFunction (DELETE /2015-03-31/functions/{FunctionName})"},
		},
		{
			name: "botocore query protocol",
			sc:   catalog.SchemaSource{Kind: "botocore", Service: "iam"},
			data: `{"metadata": {"protocol": "query"}, "operations": {"DeleteUser": {"http": {"method": "POST", "requestUri": "/"}}}}`,
			want: []string{"iam DeleteUser"},
		},
		{
			name: "queries only",
			sc:   catalog.SchemaSource{Kind: "graphql"},
			data: "type Query { a: Int }\n",
			want: []string{"query a"},
		},
		{
			name: "no operations",
			sc:   catalog.SchemaSource{Kind: "heroku"},
			data: `{"definitions": {}}`,
			err:  "no operations",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ops, err := Extract(tt.sc, []string{"api.acme.dev"}, []byte(tt.data))
			if tt.err != "" {
				if err == nil || !strings.Contains(err.Error(), tt.err) {
					t.Fatalf("err = %v, want %q", err, tt.err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			var got []string
			for _, o := range ops {
				got = append(got, o.String())
			}
			if !slices.Equal(got, tt.want) {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestCompilePath(t *testing.T) {
	p := compilePath("/buckets/{Bucket}/{Key+}")
	for path, want := range map[string]bool{
		"/buckets/b/a/b/c": true,
		"/buckets/b/k":     true,
		"/buckets/b":       false,
		"/buckets/b/k/":    true,
	} {
		if got := p.re.MatchString(path); got != want {
			t.Errorf("%s: got %v, want %v", path, got, want)
		}
	}
	if p.sample != "/buckets/x1/x1/x2" {
		t.Errorf("sample = %q", p.sample)
	}
}

func TestOnHosts(t *testing.T) {
	hosts := []string{"api.acme.dev", "*.acme.run"}
	for host, want := range map[string]bool{
		"api.acme.dev":    true,
		"API.ACME.DEV":    true,
		"eu.acme.run":     true,
		"acme.run":        false,
		"evilacme.run":    false,
		"api.acme.dev.io": false,
	} {
		if got := onHosts(host, hosts); got != want {
			t.Errorf("%s: got %v, want %v", host, got, want)
		}
	}
}

func TestAWS(t *testing.T) {
	c, err := catalog.Load(fstest.MapFS{
		"aws/provider.yaml": {Data: []byte("provider: aws\ntitle: AWS\nhosts: [\"*.amazonaws.com\"]\nsigv4: true\ndefaults:\n  aws_read_actions: read\nschemas:\n  - kind: botocore\n    service: lambda\n    url: https://schemas.acme.dev/lambda.json\n")},
		"aws/rules.yaml": {Data: []byte(`operations:
  - id: aws.lambda.delete
    match: { aws: { service: lambda, method: DELETE, path: "/2015-03-31/functions/{name}" } }
    class: irreversible
    card: x
    status: community
  - id: aws.lambda.invoke
    match: { aws: { service: lambda, action: InvokeFunction } }
    class: write
    card: x
    status: community
  - id: aws.lambda.gone
    match: { aws: { service: lambda, action: DeleteLayer } }
    class: delete
    card: x
    status: community
  - id: aws.iam.delete-user
    match: { aws: { service: iam, action: DeleteUser } }
    class: access
    card: x
    status: community
`)},
		"embed.go": {Data: []byte("package catalog")},
	})
	if err != nil {
		t.Fatal(err)
	}
	model := `{"metadata": {"protocol": "rest-json"}, "operations": {
		"DeleteFunction": {"http": {"method": "DELETE", "requestUri": "/2015-03-31/functions/{FunctionName}"}},
		"InvokeFunction": {"http": {"method": "POST", "requestUri": "/2015-03-31/functions/{FunctionName}/invocations"}},
		"GetFunction": {"http": {"method": "GET", "requestUri": "/2015-03-31/functions/{FunctionName}"}},
		"PublishVersion": {"http": {"method": "POST", "requestUri": "/2015-03-31/functions/{FunctionName}/versions"}}}}`
	r := CheckProvider(context.Background(), c.Providers[0], fakeFetcher(map[string]string{"https://schemas.acme.dev/lambda.json": model}))
	if r.Err != nil {
		t.Fatal(r.Err)
	}
	// The IAM rule has no model to compare with.
	if got, want := ids(r.Stale), []string{"aws.lambda.gone"}; !slices.Equal(got, want) {
		t.Errorf("stale = %v, want %v", got, want)
	}
	if got, want := ids(r.Uncovered), []string{"lambda PublishVersion (POST /2015-03-31/functions/{FunctionName}/versions)"}; !slices.Equal(got, want) {
		t.Errorf("uncovered = %v, want %v", got, want)
	}
	if r.Compared != 3 {
		t.Errorf("compared = %d, want 3", r.Compared)
	}
}
