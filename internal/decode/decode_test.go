package decode

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/rakeshnitb23/opfence/internal/request"
)

func fixture(t testing.TB, s string) *request.Request {
	t.Helper()
	r, _, err := request.ParseFixture([]byte(s))
	if err != nil {
		t.Fatalf("fixture: %v\n%s", err, s)
	}
	return r
}

var railway = Hints{GraphQLPaths: []string{"/graphql/v2"}}

func gqlPost(body string) string {
	return "POST /graphql/v2 HTTP/1.1\nHost: backboard.railway.com\nContent-Type: application/json\n\n" + body
}

type opSummary struct {
	Type, Field string
	Args        map[string]any
}

func summarize(ops []Operation) []opSummary {
	var out []opSummary
	for _, o := range ops {
		out = append(out, opSummary{o.GraphQLType, o.Field, o.Args})
	}
	return out
}

func TestGraphQL(t *testing.T) {
	cases := []struct {
		name string
		req  string
		want []opSummary
	}{
		{
			"variables",
			gqlPost(`{"query":"mutation volumeDelete($volumeId: String!) { volumeDelete(volumeId: $volumeId) }","variables":{"volumeId":"vol-1"}}`),
			[]opSummary{{"mutation", "volumeDelete", map[string]any{"volumeId": "vol-1"}}},
		},
		{
			"alias hides nothing",
			gqlPost(`{"query":"mutation { harmless: volumeDelete(volumeId: \"v\") }"}`),
			[]opSummary{{"mutation", "volumeDelete", map[string]any{"volumeId": "v"}}},
		},
		{
			"fragments and inline fragments",
			gqlPost(`{"query":"mutation M { ...F ... on Mutation { serviceDelete(id: \"s\") } } fragment F on Mutation { volumeDelete(volumeId: \"v\") }"}`),
			[]opSummary{
				{"mutation", "volumeDelete", map[string]any{"volumeId": "v"}},
				{"mutation", "serviceDelete", map[string]any{"id": "s"}},
			},
		},
		{
			"multiple root fields and default variables",
			gqlPost(`{"query":"mutation($n: Int = 3, $o: VolumeInput) { a: volumeUpdate(volumeId: \"v\", input: {sizeMB: $n, name: \"x\", tags: [1, true, null, ENUM]}) b: volumeDelete(volumeId: \"w\") }"}`),
			[]opSummary{
				{"mutation", "volumeUpdate", map[string]any{"volumeId": "v", "input": map[string]any{"sizeMB": json.Number("3"), "name": "x", "tags": []any{json.Number("1"), true, nil, "ENUM"}}}},
				{"mutation", "volumeDelete", map[string]any{"volumeId": "w"}},
			},
		},
		{
			"every operation in the document counts",
			gqlPost(`{"query":"query Safe { me { id } } mutation Bad { volumeDelete(volumeId: \"v\") }","operationName":"Safe"}`),
			[]opSummary{
				{"query", "me", map[string]any{}},
				{"mutation", "volumeDelete", map[string]any{"volumeId": "v"}},
			},
		},
		{
			"batch",
			gqlPost(`[{"query":"{ me { id } }"},{"query":"mutation { volumeDelete(volumeId: \"v\") }"}]`),
			[]opSummary{
				{"query", "me", map[string]any{}},
				{"mutation", "volumeDelete", map[string]any{"volumeId": "v"}},
			},
		},
		{
			"variables as a string",
			gqlPost(`{"query":"mutation($v: String!) { volumeDelete(volumeId: $v) }","variables":"{\"v\":\"x\"}"}`),
			[]opSummary{{"mutation", "volumeDelete", map[string]any{"volumeId": "x"}}},
		},
		{
			"application/graphql",
			"POST /graphql/v2 HTTP/1.1\nHost: backboard.railway.com\nContent-Type: application/graphql\n\nmutation { volumeDelete(volumeId: \"v\") }",
			[]opSummary{{"mutation", "volumeDelete", map[string]any{"volumeId": "v"}}},
		},
		{
			"GET",
			"GET /graphql/v2?query=%7B%20me%20%7B%20id%20%7D%20%7D HTTP/1.1\nHost: backboard.railway.com\n\n",
			[]opSummary{{"query", "me", map[string]any{}}},
		},
		{
			"path normalised",
			"POST //graphql/v2/ HTTP/1.1\nHost: backboard.railway.com\nContent-Type: application/json\n\n{\"query\":\"mutation { volumeDelete(volumeId: \\\"v\\\") }\"}",
			[]opSummary{{"mutation", "volumeDelete", map[string]any{"volumeId": "v"}}},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ops := Decode(fixture(t, c.req), railway)
			for _, o := range ops {
				if o.Error != "" {
					t.Fatalf("decode error: %s", o.Error)
				}
				if o.Protocol != GraphQL {
					t.Fatalf("protocol %q", o.Protocol)
				}
			}
			if got := summarize(ops); !reflect.DeepEqual(got, c.want) {
				t.Errorf("got  %#v\nwant %#v", got, c.want)
			}
		})
	}
}

func TestGraphQLFailsClosed(t *testing.T) {
	many := strings.Repeat("me { id } ", MaxOperations+1)
	cases := map[string]string{
		"parse error":          gqlPost(`{"query":"mutation { volumeDelete(volumeId: "}`),
		"duplicate key":        gqlPost(`{"query":"{ me { id } }","query":"mutation { volumeDelete(volumeId: \"v\") }"}`),
		"persisted only":       gqlPost(`{"extensions":{"persistedQuery":{"version":1,"sha256Hash":"abc"}},"variables":{}}`),
		"no query":             gqlPost(`{"variables":{}}`),
		"not json":             gqlPost(`mutation { x }`),
		"trailing data":        gqlPost(`{"query":"{ me { id } }"} {"query":"mutation { a }"}`),
		"batch of non-objects": gqlPost(`["{ me }"]`),
		"empty batch":          gqlPost(`[]`),
		"unknown fragment":     gqlPost(`{"query":"mutation { ...Nope }"}`),
		"self fragment":        gqlPost(`{"query":"mutation { ...A } fragment A on Mutation { ...A }"}`),
		"too many fields":      gqlPost(`{"query":"{ ` + many + ` }"}`),
		"multipart upload":     "POST /graphql/v2 HTTP/1.1\nHost: backboard.railway.com\nContent-Type: multipart/form-data; boundary=x\n\n--x--",
		"compressed unknown":   "POST /graphql/v2 HTTP/1.1\nHost: backboard.railway.com\nContent-Type: application/json\nContent-Encoding: br\n\nxx",
		"repeated argument":    gqlPost(`{"query":"mutation { volumeDelete(volumeId: \"a\", volumeId: \"b\") }"}`),
	}
	for name, req := range cases {
		t.Run(name, func(t *testing.T) {
			ops := Decode(fixture(t, req), railway)
			if len(ops) != 1 || ops[0].Error == "" {
				t.Fatalf("expected one failed operation, got %+v", ops)
			}
		})
	}
}

func TestREST(t *testing.T) {
	r := fixture(t, "PATCH /repos/o/r?a=1&b=2&b=3 HTTP/1.1\nHost: api.github.com\nContent-Type: application/json\n\n{\"private\":false,\"name\":\"r\"}")
	ops := Decode(r, Hints{})
	if len(ops) != 1 {
		t.Fatal(ops)
	}
	op := ops[0]
	if op.Protocol != REST || op.Method != "PATCH" || op.Path != "/repos/o/r" || op.BodyErr != "" {
		t.Fatalf("op = %+v", op)
	}
	want := map[string]any{
		"query": map[string]any{"a": "1", "b": []any{"2", "3"}},
		"body":  map[string]any{"private": false, "name": "r"},
	}
	if !reflect.DeepEqual(op.Args, want) {
		t.Errorf("args = %#v", op.Args)
	}

	form := Decode(fixture(t, "POST /v1/refunds HTTP/1.1\nHost: api.stripe.com\nContent-Type: application/x-www-form-urlencoded\n\ncharge=ch_1&amount=100"), Hints{})[0]
	if form.Args["body"].(map[string]any)["charge"] != "ch_1" {
		t.Errorf("form args = %#v", form.Args)
	}

	bad := Decode(fixture(t, "PATCH /x HTTP/1.1\nHost: api.github.com\nContent-Type: application/json\n\n{\"a\":1,\"a\":2}"), Hints{})[0]
	if bad.BodyErr == "" || bad.Error != "" {
		t.Errorf("duplicate-key body should set BodyErr only: %+v", bad)
	}
	// Both the real and the overriding method are decoded, so neither can
	// hide the other.
	for _, tc := range []struct{ method, override string }{{"POST", "delete"}, {"DELETE", "GET"}} {
		ops := Decode(fixture(t, tc.method+" /v9/projects/web HTTP/1.1\nHost: api.vercel.com\nX-HTTP-Method-Override: "+tc.override+"\nX-Method-Override: "+tc.method+"\n\n"), Hints{})
		if len(ops) != 2 || ops[0].Method != tc.method || ops[1].Method != strings.ToUpper(tc.override) {
			t.Errorf("%s with override %s: ops = %+v", tc.method, tc.override, ops)
		}
	}
	for _, tc := range []struct{ ct, body, want string }{
		{"text/plain", `{"force":true}`, ""},                    // JSON whatever the Content-Type
		{"", " [1]", ""},                                        // no Content-Type
		{"text/plain", "force=true", "neither JSON nor a form"}, // fails closed
		{"application/x-www-form-urlencoded", `{"force":true}`, ""},
	} {
		op := Decode(fixture(t, "PATCH /x HTTP/1.1\nHost: api.github.com\nContent-Type: "+tc.ct+"\n\n"+tc.body), Hints{})[0]
		if !strings.Contains(op.BodyErr, tc.want) || (tc.want == "") != (op.BodyErr == "") {
			t.Errorf("%s body %q: BodyErr = %q", tc.ct, tc.body, op.BodyErr)
		}
		if tc.want == "" && op.Args["body"] == nil {
			t.Errorf("%s body %q not decoded", tc.ct, tc.body)
		}
	}
	big := Decode(fixture(t, "PUT /x HTTP/1.1\nHost: api.github.com\n\n"+strings.Repeat("a", request.MaxBody+1)), Hints{})[0]
	if big.BodyErr == "" {
		t.Error("oversized body should set BodyErr")
	}
}

func TestMCP(t *testing.T) {
	h := Hints{MCP: true}
	post := func(body string) *request.Request {
		return fixture(t, "POST /mcp HTTP/1.1\nHost: mcp.supabase.com\nContent-Type: application/json\n\n"+body)
	}
	ops := Decode(post(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"execute_sql","arguments":{"project_id":"p1","query":"drop table x"}}}`), h)
	if len(ops) != 1 || ops[0].Tool != "execute_sql" || ops[0].Args["query"] != "drop table x" || ops[0].MCPMethod != "tools/call" {
		t.Fatalf("ops = %+v", ops)
	}
	ops = Decode(post(`[{"jsonrpc":"2.0","id":1,"method":"tools/list"},{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"delete_branch","arguments":{"branch_id":"b"}}},{"jsonrpc":"2.0","id":9,"result":{}}]`), h)
	if len(ops) != 3 || ops[0].MCPMethod != "tools/list" || ops[1].Tool != "delete_branch" || ops[2].MCPMethod != MCPResponse {
		t.Fatalf("batch ops = %+v", ops)
	}
	if !IsMCPReadMethod("tools/list") || IsMCPReadMethod("tools/call") {
		t.Error("IsMCPReadMethod")
	}
	get := Decode(fixture(t, "GET /mcp HTTP/1.1\nHost: mcp.supabase.com\nAccept: text/event-stream\n\n"), h)
	if get[0].MCPMethod != "http GET" || get[0].Error != "" {
		t.Errorf("GET = %+v", get)
	}
	for name, body := range map[string]string{
		"not jsonrpc":    `{"id":1,"method":"tools/call","params":{"name":"x"}}`,
		"no tool name":   `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{}}`,
		"bad arguments":  `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"x","arguments":[1]}}`,
		"duplicate name": `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_tables","name":"delete_branch"}}`,
		"empty batch":    `[]`,
		"no method":      `{"jsonrpc":"2.0","id":1}`,
		"garbage":        `hello`,
	} {
		ops := Decode(post(body), h)
		if len(ops) != 1 || ops[0].Error == "" {
			t.Errorf("%s: expected failure, got %+v", name, ops)
		}
	}
}

func TestAWS(t *testing.T) {
	h := Hints{SigV4: true}
	auth := "Authorization: AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20261016/us-east-1/%s/aws4_request, SignedHeaders=host;x-amz-date, Signature=abc\n"
	query := fixture(t, "POST / HTTP/1.1\nHost: rds.us-east-1.amazonaws.com\nContent-Type: application/x-www-form-urlencoded\n"+
		strings.Replace(auth, "%s", "rds", 1)+"\nAction=DeleteDBInstance&DBInstanceIdentifier=prod-db&SkipFinalSnapshot=true&Version=2014-10-31")
	op := Decode(query, h)[0]
	if op.Service != "rds" || op.Action != "DeleteDBInstance" || op.Args["SkipFinalSnapshot"] != "true" || op.Args["DBInstanceIdentifier"] != "prod-db" || op.Error != "" {
		t.Errorf("query protocol op = %+v", op)
	}

	jsonReq := fixture(t, "POST / HTTP/1.1\nHost: dynamodb.us-east-1.amazonaws.com\nContent-Type: application/x-amz-json-1.0\nX-Amz-Target: DynamoDB_20120810.DeleteTable\n"+
		strings.Replace(auth, "%s", "dynamodb", 1)+"\n{\"TableName\":\"orders\"}")
	op = Decode(jsonReq, h)[0]
	if op.Service != "dynamodb" || op.Action != "DeleteTable" || op.Args["TableName"] != "orders" {
		t.Errorf("json protocol op = %+v", op)
	}

	presigned := fixture(t, "GET /?Action=ListUsers&X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKID%2F20261016%2Fus-east-1%2Fiam%2Faws4_request&X-Amz-Signature=x HTTP/1.1\nHost: iam.amazonaws.com\n\n")
	op = Decode(presigned, h)[0]
	if op.Service != "iam" || op.Action != "ListUsers" {
		t.Errorf("presigned op = %+v", op)
	}
	if _, ok := op.Args["X-Amz-Credential"]; ok {
		t.Error("signature parameters should not be args")
	}

	// Parameters a service ignores must not relabel the request.
	s3Spoof := fixture(t, "DELETE /?Action=ListBuckets HTTP/1.1\nHost: backups.s3.amazonaws.com\nX-Amz-Target: DynamoDB_20120810.ListTables\n"+strings.Replace(auth, "%s", "s3", 1)+"\n")
	if op := Decode(s3Spoof, h)[0]; op.Action != "DeleteBucket" {
		t.Errorf("S3 spoof classified as %q", op.Action)
	}
	lambdaSpoof := fixture(t, "DELETE /2015-03-31/functions/f?Action=GetFunction HTTP/1.1\nHost: lambda.us-east-1.amazonaws.com\nX-Amz-Target: AWSLambda.GetFunction\n"+strings.Replace(auth, "%s", "lambda", 1)+"\n")
	if op := Decode(lambdaSpoof, h)[0]; op.Action != "" || op.Method != "DELETE" {
		t.Errorf("Lambda spoof classified as %q", op.Action)
	}
	twoActions := fixture(t, "POST /?Action=DescribeDBInstances HTTP/1.1\nHost: rds.us-east-1.amazonaws.com\nContent-Type: application/x-www-form-urlencoded\n"+strings.Replace(auth, "%s", "rds", 1)+"\nAction=DeleteDBInstance")
	if op := Decode(twoActions, h)[0]; op.Error == "" {
		t.Errorf("two Actions accepted as %q", op.Action)
	}

	unsigned := Decode(fixture(t, "POST / HTTP/1.1\nHost: rds.us-east-1.amazonaws.com\n\nAction=DeleteDBInstance"), h)[0]
	if unsigned.Error == "" {
		t.Error("unsigned AWS request should fail closed")
	}
	sigv4a := fixture(t, "DELETE /2015-03-31/functions/f HTTP/1.1\nHost: lambda.us-east-1.amazonaws.com\nAuthorization: AWS4-ECDSA-P256-SHA256 Credential=AKID/20261016/lambda/aws4_request, SignedHeaders=host, Signature=x\n\n")
	op = Decode(sigv4a, h)[0]
	if op.Service != "lambda" || op.Action != "" || op.Method != "DELETE" || op.Error != "" {
		t.Errorf("rest-json op = %+v", op)
	}
}

func TestS3(t *testing.T) {
	h := Hints{SigV4: true}
	auth := "Authorization: AWS4-HMAC-SHA256 Credential=AKID/20261016/us-east-1/s3/aws4_request, SignedHeaders=host, Signature=x\n"
	cases := []struct {
		req, action, bucket, key string
	}{
		{"DELETE / HTTP/1.1\nHost: backups.s3.us-east-1.amazonaws.com\n", "DeleteBucket", "backups", ""},
		{"DELETE /backups HTTP/1.1\nHost: s3.amazonaws.com\n", "DeleteBucket", "backups", ""},
		{"DELETE /backups/db/2026.sql.gz?versionId=v1 HTTP/1.1\nHost: s3.us-east-1.amazonaws.com\n", "DeleteObject", "backups", "db/2026.sql.gz"},
		{"POST /?delete HTTP/1.1\nHost: my.bucket.s3.amazonaws.com\n", "DeleteObjects", "my.bucket", ""},
		{"PUT /?policy HTTP/1.1\nHost: b.s3.amazonaws.com\n", "PutBucketPolicy", "b", ""},
		{"DELETE /?publicAccessBlock HTTP/1.1\nHost: b.s3.amazonaws.com\n", "DeletePublicAccessBlock", "b", ""},
		{"PUT /k?acl HTTP/1.1\nHost: b.s3.amazonaws.com\n", "PutObjectAcl", "b", "k"},
		{"PUT /k HTTP/1.1\nHost: b.s3.amazonaws.com\nX-Amz-Copy-Source: /a/b\n", "CopyObject", "b", "k"},
		{"GET /?list-type=2 HTTP/1.1\nHost: b.s3.amazonaws.com\n", "ListObjectsV2", "b", ""},
		{"GET / HTTP/1.1\nHost: s3.amazonaws.com\n", "ListBuckets", "", ""},
		{"GET /k HTTP/1.1\nHost: b.s3-us-west-2.amazonaws.com\n", "GetObject", "b", "k"},
		{"PATCH /k HTTP/1.1\nHost: b.s3.amazonaws.com\n", "", "b", "k"},
	}
	for _, c := range cases {
		op := Decode(fixture(t, strings.Replace(c.req, "\n", "\n"+auth, 1)+"\n"), h)[0]
		if op.Action != c.action || op.Error != "" {
			t.Errorf("%q: action %q (err %q), want %q", c.req, op.Action, op.Error, c.action)
			continue
		}
		if b, _ := op.Args["Bucket"].(string); b != c.bucket {
			t.Errorf("%q: bucket %q", c.req, b)
		}
		if k, _ := op.Args["Key"].(string); k != c.key {
			t.Errorf("%q: key %q", c.req, k)
		}
	}
	acl := Decode(fixture(t, "PUT /k HTTP/1.1\nHost: b.s3.amazonaws.com\n"+auth+"X-Amz-Acl: public-read\n\n"), h)[0]
	if acl.Args["headers"].(map[string]any)["x-amz-acl"] != "public-read" {
		t.Errorf("headers = %#v", acl.Args["headers"])
	}
}

func FuzzGraphQL(f *testing.F) {
	f.Add(`{"query":"mutation { a: volumeDelete(volumeId: \"v\") ...F } fragment F on Mutation { x }"}`)
	f.Add(`[{"query":"{ me { id } }","variables":{"a":[1,{"b":null}]}}]`)
	f.Fuzz(func(t *testing.T, body string) {
		r := &request.Request{Method: "POST", Host: "h.example.com", Path: "/graphql", Header: map[string][]string{"Content-Type": {"application/json"}}, Body: []byte(body)}
		ops := Decode(r, Hints{GraphQLPaths: []string{"/graphql"}})
		checkOps(t, ops)
		for _, o := range ops {
			if o.Error == "" && (o.Field == "" || o.GraphQLType == "") {
				t.Fatalf("successful GraphQL op without field or type: %+v", o)
			}
		}
	})
}

func FuzzMCP(f *testing.F) {
	f.Add(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"x","arguments":{"a":1}}}`)
	f.Add(`[{"jsonrpc":"2.0","method":"notifications/initialized"}]`)
	f.Fuzz(func(t *testing.T, body string) {
		r := &request.Request{Method: "POST", Host: "h.example.com", Path: "/mcp", Header: map[string][]string{}, Body: []byte(body)}
		ops := Decode(r, Hints{MCP: true})
		checkOps(t, ops)
		for _, o := range ops {
			if o.Error == "" && o.MCPMethod == "tools/call" && o.Tool == "" {
				t.Fatalf("tools/call without tool: %+v", o)
			}
		}
	})
}

func checkOps(t *testing.T, ops []Operation) {
	t.Helper()
	if len(ops) == 0 || len(ops) > MaxOperations {
		t.Fatalf("got %d operations", len(ops))
	}
}
