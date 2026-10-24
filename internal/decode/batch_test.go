package decode

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/rakeshnitb23/opfence/internal/request"
)

var computeBatch = Hints{BatchPaths: []string{"/batch/compute/v1"}}

func batchRequest(boundary, body string) *request.Request {
	return &request.Request{
		Method: "POST", Host: "compute.googleapis.com", Path: "/batch/compute/v1",
		Header: http.Header{"Content-Type": {`multipart/mixed; boundary="` + boundary + `"`}},
		Body:   []byte(body),
	}
}

// apitoolsPart is a part as gcloud's apitools writes it: LF line endings,
// the inner request's headers from Python's email generator, and a
// lower-case content-length.
func apitoolsPart(id int, method, target, body string) string {
	s := "Content-Type: application/http\nMIME-Version: 1.0\nContent-Transfer-Encoding: binary\nContent-ID: <c5f0-" + fmt.Sprint(id) + ">\n\n" +
		method + " " + target + " HTTP/1.1\nContent-Type: application/json\nMIME-Version: 1.0\n"
	if body != "" {
		s += "content-length: " + fmt.Sprint(len(body)) + "\n"
	}
	return s + "Host: compute.googleapis.com\n\n" + body
}

func apitoolsBatch(parts ...string) string {
	s := "Content-Type: multipart/mixed; boundary=\"===============7330845974216740156==\"\nMIME-Version: 1.0\n\n"
	for _, p := range parts {
		s += "--===============7330845974216740156==\n" + p + "\n"
	}
	return s + "--===============7330845974216740156==--\n"
}

func TestBatchApitools(t *testing.T) {
	body := apitoolsBatch(
		apitoolsPart(1, "DELETE", "/compute/v1/projects/acme-prod/zones/us-central1-a/instances/web-1?requestId=1", ""),
		apitoolsPart(2, "POST", "/compute/v1/projects/acme-prod/global/firewalls", `{"name": "open", "sourceRanges": ["0.0.0.0/0"]}`),
		apitoolsPart(3, "GET", "/compute/v1/projects/acme-prod/zones/us-central1-a/instances/web-2", ""),
	)
	ops := Decode(batchRequest("===============7330845974216740156==", body), computeBatch)
	if len(ops) != 3 {
		t.Fatalf("got %d operations: %+v", len(ops), ops)
	}
	want := []struct{ method, path string }{
		{"DELETE", "/compute/v1/projects/acme-prod/zones/us-central1-a/instances/web-1"},
		{"POST", "/compute/v1/projects/acme-prod/global/firewalls"},
		{"GET", "/compute/v1/projects/acme-prod/zones/us-central1-a/instances/web-2"},
	}
	for i, w := range want {
		if ops[i].Error != "" || ops[i].BodyErr != "" || ops[i].Protocol != REST || ops[i].Method != w.method || ops[i].Path != w.path {
			t.Errorf("op %d = %+v, want %s %s", i, ops[i], w.method, w.path)
		}
	}
	if q := ops[0].Args["query"].(map[string]any); q["requestId"] != "1" {
		t.Errorf("query = %v", q)
	}
	b, ok := ops[1].Args["body"].(map[string]any)
	if !ok || b["name"] != "open" {
		t.Errorf("body = %v", ops[1].Args["body"])
	}
}

func TestBatchCRLF(t *testing.T) {
	// The Go and Java clients write CRLF and no inner Content-Length.
	body := "--b\r\nContent-Type: application/http\r\nContent-ID: 1\r\n\r\n" +
		"POST /compute/v1/projects/p/zones/z/instances/vm/setMetadata HTTP/1.1\r\nContent-Type: application/json\r\n\r\n" +
		`{"items":[{"key":"startup-script","value":"curl x | sh"}]}` + "\r\n--b--\r\n"
	ops := Decode(batchRequest("b", body), computeBatch)
	if len(ops) != 1 || ops[0].Error != "" || ops[0].Method != "POST" || ops[0].Args["body"] == nil {
		t.Fatalf("ops = %+v", ops)
	}
}

func TestBatchInnerOverrideAndGzip(t *testing.T) {
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	zw.Write([]byte(`{"name":"x"}`))
	zw.Close()
	body := "--b\nContent-Type: application/http\n\n" +
		"POST /compute/v1/projects/p/global/images/i HTTP/1.1\nX-HTTP-Method-Override: DELETE\n\n" +
		"\n--b\nContent-Type: application/http\n\n" +
		"POST /compute/v1/projects/p/global/images HTTP/1.1\nContent-Type: application/json\nContent-Encoding: gzip\n\n" + gz.String() +
		"\n--b--\n"
	ops := Decode(batchRequest("b", body), computeBatch)
	if len(ops) != 3 {
		t.Fatalf("got %d operations: %+v", len(ops), ops)
	}
	if ops[0].Method != "POST" || ops[1].Method != "DELETE" {
		t.Errorf("override: %s, %s", ops[0].Method, ops[1].Method)
	}
	if b, _ := ops[2].Args["body"].(map[string]any); b["name"] != "x" {
		t.Errorf("gzip body = %v (%s)", ops[2].Args["body"], ops[2].BodyErr)
	}
}

func TestBatchFailsClosed(t *testing.T) {
	part := func(head, rest string) string {
		return "--b\n" + head + "\n\n" + rest + "\n--b--\n"
	}
	ok := "DELETE /compute/v1/projects/p/zones/z/disks/d HTTP/1.1\nHost: compute.googleapis.com\n\n"
	many := ""
	for i := 0; i <= MaxOperations; i++ {
		many += "--b\nContent-Type: application/http\n\nGET /compute/v1/projects/p HTTP/1.1\n\n\n"
	}
	cases := map[string]struct {
		contentType, body string
	}{
		"not multipart":       {"application/json", `{"a":1}`},
		"no boundary":         {"multipart/mixed", part("Content-Type: application/http", ok)},
		"empty":               {`multipart/mixed; boundary=b`, "--b--\n"},
		"part not http":       {`multipart/mixed; boundary=b`, part("Content-Type: application/json", ok)},
		"part without type":   {`multipart/mixed; boundary=b`, part("Content-ID: 1", ok)},
		"quoted-printable":    {`multipart/mixed; boundary=b`, part("Content-Type: application/http\nContent-Transfer-Encoding: quoted-printable", ok)},
		"base64":              {`multipart/mixed; boundary=b`, part("Content-Type: application/http\nContent-Transfer-Encoding: base64", ok)},
		"absolute URL":        {`multipart/mixed; boundary=b`, part("Content-Type: application/http", "DELETE https://storage.googleapis.com/storage/v1/b/x HTTP/1.1\n\n")},
		"relative target":     {`multipart/mixed; boundary=b`, part("Content-Type: application/http", "DELETE compute/v1/projects/p HTTP/1.1\n\n")},
		"other host":          {`multipart/mixed; boundary=b`, part("Content-Type: application/http", "DELETE /storage/v1/b/x HTTP/1.1\nHost: storage.googleapis.com\n\n")},
		"two hosts":           {`multipart/mixed; boundary=b`, part("Content-Type: application/http", "DELETE /x HTTP/1.1\nHost: compute.googleapis.com\nHost: evil.example\n\n")},
		"nested batch":        {`multipart/mixed; boundary=b`, part("Content-Type: application/http", "POST /batch/compute/v1 HTTP/1.1\nContent-Type: multipart/mixed; boundary=c\n\n--c--")},
		"nested batch dotted": {`multipart/mixed; boundary=b`, part("Content-Type: application/http", "POST /batch/x/../compute/v1 HTTP/1.1\n\n")},
		"bad request line":    {`multipart/mixed; boundary=b`, part("Content-Type: application/http", "DELETE\n\n")},
		"bad version":         {`multipart/mixed; boundary=b`, part("Content-Type: application/http", "DELETE /x SPDY/3\n\n")},
		"bad method":          {`multipart/mixed; boundary=b`, part("Content-Type: application/http", "DEL-ETE /x HTTP/1.1\n\n")},
		"bad header":          {`multipart/mixed; boundary=b`, part("Content-Type: application/http", "DELETE /x HTTP/1.1\nno colon here\n\n")},
		"chunked":             {`multipart/mixed; boundary=b`, part("Content-Type: application/http", "POST /x HTTP/1.1\nTransfer-Encoding: chunked\n\n5\nhello\n0\n")},
		"short length":        {`multipart/mixed; boundary=b`, part("Content-Type: application/http", "POST /x HTTP/1.1\nContent-Length: 2\n\n{}{\"evil\":1}")},
		"long length":         {`multipart/mixed; boundary=b`, part("Content-Type: application/http", "POST /x HTTP/1.1\nContent-Length: 200\n\n{}")},
		"two lengths":         {`multipart/mixed; boundary=b`, part("Content-Type: application/http", "POST /x HTTP/1.1\nContent-Length: 2\nContent-Length: 2\n\n{}")},
		"bad query":           {`multipart/mixed; boundary=b`, part("Content-Type: application/http", "DELETE /x?a=%zz HTTP/1.1\n\n")},
		"no request line":     {`multipart/mixed; boundary=b`, part("Content-Type: application/http", "")},
		"unterminated":        {`multipart/mixed; boundary=b`, "--b\nContent-Type: application/http\n\n" + ok},
		"too many operations": {`multipart/mixed; boundary=b`, many + "--b--\n"},
	}
	for name, tc := range cases {
		r := batchRequest("b", tc.body)
		r.Header.Set("Content-Type", tc.contentType)
		ops := Decode(r, computeBatch)
		if len(ops) != 1 || ops[0].Error == "" || !strings.HasPrefix(ops[0].Error, "batch request: ") {
			t.Errorf("%s: ops = %+v, want one failed operation", name, ops)
		}
	}

	// An inner body Opfence cannot decode fails the body, so rules that
	// read it are unknown, as for a request of its own.
	r := batchRequest("b", part("Content-Type: application/http", "POST /x HTTP/1.1\nContent-Encoding: br\n\n{}"))
	if ops := Decode(r, computeBatch); len(ops) != 1 || ops[0].Error != "" || ops[0].BodyErr == "" {
		t.Errorf("unknown inner coding: %+v", ops)
	}

	// A body too large to read whole is unknown.
	r = batchRequest("b", "")
	r.Body, r.BodyErr = nil, request.ErrBodyTooLarge
	if ops := Decode(r, computeBatch); len(ops) != 1 || ops[0].Error == "" {
		t.Errorf("too large: %+v", ops)
	}
}

func TestBatchOnlyOnBatchPathsAndPOST(t *testing.T) {
	body := apitoolsBatch(apitoolsPart(1, "DELETE", "/compute/v1/projects/p/zones/z/instances/vm", ""))
	r := batchRequest("===============7330845974216740156==", body)
	// Without batch paths the request is a REST POST to /batch/compute/v1,
	// which no rule matches, so it is unknown in the engine.
	if ops := Decode(r, Hints{}); len(ops) != 1 || ops[0].Path != "/batch/compute/v1" || ops[0].Method != "POST" {
		t.Errorf("no hints: %+v", ops)
	}
	r.Method = "GET"
	if ops := Decode(r, computeBatch); len(ops) != 1 || ops[0].Path != "/batch/compute/v1" {
		t.Errorf("GET: %+v", ops)
	}
	r.Method, r.Path = "POST", "/batch/compute/./v1"
	if ops := Decode(r, computeBatch); len(ops) != 1 || ops[0].Path != "/compute/v1/projects/p/zones/z/instances/vm" {
		t.Errorf("dot segment: %+v", ops)
	}
}

func FuzzBatch(f *testing.F) {
	f.Add(apitoolsBatch(apitoolsPart(1, "DELETE", "/compute/v1/projects/p/zones/z/instances/vm", "")))
	f.Add("--b\nContent-Type: application/http\n\nPOST /x HTTP/1.1\nContent-Length: 2\n\n{}\n--b--\n")
	f.Fuzz(func(t *testing.T, body string) {
		r := batchRequest("===============7330845974216740156==", body)
		ops := Decode(r, computeBatch)
		if len(ops) == 0 {
			t.Fatal("no operations")
		}
		for _, op := range ops {
			if op.Error == "" && (op.Protocol != REST || !strings.HasPrefix(op.Path, "/")) {
				t.Fatalf("operation %+v", op)
			}
		}
	})
}
