package request

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestParseFixture(t *testing.T) {
	data := "# description: Delete a volume\n# captured: 2026-10-16\n\nPOST /graphql/v2?x=1&x=2 HTTP/1.1\nHost: Backboard.Railway.com:443\nContent-Type: application/json; charset=utf-8\nContent-Length: 999\n\n{\"query\":\"{ me { id } }\"}\n"
	r, meta, err := ParseFixture([]byte(data))
	if err != nil {
		t.Fatal(err)
	}
	if meta["description"] != "Delete a volume" || meta["captured"] != "2026-10-16" {
		t.Errorf("meta = %v", meta)
	}
	if r.Method != "POST" || r.Host != "backboard.railway.com" || r.Port != "" || r.Path != "/graphql/v2" {
		t.Errorf("request = %+v", r)
	}
	if got := r.Query["x"]; len(got) != 2 {
		t.Errorf("query = %v", r.Query)
	}
	if string(r.Body) != `{"query":"{ me { id } }"}` || r.BodyErr != nil {
		t.Errorf("body = %q, %v", r.Body, r.BodyErr)
	}
	if r.ContentType() != "application/json" {
		t.Errorf("content type %q", r.ContentType())
	}
	if r.Header.Get("Content-Length") != "" {
		t.Error("Content-Length should be dropped")
	}
}

func TestParseFixtureVariants(t *testing.T) {
	cases := []struct {
		name, data       string
		host, port, path string
		body             string
	}{
		{"crlf", "DELETE /v9/projects/web HTTP/1.1\r\nHost: api.vercel.com\r\n\r\n", "api.vercel.com", "", "/v9/projects/web", ""},
		{"no trailing newline", "GET / HTTP/1.1\nHost: x.example.com", "x.example.com", "", "/", ""},
		{"absolute form", "GET https://API.github.com:8443/repos/a%2Fb?q=1 HTTP/1.1\nHost: ignored.example\n\n", "api.github.com", "8443", "/repos/a%2Fb", ""},
		{"escaped path kept raw", "GET /v1/a%2Fb/c HTTP/1.1\nHost: h.example.com\n\n", "h.example.com", "", "/v1/a%2Fb/c", ""},
		{"multi-line body", "POST /x HTTP/1.1\nHost: h.example.com\n\nline1\nline2\n", "h.example.com", "", "/x", "line1\nline2"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r, _, err := ParseFixture([]byte(c.data))
			if err != nil {
				t.Fatal(err)
			}
			if r.Host != c.host || r.Port != c.port || r.Path != c.path || string(r.Body) != c.body {
				t.Errorf("got host=%q port=%q path=%q body=%q", r.Host, r.Port, r.Path, r.Body)
			}
		})
	}
}

func TestParseFixtureErrors(t *testing.T) {
	for _, data := range []string{"", "# only a comment\n", "NOT A REQUEST\n\n", "GET / HTTP/1.1\n\n", "GET /?a=%zz HTTP/1.1\nHost: h.example.com\n\n"} {
		if _, _, err := ParseFixture([]byte(data)); err == nil {
			t.Errorf("ParseFixture(%q) succeeded", data)
		}
	}
}

func gz(b []byte) []byte {
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	w.Write(b)
	w.Close()
	return buf.Bytes()
}

func TestDecode(t *testing.T) {
	plain := []byte(`{"a":1}`)
	got, err := Decode(gz(plain), "gzip")
	if err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("gzip: %q %v", got, err)
	}
	got, err = Decode(gz(gz(plain)), "gzip, gzip")
	if err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("gzip,gzip: %q %v", got, err)
	}
	var zb bytes.Buffer
	zw := zlib.NewWriter(&zb)
	zw.Write(plain)
	zw.Close()
	got, err = Decode(zb.Bytes(), "deflate")
	if err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("deflate: %q %v", got, err)
	}
	if _, err := Decode(plain, "br"); err == nil {
		t.Error("br accepted")
	}
	if _, err := Decode(plain, "gzip"); err == nil {
		t.Error("garbage gzip accepted")
	}
	bomb := gz(bytes.Repeat([]byte("a"), MaxBody+10))
	if _, err := Decode(bomb, "gzip"); !errors.Is(err, ErrBodyTooLarge) {
		t.Errorf("zip bomb: %v", err)
	}
}

func TestFixtureBodyErrors(t *testing.T) {
	big := "POST /x HTTP/1.1\nHost: h.example.com\n\n" + strings.Repeat("a", MaxBody+1)
	r, _, err := ParseFixture([]byte(big))
	if err != nil || !errors.Is(r.BodyErr, ErrBodyTooLarge) || r.Body != nil {
		t.Errorf("big body: %v %v", err, r.BodyErr)
	}
	br := "POST /x HTTP/1.1\nHost: h.example.com\nContent-Encoding: br\n\nxyz"
	r, _, err = ParseFixture([]byte(br))
	if err != nil || r.BodyErr == nil {
		t.Errorf("br body: %v %v", err, r.BodyErr)
	}
}

func TestFromHTTP(t *testing.T) {
	hr := httptest.NewRequest("POST", "https://api.example.com/a?b=c", bytes.NewReader(gz([]byte("hello"))))
	hr.Header.Set("Content-Encoding", "gzip")
	r, raw, err := FromHTTP(hr)
	if err != nil {
		t.Fatal(err)
	}
	if string(r.Body) != "hello" || len(raw) == 0 || r.Host != "api.example.com" || r.Query.Get("b") != "c" {
		t.Errorf("got %+v raw=%d", r, len(raw))
	}
	big := httptest.NewRequest("POST", "/x", strings.NewReader(strings.Repeat("a", MaxBody+100)))
	big.Host = "api.example.com"
	r, raw, err = FromHTTP(big)
	if err != nil || !errors.Is(r.BodyErr, ErrBodyTooLarge) || len(raw) != MaxBody+1 {
		t.Errorf("big: %v %v raw=%d", err, r.BodyErr, len(raw))
	}
}

func TestSplitHostPort(t *testing.T) {
	cases := map[string][2]string{
		"API.Example.com":      {"api.example.com", ""},
		"api.example.com:443":  {"api.example.com", ""},
		"api.example.com:8443": {"api.example.com", "8443"},
		"api.example.com.":     {"api.example.com", ""},
		"[::1]:443":            {"::1", ""},
		"[::1]":                {"::1", ""},
	}
	for in, want := range cases {
		h, p := SplitHostPort(in)
		if h != want[0] || p != want[1] {
			t.Errorf("SplitHostPort(%q) = %q, %q", in, h, p)
		}
	}
}

func FuzzParseFixture(f *testing.F) {
	f.Add([]byte("POST /graphql HTTP/1.1\nHost: h.example.com\n\n{}"))
	f.Add([]byte("# a: b\nGET https://h.example.com/x?y=z HTTP/1.1\r\n\r\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		r, _, err := ParseFixture(data)
		if err != nil {
			return
		}
		if r.Host == "" || !strings.HasPrefix(r.Path, "/") {
			t.Fatalf("accepted request without host or absolute path: %+v", r)
		}
		if r.BodyErr == nil && len(r.Body) > MaxBody {
			t.Fatal("body over limit without BodyErr")
		}
	})
}

func TestNormalizePath(t *testing.T) {
	cases := map[string]string{
		"/":           "",
		"//a///b/":    "a/b",
		"/a/./b/../c": "a/c",
		"/a/%2e%2e/b": "b",
		"/a%2Fb/c":    "a%2Fb/c",
	}
	for in, want := range cases {
		segs, ok := NormalizePath(in)
		if !ok || strings.Join(segs, "/") != want {
			t.Errorf("NormalizePath(%q) = %v, %v; want %q", in, segs, ok, want)
		}
	}
	for _, bad := range []string{"a/b", "/..", "/a/../../b", "/%zz"} {
		if _, ok := NormalizePath(bad); ok {
			t.Errorf("NormalizePath(%q) accepted", bad)
		}
	}
}
