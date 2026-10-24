package proxy

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/rakeshnitb23/opfence/internal/catalog"
	"github.com/rakeshnitb23/opfence/internal/inject"
)

const heldProvider = `provider: heldtest
title: Held values test
docs: https://example.com
hosts: [run.googleapis.com]
auth:
  - header: Authorization
    scheme: Bearer
defaults:
  rest_safe_methods: read
`

const heldRules = `operations:
  - id: heldtest.service.get
    match: { rest: { method: GET, path: "/v2/projects/{project}/locations/{location}/services/{service}" } }
    class: credential
    card: "Read service {service}"
    response: { hold: [template.containers.env.value], class: read }
    status: verified
    verified: 2026-10-23
    sources: [https://example.com]
    tests:
      - { fixture: fixtures/get.http, expect: credential, response: fixtures/get.json }
  - id: heldtest.service.patch
    match: { rest: { method: PATCH, path: "/v2/projects/{project}/locations/{location}/services/{service}" } }
    class: write
    card: "Change service {service}"
    restore: [template.containers.env.value]
    response: { hold: [template.containers.env.value], class: write }
    status: verified
    verified: 2026-10-23
    sources: [https://example.com]
    tests:
      - { fixture: fixtures/patch.http, expect: write, response: fixtures/get.json }
  - id: heldtest.service.create
    match: { rest: { method: POST, path: "/v2/projects/{project}/locations/{location}/services" } }
    class: write
    card: "Create a service"
    status: verified
    verified: 2026-10-23
    sources: [https://example.com]
    tests:
      - { fixture: fixtures/create.http, expect: write }
`

func heldCatalog(t *testing.T) *catalog.Catalog {
	t.Helper()
	svc := `{"name":"api","template":{"containers":[{"image":"img","env":[{"name":"K","value":"v"}]}]}}`
	fs := fstest.MapFS{
		"heldtest/provider.yaml":        {Data: []byte(heldProvider)},
		"heldtest/services.yaml":        {Data: []byte(heldRules)},
		"heldtest/fixtures/get.json":    {Data: []byte(svc)},
		"heldtest/fixtures/get.http":    {Data: []byte("GET /v2/projects/p/locations/l/services/api HTTP/1.1\nHost: run.googleapis.com\n\n")},
		"heldtest/fixtures/patch.http":  {Data: []byte("PATCH /v2/projects/p/locations/l/services/api HTTP/1.1\nHost: run.googleapis.com\n\n" + svc)},
		"heldtest/fixtures/create.http": {Data: []byte("POST /v2/projects/p/locations/l/services HTTP/1.1\nHost: run.googleapis.com\n\n" + svc)},
	}
	c, err := catalog.Load(fs)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// A Cloud Run style read-modify-write: the agent reads a service whose
// environment holds a password, sees tokens instead of the values, changes
// the image and writes the service back; the API receives the real values,
// and the echo comes back with tokens again. A token taken to another
// service, into a new one, or left over from another session is blocked.
func TestHeldValues(t *testing.T) {
	password := "pw-" + strings.Repeat("s3cr3t", 4)
	e := newEnv(t, opts{catalog: heldCatalog(t), respond: func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet {
			io.WriteString(w, `{"name":"api","template":{"containers":[{"image":"img:v1","env":[{"name":"DB_PASSWORD","value":"`+password+`"},{"name":"PORT","value":"8080"}]}]}}`)
			return
		}
		io.Copy(w, r.Body) // echo what was written
	}})
	e.srv.cfg.Approver = &approveAll{}
	c := e.client(true)
	do := func(method, u, body string, gz bool) (int, string) {
		t.Helper()
		var rd io.Reader
		if body != "" {
			rd = strings.NewReader(body)
			if gz {
				var b bytes.Buffer
				zw := gzip.NewWriter(&b)
				zw.Write([]byte(body))
				zw.Close()
				rd = &b
			}
		}
		req, _ := http.NewRequest(method, u, rd)
		req.Header.Set("Content-Type", "application/json")
		if gz {
			req.Header.Set("Content-Encoding", "gzip")
		}
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	const svc = "https://run.googleapis.com/v2/projects/p/locations/l/services/api"

	status, read := do("GET", svc, "", false)
	if status != 200 || strings.Contains(read, password) || strings.Contains(read, "8080") || strings.Count(read, inject.HeldPrefix) != 2 {
		t.Fatalf("read: %d %s", status, read)
	}
	if es := e.entries(); es[len(es)-1].Held != 2 || es[len(es)-1].Operations[0].Class != "read" {
		t.Fatalf("read audited as %+v", es[len(es)-1])
	}

	// Write it back with a new image, plain and gzip-encoded.
	write := strings.Replace(read, "img:v1", "img:v2", 1)
	for _, gz := range []bool{false, true} {
		status, echo := do("PATCH", svc, write, gz)
		if status != 200 || strings.Contains(echo, password) || echo != write {
			t.Fatalf("write (gzip %v): %d %s", gz, status, echo)
		}
		e.mu.Lock()
		got, up := e.bodies[len(e.bodies)-1], e.upstream[len(e.upstream)-1]
		e.mu.Unlock()
		var sent struct {
			Template struct {
				Containers []struct {
					Image string
					Env   []struct{ Name, Value string }
				}
			}
		}
		if err := json.Unmarshal([]byte(got), &sent); err != nil || strings.Contains(got, inject.HeldPrefix) ||
			sent.Template.Containers[0].Image != "img:v2" || sent.Template.Containers[0].Env[0].Value != password || sent.Template.Containers[0].Env[1].Value != "8080" {
			t.Fatalf("the API got %s (%v)", got, err)
		}
		if up.Header.Get("Content-Encoding") != "" || up.ContentLength != int64(len(got)) {
			t.Fatalf("the API got headers %v, length %d for %d bytes", up.Header, up.ContentLength, len(got))
		}
		if es := e.entries(); es[len(es)-1].Restored != 2 || es[len(es)-1].Held != 2 {
			t.Fatalf("write audited as %+v", es[len(es)-1])
		}
	}

	hits := e.hits.Load()
	tok := write[strings.Index(write, inject.HeldPrefix):][:len(inject.HeldPrefix)+26]
	blocked := []struct{ name, method, url, body string }{
		{"another service", "PATCH", "https://run.googleapis.com/v2/projects/p/locations/l/services/public-echo", write},
		{"a new service", "POST", "https://run.googleapis.com/v2/projects/p/locations/l/services", write},
		{"another field", "PATCH", svc, `{"name":"api","description":"` + tok + `"}`},
		{"another session", "PATCH", svc, strings.Replace(write, tok, inject.HeldPrefix+strings.Repeat("a", 26), 1)},
		{"not JSON", "PATCH", svc, "env=" + tok},
	}
	for _, b := range blocked {
		status, body := do(b.method, b.url, b.body, false)
		if status != http.StatusForbidden || !strings.Contains(body, "held") {
			t.Errorf("%s: %d %s", b.name, status, body)
		}
	}
	if e.hits.Load() != hits {
		t.Fatalf("a blocked request reached the API")
	}
}
