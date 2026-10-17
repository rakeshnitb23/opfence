package proxy

import (
	"net/http"
	"strings"
	"testing"
)

// Behind a corporate proxy, intercepted requests and tunnels both leave
// through it with its credentials, and a private IP literal is refused
// before the corporate proxy is asked.
func TestUpstreamProxy(t *testing.T) {
	e := newEnv(t, opts{upstream: true, mode: "open"})
	resp, body := post(t, e.client(true), "https://backboard.railway.com/graphql/v2", `{"query":"query { me { id } }"}`)
	if resp.StatusCode != 200 || e.hits.Load() != 1 {
		t.Fatalf("intercepted request: %d %s", resp.StatusCode, body)
	}
	c, code := connect(t, e.httpAddr, "registry.npmjs.org:443")
	if code != 200 || !e.tlsEchoes(c, "registry.npmjs.org") {
		t.Fatalf("tunnel: %d", code)
	}
	c.Close()
	if c, code := connect(t, e.httpAddr, "10.1.2.3:8443"); code != http.StatusForbidden {
		t.Fatalf("private literal: %d", code)
	} else {
		c.Close()
	}
	if c, code := connect(t, e.httpAddr, "refused.example.com:8443"); code != http.StatusForbidden {
		t.Fatalf("upstream refusal: %d", code)
	} else {
		c.Close()
	}

	e.mu.Lock()
	got := strings.Join(e.connects, "\n")
	e.mu.Unlock()
	auth := "Basic Y29ycDpzM2NyZXQ=" // corp:s3cret
	for _, want := range []string{"backboard.railway.com:443 " + auth, "registry.npmjs.org:443 " + auth} {
		if !strings.Contains(got, want) {
			t.Errorf("upstream CONNECTs missing %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "10.1.2.3") {
		t.Error("private literal reached the upstream proxy")
	}
	var reasons []string
	for _, en := range e.entries() {
		reasons = append(reasons, en.Reason)
	}
	if r := strings.Join(reasons, "\n"); !strings.Contains(r, "refused CONNECT refused.example.com:8443: 403 Forbidden") {
		t.Errorf("audit reasons:\n%s", r)
	}
}

func TestUpstreamFromEnvAndBypass(t *testing.T) {
	env := map[string]string{"https_proxy": "corp:s3cret@proxy.corp.example:3128", "NO_PROXY": "localhost, .internal.example,10.0.0.0/8,[::1],intranet:8080,*.svc"}
	up, err := UpstreamFromEnv(func(k string) string { return env[k] })
	if err != nil || up == nil || up.URL.Host != "proxy.corp.example:3128" || up.URL.User.Username() != "corp" {
		t.Fatalf("%+v %v", up, err)
	}
	if Redact(up.URL.String()) != "http://corp:xxxxx@proxy.corp.example:3128" {
		t.Errorf("redact: %s", Redact(up.URL.String()))
	}
	for host, want := range map[string]bool{
		"localhost": true, "a.internal.example": true, "internal.example": true, "10.9.8.7": true, "::1": true,
		"intranet": true, "api.svc": true, "github.com": false, "notinternal.example": false, "11.0.0.1": false,
	} {
		if up.Bypass(host) != want {
			t.Errorf("Bypass(%s) = %v", host, !want)
		}
	}
	if up, err := UpstreamFromEnv(func(string) string { return "" }); up != nil || err != nil {
		t.Errorf("no proxy: %+v %v", up, err)
	}
	if _, err := UpstreamFromEnv(func(k string) string {
		if k == "HTTPS_PROXY" {
			return "socks5://user:pw@h:1080"
		}
		return ""
	}); err == nil || strings.Contains(err.Error(), "pw") {
		t.Errorf("socks: %v", err)
	}
}
