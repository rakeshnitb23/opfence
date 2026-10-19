package proxy

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/rakeshnitb23/opfence/internal/catalog"
)

// Reads whose responses carry secrets are allowed once the proxy removes
// them: Netlify's site object loses its visitor password and environment
// values, and an Atlas access token is held by Opfence, with the agent given
// a placeholder that works on later Atlas calls.
func TestResponseTransforms(t *testing.T) {
	// Assembled here so no token-shaped literal sits in the source.
	token := "eyJhbGciOiJSUzI1NiJ9." + "eyJzdWIiOiJ0ZXN0In0." + strings.Repeat("Qx7", 14)
	visitor := "visitor-" + strings.Repeat("pw", 8)
	envValue := "sk_" + strings.Repeat("live", 6)
	e := newEnv(t, opts{respond: func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		var body string
		status := http.StatusOK
		switch {
		case r.URL.Path == "/api/oauth/token":
			body = fmt.Sprintf(`{"access_token":%q,"expires_in":3600,"token_type":"Bearer"}`, token)
		case r.URL.Path == "/api/atlas/v2/groups":
			body = fmt.Sprintf(`{"auth":%q}`, r.Header.Get("Authorization"))
		case strings.HasSuffix(r.URL.Path, "/html"):
			w.Header().Set("Content-Type", "text/html")
			body = "<html>" + visitor + "</html>"
		case strings.HasSuffix(r.URL.Path, "/missing"):
			w.Header().Set("Content-Type", "text/html")
			status = http.StatusNotFound
			body = "<html>not found</html>"
		default:
			body = fmt.Sprintf(`{"id":"site-1","name":"acme","password":%q,"build_settings":{"repo_path":"acme/web","env":{"STRIPE_KEY":%q}},"default_hooks_data":{"access_token":%q}}`, visitor, envValue, token)
		}
		if strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			w.Header().Set("Content-Encoding", "gzip")
			w.WriteHeader(status)
			zw := gzip.NewWriter(w)
			_, _ = zw.Write([]byte(body))
			_ = zw.Close()
			return
		}
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}})
	c := e.client(true)
	do := func(method, u, auth string) (*http.Response, string) {
		t.Helper()
		req, _ := http.NewRequest(method, u, nil)
		req.Header.Set("Authorization", auth)
		req.Header.Set("Accept-Encoding", "gzip") // the client does not decode
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp, string(b)
	}

	// A Netlify site read is allowed in production with the secrets gone.
	resp, body := do("GET", "https://api.netlify.com/api/v1/sites/site-1", "Bearer x")
	if resp.StatusCode != 200 || strings.Contains(body, visitor) || strings.Contains(body, envValue) || strings.Contains(body, token) ||
		!strings.Contains(body, `"repo_path":"acme/web"`) || !strings.Contains(body, catalog.RedactedValue) {
		t.Fatalf("site read: %d %s", resp.StatusCode, body)
	}
	if resp.Header.Get("Content-Encoding") != "" || resp.Header.Get("Content-Length") != strconv.Itoa(len(body)) {
		t.Fatalf("site read headers %v for %d bytes", resp.Header, len(body))
	}
	var site map[string]any
	if err := json.Unmarshal([]byte(body), &site); err != nil {
		t.Fatalf("site read is not JSON: %v", err)
	}
	if es := e.entries(); es[len(es)-1].Operations[0].Class != "read" {
		t.Fatalf("site read audited as %+v", es[len(es)-1])
	}

	// A successful response that cannot be transformed is withheld, while
	// an error page passes.
	if resp, body := do("GET", "https://api.netlify.com/api/v1/sites/html", "Bearer x"); resp.StatusCode != http.StatusBadGateway ||
		strings.Contains(body, visitor) || !strings.Contains(body, "withheld") {
		t.Fatalf("html site read: %d %s", resp.StatusCode, body)
	}
	if resp, body := do("GET", "https://api.netlify.com/api/v1/sites/missing", "Bearer x"); resp.StatusCode != http.StatusNotFound || body != "<html>not found</html>" {
		t.Fatalf("404: %d %s", resp.StatusCode, body)
	}

	// The Atlas token exchange hands out a placeholder.
	resp, body = do("POST", "https://cloud.mongodb.com/api/oauth/token", "Basic eDp5")
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal([]byte(body), &tok); err != nil || resp.StatusCode != 200 {
		t.Fatalf("token exchange: %d %s", resp.StatusCode, body)
	}
	if tok.AccessToken == token || len(tok.AccessToken) != len(token) || strings.Contains(body, token) {
		t.Fatalf("token exchange leaked the token: %s", body)
	}
	es := e.entries()
	minted := es[len(es)-1].Minted
	if len(minted) != 1 || !strings.HasPrefix(minted[0], "mongodb-atlas/minted/mongodb-atlas.oauth-token.create/") {
		t.Fatalf("minted %v", minted)
	}

	// The placeholder works on Atlas, and the real token echoed back is
	// scrubbed.
	resp, body = do("GET", "https://cloud.mongodb.com/api/atlas/v2/groups", "Bearer "+tok.AccessToken)
	e.mu.Lock()
	upstreamAuth := e.upstream[len(e.upstream)-1].Header.Get("Authorization")
	e.mu.Unlock()
	if upstreamAuth != "Bearer "+token {
		t.Fatalf("upstream got %q", upstreamAuth)
	}
	if resp.StatusCode != 200 || strings.Contains(body, token) || !strings.Contains(body, tok.AccessToken) {
		t.Fatalf("echo: %d %s", resp.StatusCode, body)
	}

	// It is not swapped in for another provider.
	_, _ = do("GET", "https://api.netlify.com/api/v1/sites/site-1", "Bearer "+tok.AccessToken)
	e.mu.Lock()
	upstreamAuth = e.upstream[len(e.upstream)-1].Header.Get("Authorization")
	e.mu.Unlock()
	if upstreamAuth != "Bearer "+tok.AccessToken {
		t.Fatalf("Netlify got %q", upstreamAuth)
	}

	data, _ := os.ReadFile(e.auditPath)
	if bytes.Contains(data, []byte(token)) || bytes.Contains(data, []byte(visitor)) {
		t.Fatal("secret value in the audit log")
	}
}
