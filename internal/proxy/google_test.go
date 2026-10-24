package proxy

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/rakeshnitb23/opfence/internal/secrets"
)

// The agent holds only placeholders for Google (stage 27d): its refresh
// token is swapped in at the token endpoint, the access token that comes
// back is minted, and the minted placeholder works on every Google API,
// the fallback for googleapis.com and Artifact Registry's Docker protocol
// included.
func TestGoogleTokensStayWithOpfence(t *testing.T) {
	refresh := "1//0g" + strings.Repeat("Rt7-", 20)
	placeholder, err := secrets.NewPlaceholder(refresh, nil)
	if err != nil {
		t.Fatal(err)
	}
	set := secrets.NewSet([]*secrets.Secret{{Provider: "google-oauth", Name: "gcloud dev@acme.dev", Value: refresh, Placeholder: placeholder}})
	access := "ya29.a0" + strings.Repeat("Acc3ss", 12)
	e := newEnv(t, opts{secrets: set, respond: func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Host == "oauth2.googleapis.com" {
			fmt.Fprintf(w, `{"access_token":%q,"expires_in":3599,"token_type":"Bearer","id_token":"eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxIn0.c2ln"}`, access)
			return
		}
		fmt.Fprintf(w, `{"auth":%q}`, r.Header.Get("Authorization"))
	}})
	c := e.client(true)
	upstream := func() *http.Request {
		e.mu.Lock()
		defer e.mu.Unlock()
		return e.upstream[len(e.upstream)-1]
	}
	lastBody := func() string {
		e.mu.Lock()
		defer e.mu.Unlock()
		return e.bodies[len(e.bodies)-1]
	}

	form := url.Values{"grant_type": {"refresh_token"}, "client_id": {"32555940559.apps.googleusercontent.com"},
		"client_secret": {"not-so-secret"}, "refresh_token": {placeholder}}
	resp, body := post(t, c, "https://oauth2.googleapis.com/token", form.Encode(), "Content-Type", "application/x-www-form-urlencoded")
	if resp.StatusCode != 200 {
		t.Fatalf("token: %d %s", resp.StatusCode, body)
	}
	sent, _ := url.ParseQuery(lastBody())
	if sent.Get("refresh_token") != refresh || upstream().ContentLength != int64(len(lastBody())) {
		t.Fatalf("the token endpoint got %q", lastBody())
	}
	var tok struct {
		AccessToken string `json:"access_token"`
		IDToken     string `json:"id_token"`
	}
	if err := json.Unmarshal([]byte(body), &tok); err != nil || tok.AccessToken == access || !strings.HasPrefix(tok.AccessToken, "ya29.") ||
		strings.Contains(body, access) || tok.IDToken == "" {
		t.Fatalf("the agent got %s", body)
	}
	if es := e.entries(); len(es[len(es)-1].Credentials) != 1 || len(es[len(es)-1].Minted) != 1 {
		t.Fatalf("token exchange audited as %+v", es[len(es)-1])
	}

	get := func(u, auth string) (int, string) {
		t.Helper()
		req, _ := http.NewRequest("GET", u, nil)
		req.Header.Set("Authorization", auth)
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	for _, u := range []string{
		"https://storage.googleapis.com/storage/v1/b?project=acme-prod",      // a provider with rules
		"https://aiplatform.googleapis.com/v1/projects/p/locations/l/models", // the googleapis.com fallback
	} {
		status, body := get(u, "Bearer "+tok.AccessToken)
		if status != 200 || upstream().Header.Get("Authorization") != "Bearer "+access || strings.Contains(body, access) {
			t.Errorf("%s: %d, upstream got %q, agent got %s", u, status, upstream().Header.Get("Authorization"), body)
		}
	}
	// Docker signs in to Artifact Registry with the token as a password.
	basic := "Basic " + base64.StdEncoding.EncodeToString([]byte("oauth2accesstoken:"+tok.AccessToken))
	if status, _ := get("https://us-docker.pkg.dev/v2/token?scope=repository:acme-prod/web/orders:push,pull", basic); status != 200 ||
		upstream().Header.Get("Authorization") != "Basic "+base64.StdEncoding.EncodeToString([]byte("oauth2accesstoken:"+access)) {
		t.Errorf("docker sign-in: %d, upstream got %q", status, upstream().Header.Get("Authorization"))
	}
	// A change on an API without rules is unknown: it asks, and with no
	// one to ask it is blocked.
	hits := e.hits.Load()
	if resp, body := post(t, c, "https://aiplatform.googleapis.com/v1/projects/p/locations/l/endpoints/e:deployModel", "{}", "Authorization", "Bearer "+tok.AccessToken); resp.StatusCode != http.StatusForbidden || e.hits.Load() != hits {
		t.Errorf("deployModel: %d %s", resp.StatusCode, body)
	}
}
