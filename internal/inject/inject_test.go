package inject

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/rakeshnitb23/opfence/internal/catalog"
	"github.com/rakeshnitb23/opfence/internal/secrets"
)

var (
	railway = &secrets.Secret{Provider: "railway", Name: "RAILWAY_TOKEN", Value: "4f1c2a7e-9b3d-4c8e-a1f2-0d9e8b7c6a5f", Placeholder: "0a9b8c7d-6e5f-4a3b-b2c1-d0e9f8a7b6c5"}
	vercel  = &secrets.Secret{Provider: "vercel", Name: "VERCEL_TOKEN", Value: "vcp_AbCdEfGhIjKlMnOpQrStUvWx", Placeholder: "vcp_ZyXwVuTsRqPoNmLkJiHgFeDc"}
	set     = secrets.NewSet([]*secrets.Secret{railway, vercel})
)

func provider(id string, auth ...catalog.Auth) *catalog.Provider {
	return &catalog.Provider{ID: id, Auth: auth}
}

func TestInjectOnlyForItsProvider(t *testing.T) {
	rw := provider("railway", catalog.Auth{Header: "Authorization", Scheme: "Bearer"}, catalog.Auth{Header: "Project-Access-Token"})
	h := http.Header{}
	h.Set("Authorization", "bearer "+railway.Placeholder)
	h.Set("Project-Access-Token", railway.Placeholder)
	h.Set("X-Other", railway.Placeholder)
	_, res := Request(rw, h, "", set)
	if h.Get("Authorization") != "bearer "+railway.Value || h.Get("Project-Access-Token") != railway.Value {
		t.Fatalf("not injected: %v", h)
	}
	if h.Get("X-Other") != railway.Placeholder {
		t.Fatal("injected outside a declared auth location")
	}
	if len(res.Injected) != 2 || len(res.Foreign) != 0 {
		t.Fatalf("%+v", res)
	}

	// Railway's placeholder sent to Vercel stays a placeholder.
	vc := provider("vercel", catalog.Auth{Header: "Authorization", Scheme: "Bearer"})
	h = http.Header{"Authorization": {"Bearer " + railway.Placeholder}}
	_, res = Request(vc, h, "", set)
	if h.Get("Authorization") != "Bearer "+railway.Placeholder || len(res.Foreign) != 1 || len(res.Injected) != 0 {
		t.Fatalf("foreign placeholder: %v %+v", h, res)
	}
	// A scheme mismatch is left alone.
	h = http.Header{"Authorization": {"Token " + vercel.Placeholder}}
	if Request(vc, h, "", set); h.Get("Authorization") != "Token "+vercel.Placeholder {
		t.Fatal("injected under the wrong scheme")
	}
	// No scheme declared: the last word is the token (GitHub's "token x").
	gh := provider("vercel", catalog.Auth{Header: "Authorization"})
	h = http.Header{"Authorization": {"token " + vercel.Placeholder}}
	if Request(gh, h, "", set); h.Get("Authorization") != "token "+vercel.Value {
		t.Fatalf("schemeless: %v", h)
	}
	// "<id>:<token>" (PlanetScale service tokens): the token part is swapped.
	h = http.Header{"Authorization": {"k3m9x2p7q1w8:" + vercel.Placeholder}}
	if _, res := Request(gh, h, "", set); h.Get("Authorization") != "k3m9x2p7q1w8:"+vercel.Value || len(res.Injected) != 1 {
		t.Fatalf("id:token: %v %+v", h, res)
	}
	// ... but never another provider's.
	h = http.Header{"Authorization": {"k3m9x2p7q1w8:" + railway.Placeholder}}
	if _, res := Request(gh, h, "", set); h.Get("Authorization") != "k3m9x2p7q1w8:"+railway.Placeholder || len(res.Foreign) != 1 {
		t.Fatalf("foreign id:token: %v %+v", h, res)
	}
}

func TestInjectQueryAndBasic(t *testing.T) {
	p := provider("vercel", catalog.Auth{Query: "access_token"}, catalog.Auth{Basic: "password"})
	q, res := Request(p, http.Header{}, "a=1&access_token="+vercel.Placeholder+"&b=%2F", set)
	if q != "a=1&access_token="+vercel.Value+"&b=%2F" || len(res.Injected) != 1 {
		t.Fatalf("query %q", q)
	}
	h := http.Header{"Authorization": {"Basic " + base64.StdEncoding.EncodeToString([]byte("x:"+vercel.Placeholder))}}
	Request(p, h, "", set)
	if h.Get("Authorization") != "Basic "+base64.StdEncoding.EncodeToString([]byte("x:"+vercel.Value)) {
		t.Fatalf("basic %v", h)
	}
}

func TestScrubAcrossReads(t *testing.T) {
	s := NewScrubber(set)
	body := strings.Repeat("x", 40000) + railway.Value + "," + vercel.Value + strings.Repeat("y", 100) + railway.Value
	for name, r := range map[string]io.Reader{
		"one byte at a time": iotest.OneByteReader(strings.NewReader(body)),
		"half reads":         iotest.HalfReader(strings.NewReader(body)),
		"whole":              strings.NewReader(body),
	} {
		out, err := io.ReadAll(s.Reader(io.NopCloser(r), nil))
		if err != nil {
			t.Fatal(err)
		}
		want := strings.Repeat("x", 40000) + railway.Placeholder + "," + vercel.Placeholder + strings.Repeat("y", 100) + railway.Placeholder
		if string(out) != want {
			t.Fatalf("%s: secret survived or bytes changed", name)
		}
	}
	h := http.Header{"X-Token": {"a " + vercel.Value}}
	s.Header(h)
	if h.Get("X-Token") != "a "+vercel.Placeholder {
		t.Fatal("header not scrubbed")
	}
	if NewScrubber(secrets.NewSet(nil)) != nil {
		t.Fatal("scrubber with nothing to do")
	}
}

// A key echoed back encoded is scrubbed too: base64 at any alignment (an
// echoed Basic header, a base64 file body) and URL-encoded.
func TestScrubEncodedForms(t *testing.T) {
	s := NewScrubber(set)
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.URLEncoding} {
		for _, prefix := range []string{"", "x:", "ab:"} {
			body := `{"auth":"` + enc.EncodeToString([]byte(prefix+vercel.Value+"\n")) + `"}`
			var eof bool
			out, err := io.ReadAll(s.Reader(io.NopCloser(strings.NewReader(body)), func() { eof = true }))
			if err != nil || !eof {
				t.Fatal(err, eof)
			}
			var got struct{ Auth string }
			if err := json.Unmarshal(out, &got); err != nil {
				t.Fatal(err)
			}
			dec, err := enc.DecodeString(got.Auth)
			// Up to two bytes at each end share base64 characters with what
			// surrounds them, so they cannot be matched; the rest is replaced.
			v := vercel.Value
			if err != nil || len(dec) != len(prefix+v+"\n") || strings.Contains(string(dec), v[2:len(v)-2]) {
				t.Errorf("prefix %q: decoded %q (%v)", prefix, dec, err)
			}
		}
	}
	// A secret with characters URL encoding changes, and a placeholder with
	// the same characters in the same places.
	value := "wJalrXUtnFEMI/K7MDENG/" + "bPxRfiCYEXAMPLEKEY"
	ph := strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' {
			return 'a' + ('z'-r+1)%26
		}
		return r
	}, value)
	aws := NewScrubber(secrets.NewSet([]*secrets.Secret{{Provider: "aws", Name: "AWS_SECRET_ACCESS_KEY", Value: value, Placeholder: ph}}))
	h := http.Header{"Location": {"https://x.example/?t=" + url.QueryEscape(value)}}
	aws.Header(h)
	if h.Get("Location") != "https://x.example/?t="+url.QueryEscape(ph) {
		t.Errorf("URL-encoded key not scrubbed: %v", h)
	}
}

func TestScrubKeepsReadErrors(t *testing.T) {
	boom := errors.New("boom")
	r := NewScrubber(set).Reader(io.NopCloser(io.MultiReader(strings.NewReader(railway.Value), iotest.ErrReader(boom))), nil)
	out, err := io.ReadAll(r)
	if !errors.Is(err, boom) || !bytes.Equal(out, []byte(railway.Placeholder)) {
		t.Fatalf("%q %v", out, err)
	}
}

func TestTransform(t *testing.T) {
	x := &catalog.Response{Redact: []string{"password", "build.env"}, Mint: []string{"token"}}
	body := `[{"name":"a","password":"hunter2hunter2","build":{"env":{"K":"v1","N":{"deep":"v2"},"Z":3}},"token":"tok-0123456789abcdef"},` +
		`{"name":"b","password":"","token":null}]`
	var minted []string
	out, res, err := Transform([]byte(body), x, func(v string) (string, error) {
		minted = append(minted, v)
		return "ph-" + v[4:], nil
	})
	if err != nil {
		t.Fatal(err)
	}
	want := `[{"build":{"env":{"K":"[redacted by opfence]","N":{"deep":"[redacted by opfence]"},"Z":3}},"name":"a","password":"[redacted by opfence]","token":"ph-0123456789abcdef"},` +
		`{"name":"b","password":"","token":null}]`
	if string(out) != want {
		t.Fatalf("got  %s\nwant %s", out, want)
	}
	if res.Hits["password"] != 2 || res.Hits["build.env"] != 1 || res.Hits["token"] != 1 || len(res.Minted) != 1 || len(minted) != 1 {
		t.Fatalf("result %+v, minted %v", res, minted)
	}

	// Numbers keep their exact text, and HTML stays unescaped.
	out, _, err = Transform([]byte(`{"n":12345678901234567890,"html":"<a>&","password":"x"}`), x, nil)
	if err != nil || string(out) != `{"html":"<a>&","n":12345678901234567890,"password":"[redacted by opfence]"}` {
		t.Fatalf("%s %v", out, err)
	}

	for _, bad := range []string{"", "<html>", `{"a":1} {"b":2}`, `{"a":`} {
		if _, _, err := Transform([]byte(bad), x, nil); err == nil {
			t.Errorf("%q: no error", bad)
		}
	}
	// clear empties a value of any shape, keeping its type; numbers stay.
	cx := &catalog.Response{Clear: []string{"projects.protectionBypass", "projects.list", "projects.secret", "projects.n"}}
	out, res, err = Transform([]byte(`{"projects":[{"protectionBypass":{"bypass-secret-0123456789":{"scope":"automation-bypass"}},"list":["a"],"secret":"s","n":7,"name":"web"},{"name":"api"}]}`), cx, nil)
	if err != nil || string(out) != `{"projects":[{"list":[],"n":7,"name":"web","protectionBypass":{},"secret":""},{"name":"api"}]}` {
		t.Fatalf("clear: %s %v", out, err)
	}
	if res.Hits["projects.protectionBypass"] != 1 {
		t.Fatalf("clear hits %v", res.Hits)
	}

	boom := errors.New("boom")
	if _, _, err := Transform([]byte(`{"token":"tok-0123456789abcdef"}`), x, func(string) (string, error) { return "", boom }); !errors.Is(err, boom) {
		t.Fatalf("mint error: %v", err)
	}
}

// Secrets added while responses stream are scrubbed from responses read
// after, and AddSecret is safe alongside readers.
func TestScrubberAddSecret(t *testing.T) {
	var s Scrubber
	if s.Active() {
		t.Fatal("zero scrubber is active")
	}
	value := "abc" + strings.Repeat("Z9", 10)
	sec := &secrets.Secret{Provider: "x", Name: "minted", Value: value, Placeholder: strings.Repeat("p", len(value))}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for range 100 {
			_, _ = io.ReadAll(s.Reader(io.NopCloser(strings.NewReader(value)), nil))
		}
	}()
	s.AddSecret(sec)
	<-done
	got, _ := io.ReadAll(s.Reader(io.NopCloser(strings.NewReader("a "+value+" b")), nil))
	if !s.Active() || string(got) != "a "+sec.Placeholder+" b" {
		t.Fatalf("scrubbed %q", got)
	}
	h := http.Header{"X": {value}}
	s.Header(h)
	if h.Get("X") != sec.Placeholder {
		t.Fatalf("header %q", h.Get("X"))
	}
}

// A provider that lists another in secrets_from takes its secrets too, and
// still no one else's.
func TestInjectSecretsFrom(t *testing.T) {
	mcp := provider("railway-mcp", catalog.Auth{Header: "Authorization", Scheme: "Bearer"})
	mcp.SecretsFrom = []string{"railway"}
	h := http.Header{"Authorization": {"Bearer " + railway.Placeholder}}
	_, res := Request(mcp, h, "", set)
	if h.Get("Authorization") != "Bearer "+railway.Value || len(res.Injected) != 1 || res.Injected[0] != "railway/RAILWAY_TOKEN" {
		t.Fatalf("shared secret not injected: %v %+v", h, res)
	}
	h = http.Header{"Authorization": {"Bearer " + vercel.Placeholder}}
	if _, res := Request(mcp, h, "", set); h.Get("Authorization") != "Bearer "+vercel.Placeholder || len(res.Foreign) != 1 {
		t.Fatalf("another provider's secret injected: %v %+v", h, res)
	}
	// The listing is one way: railway does not take railway-mcp's secrets.
	own := &secrets.Secret{Provider: "railway-mcp", Name: "X", Value: "5e2d3b8f-0c4a-4d9e-b2f3-1e0f9c8d7b6a", Placeholder: "1b0c9d8e-7f6a-4b5c-c3d2-e1f0a9b8c7d6"}
	rw := provider("railway", catalog.Auth{Header: "Authorization", Scheme: "Bearer"})
	h = http.Header{"Authorization": {"Bearer " + own.Placeholder}}
	if _, res := Request(rw, h, "", secrets.NewSet([]*secrets.Secret{railway, own})); len(res.Foreign) != 1 {
		t.Fatalf("one-way listing used both ways: %+v", res)
	}
}

// Supabase's personal access token serves both the Management API and the
// hosted MCP server. Keys init stores now belong to supabase; keys stored
// for supabase-mcp before the supabase provider existed keep working on both.
// The values are not shaped like real tokens (sbp_ and 40 hex digits), so
// secret scanners do not flag them.
func TestInjectSupabaseSharedToken(t *testing.T) {
	c, err := catalog.Embedded()
	if err != nil {
		t.Fatal(err)
	}
	current := &secrets.Secret{Provider: "supabase", Name: "SUPABASE_ACCESS_TOKEN", Value: "sbp_EXAMPLE-not-a-real-token-current-0000", Placeholder: "sbp_EXAMPLE-not-a-real-token-current-pppp"}
	older := &secrets.Secret{Provider: "supabase-mcp", Name: "SUPABASE_ACCESS_TOKEN", Value: "sbp_EXAMPLE-not-a-real-token-older-000000", Placeholder: "sbp_EXAMPLE-not-a-real-token-older-pppppp"}
	s := secrets.NewSet([]*secrets.Secret{current, older, railway})
	for _, host := range []string{"api.supabase.com", "mcp.supabase.com"} {
		p := c.ProviderForHost(host)
		if p == nil {
			t.Fatalf("no provider for %s", host)
		}
		for _, sec := range []*secrets.Secret{current, older} {
			h := http.Header{"Authorization": {"Bearer " + sec.Placeholder}}
			if _, res := Request(p, h, "", s); h.Get("Authorization") != "Bearer "+sec.Value || len(res.Injected) != 1 {
				t.Errorf("%s: %s's key not injected: %+v", host, sec.Provider, res)
			}
		}
		h := http.Header{"Authorization": {"Bearer " + railway.Placeholder}}
		if _, res := Request(p, h, "", s); len(res.Foreign) != 1 {
			t.Errorf("%s: another provider's key injected: %+v", host, res)
		}
	}
}
