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
