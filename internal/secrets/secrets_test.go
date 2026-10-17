package secrets

import (
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/rakeshnitb23/opfence/internal/catalog"
)

func TestPlaceholderShape(t *testing.T) {
	cases := []struct {
		value, keep string
		alphabet    *regexp.Regexp
	}{
		{"ghp" + "_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789", "ghp_", regexp.MustCompile(`^ghp_[A-Za-z0-9]{36}$`)},
		{"sbp" + "_" + strings.Repeat("0123456789abcdef", 3)[:40], "sbp_", regexp.MustCompile(`^sbp_[0-9a-f]{40}$`)},
		{"4f1c2a7e-9b3d-4c8e-a1f2-0d9e8b7c6a5f", "", regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)},
		{"github_pat_11ABCDEFG0123456789_abcdefghijklmnopqrstuvwxyz", "github_pat_", regexp.MustCompile(`^github_pat_[A-Za-z0-9]{19}_[A-Za-z0-9]{26}$`)},
	}
	for _, tc := range cases {
		p, err := NewPlaceholder(tc.value, []string{"ghp_", "sbp_", "github_pat_", "gh"})
		if err != nil {
			t.Fatal(err)
		}
		if len(p) != len(tc.value) || !strings.HasPrefix(p, tc.keep) || !tc.alphabet.MatchString(p) || p == tc.value {
			t.Errorf("%s -> %s", tc.value, p)
		}
	}
	if _, err := NewPlaceholder("short", nil); err == nil {
		t.Error("short value accepted")
	}
}

func TestPlaceholderJWT(t *testing.T) {
	head := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	body := base64.RawURLEncoding.EncodeToString([]byte(`{"role":"service_role","ref":"abc"}`))
	jwt := head + "." + body + ".dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	p, err := NewPlaceholder(jwt, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(p, head+"."+body+".") || len(p) != len(jwt) || p == jwt {
		t.Fatalf("jwt placeholder %s", p)
	}
}

func testCatalog(t *testing.T) *catalog.Catalog {
	t.Helper()
	c, err := catalog.Embedded()
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// Fake tokens are assembled at run time so secret scanners do not flag the
// source.
var (
	railwayTok = "4f1c2a7e-9b3d-4c8e-a1f2-0d9e8b7c6a5f"
	vercelTok  = "vcp_AbCdEfGhIjKlMnOpQrStUvWx"
	githubTok  = "ghp" + "_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789"
	sbpTok     = "sbp" + "_" + strings.Repeat("0123456789abcdef", 3)[:40]
	sbpRemote  = "sbp" + "_" + strings.Repeat("fedcba9876543210", 3)[:40]
)

var sampleRepo = map[string]string{
	".env": "# Railway\nRAILWAY_TOKEN=" + railwayTok + "\r\nexport VERCEL_TOKEN=\"" + vercelTok + "\"  # deploys\n" +
		"GITHUB_TOKEN='" + githubTok + "'\nAWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nRAILWAY_API_TOKEN=x\nOTHER=${RAILWAY_TOKEN}\n" +
		"NOTE=value with " + sbpTok + " inside\nGH_TOKEN=\"ghp_escaped\\n0123456789abcdef0123\"\n",
	".env.example":        "RAILWAY_TOKEN=" + railwayTok + "\n",
	"apps/web/.env.local": "VERCEL_TOKEN=" + vercelTok + "\n",
	"node_modules/x/.env": "VERCEL_TOKEN=" + vercelTok + "\n",
	".mcp.json": `{
  "mcpServers": {
    "supabase": {
      "command": "npx",
      "args": ["-y", "@supabase/mcp-server-supabase", "--access-token", "` + sbpTok + `"],
      "env": {"SUPABASE_ACCESS_TOKEN": "` + sbpTok + `"}
    },
    "supabase-remote": {
      "url": "https://mcp.supabase.com/mcp",
      "headers": {"Authorization": "Bearer ` + sbpRemote + `", "Accept": "application/json, text/event-stream"}
    },
    "railway": {"command": "railway-mcp", "env": {"RAILWAY_API_TOKEN": "${RAILWAY_TOKEN}"}}
  }
}
`,
	".cursor/mcp.json": `{"mcpServers": {"vercel": {"command": "vercel-mcp", "env": {"VERCEL_TOKEN": "` + vercelTok + `"}}}}
`,
}

func writeRepo(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for name, data := range sampleRepo {
		p := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func summary(root string, fs []Finding) string {
	var lines []string
	for _, f := range fs {
		rel, _ := filepath.Rel(root, f.File)
		l := filepath.ToSlash(rel) + " " + f.Where + " " + f.Provider
		if f.Skip != "" {
			l += " SKIP " + f.Skip
		}
		lines = append(lines, l)
	}
	return strings.Join(lines, "\n")
}

func TestInitRoundTrip(t *testing.T) {
	c := testCatalog(t)
	root := writeRepo(t)
	findings, err := Discover(root, c, nil)
	if err != nil {
		t.Fatal(err)
	}
	got := summary(root, findings)
	for _, want := range []string{
		".env RAILWAY_TOKEN railway",
		".env VERCEL_TOKEN vercel",
		".env GITHUB_TOKEN github",
		".env AWS_ACCESS_KEY_ID aws SKIP AWS keys stay",
		".env RAILWAY_API_TOKEN railway SKIP too short",
		".env NOTE supabase-mcp",
		".env GH_TOKEN github SKIP the value uses escape sequences",
		"apps/web/.env.local VERCEL_TOKEN vercel",
		".mcp.json mcpServers.supabase.args.3 supabase-mcp\n",
		".mcp.json mcpServers.supabase.env.SUPABASE_ACCESS_TOKEN supabase-mcp\n",
		".mcp.json mcpServers.supabase-remote.headers.Authorization supabase-mcp\n",
		".cursor/mcp.json mcpServers.vercel.env.VERCEL_TOKEN vercel SKIP this editor's MCP servers are not started by opfence run",
		".mcp.json mcpServers.railway.env.RAILWAY_API_TOKEN railway SKIP a reference",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	for _, unwanted := range []string{".env.example", "node_modules", "OTHER", "Accept"} {
		if strings.Contains(got, unwanted) {
			t.Errorf("unexpected %q in:\n%s", unwanted, got)
		}
	}

	v := &Vault{Store: &Memory{}}
	changed, err := Apply(findings, c, v)
	if err != nil {
		t.Fatal(err)
	}
	if len(changed) != 3 {
		t.Fatalf("changed %v", changed)
	}
	secrets, err := v.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(secrets) != 5 {
		for _, s := range secrets {
			t.Log(s.Account(), s.Sources)
		}
		t.Fatalf("%d secrets", len(secrets))
	}
	if data, _ := os.ReadFile(filepath.Join(root, ".cursor", "mcp.json")); string(data) != sampleRepo[".cursor/mcp.json"] {
		t.Error(".cursor/mcp.json changed")
	}
	for name, orig := range sampleRepo {
		data, _ := os.ReadFile(filepath.Join(root, filepath.FromSlash(name)))
		if len(data) != len(orig) {
			t.Errorf("%s changed length", name)
		}
		for _, tok := range []string{railwayTok, vercelTok, githubTok, sbpTok, sbpRemote} {
			moved := name != ".env.example" && name != "node_modules/x/.env" && name != ".cursor/mcp.json"
			if moved && strings.Contains(string(data), tok) {
				t.Errorf("%s still holds %s", name, tok)
			}
		}
	}
	env, _ := os.ReadFile(filepath.Join(root, ".env"))
	for _, keep := range []string{"# Railway\n", "\r\n", "  # deploys\n", "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n", "OTHER=${RAILWAY_TOKEN}\n", "export VERCEL_TOKEN=\"vcp_", "GITHUB_TOKEN='ghp_"} {
		if !strings.Contains(string(env), keep) {
			t.Errorf(".env lost %q:\n%s", keep, env)
		}
	}

	// A second run finds only placeholders and changes nothing.
	set := NewSet(secrets)
	again, err := Discover(root, c, set)
	if err != nil {
		t.Fatal(err)
	}
	if changed, err := Apply(again, c, v); err != nil || len(changed) != 0 {
		t.Fatalf("second run changed %v (%v)", changed, err)
	}
	if !strings.Contains(summary(root, again), ".env RAILWAY_TOKEN railway SKIP already an Opfence placeholder") {
		t.Fatalf("second run:\n%s", summary(root, again))
	}

	// Undo restores every file byte for byte.
	if _, err := Undo(secrets); err != nil {
		t.Fatal(err)
	}
	for name, orig := range sampleRepo {
		data, _ := os.ReadFile(filepath.Join(root, filepath.FromSlash(name)))
		if string(data) != orig {
			t.Errorf("%s not restored:\n%s", name, data)
		}
	}
}

type failingStore struct{ Memory }

func (*failingStore) Set(string, string) error { return errors.New("keychain locked") }

func TestApplyLeavesFilesAloneWhenTheStoreFails(t *testing.T) {
	c := testCatalog(t)
	root := writeRepo(t)
	findings, err := Discover(root, c, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Apply(findings, c, &Vault{Store: &failingStore{}}); err == nil {
		t.Fatal("no error")
	}
	for name, orig := range sampleRepo {
		if data, _ := os.ReadFile(filepath.Join(root, filepath.FromSlash(name))); string(data) != orig {
			t.Errorf("%s changed although the store failed", name)
		}
	}
}

func TestVault(t *testing.T) {
	v := &Vault{Store: &Memory{}}
	s := &Secret{Provider: "railway", Name: "RAILWAY_TOKEN", Value: railwayTok, Placeholder: strings.Repeat("x", len(railwayTok))}
	if err := v.Put(s); err != nil {
		t.Fatal(err)
	}
	if err := v.Put(&Secret{Provider: "railway", Name: "bad", Value: railwayTok, Placeholder: "short"}); err == nil {
		t.Fatal("placeholder of another length accepted")
	}
	list, _ := v.List()
	if len(list) != 1 || list[0].Value != railwayTok {
		t.Fatalf("%+v", list)
	}
	if err := v.Remove("railway", "RAILWAY_TOKEN"); err != nil {
		t.Fatal(err)
	}
	if err := v.Remove("railway", "RAILWAY_TOKEN"); err == nil {
		t.Fatal("removing a missing secret succeeded")
	}
	if list, _ := v.List(); len(list) != 0 {
		t.Fatalf("%+v", list)
	}
	if err := v.SetCA([]byte("cert"), []byte("key")); err != nil {
		t.Fatal(err)
	}
	if c, k, err := v.CA(); err != nil || string(c) != "cert" || string(k) != "key" {
		t.Fatal("CA round trip")
	}
}
