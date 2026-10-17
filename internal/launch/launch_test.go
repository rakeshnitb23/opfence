package launch

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rakeshnitb23/opfence/internal/catalog"
	"github.com/rakeshnitb23/opfence/internal/secrets"
)

var update = flag.Bool("update", false, "rewrite golden files")

var testPaths = Paths{
	StateDir:   "/home/dev/.local/state/opfence",
	ConfigFile: "/home/dev/.config/opfence/config.yaml",
	CertDir:    "/home/dev/.cache/opfence",
	Executable: "/home/dev/Program Files/opfence",
}

func golden(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *update {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run go test ./internal/launch -update)", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("%s differs from golden file; run go test ./internal/launch -update and review the diff\n%s", name, got)
	}
}

func TestClaudeSettingsGolden(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		o := ClaudeOptions{HTTPPort: 41001, SOCKSPort: 41002, GOOS: goos, Paths: testPaths,
			HookArgs: []string{"--user-config", "/home/dev/it's here/config.yaml"}}
		if goos == "linux" {
			o.DenyRead = []string{"/run/user/1000/bus", "/run/user/1000/keyring"}
		}
		got, err := ClaudeSettings(o)
		if err != nil {
			t.Fatal(err)
		}
		golden(t, "claude-settings-"+goos+".json", got)

		var s struct {
			Sandbox struct {
				Enabled, FailIfUnavailable, AllowUnsandboxedCommands bool
				EnableWeakerNetworkIsolation                         bool
				Network                                              struct{ HTTPProxyPort, SOCKSProxyPort int }
				Filesystem                                           struct{ DenyRead, DenyWrite []string }
			}
			Permissions struct{ Deny []string }
			Hooks       map[string][]struct {
				Matcher string
				Hooks   []struct{ Command, OnFailure string }
			}
		}
		if err := json.Unmarshal(got, &s); err != nil {
			t.Fatal(err)
		}
		sb := s.Sandbox
		if !sb.Enabled || !sb.FailIfUnavailable || sb.AllowUnsandboxedCommands || sb.Network.HTTPProxyPort != 41001 || sb.Network.SOCKSProxyPort != 41002 {
			t.Errorf("%s: sandbox %+v", goos, sb)
		}
		if sb.EnableWeakerNetworkIsolation != (goos == "darwin") {
			t.Errorf("%s: enableWeakerNetworkIsolation %v", goos, sb.EnableWeakerNetworkIsolation)
		}
		if sb.Filesystem.DenyRead[0] != testPaths.StateDir {
			t.Errorf("%s: denyRead %v", goos, sb.Filesystem.DenyRead)
		}
		for _, want := range []string{"/home/dev/.config/opfence", testPaths.StateDir, testPaths.CertDir, testPaths.Executable} {
			if !contains(sb.Filesystem.DenyWrite, want) {
				t.Errorf("%s: denyWrite lacks %s", goos, want)
			}
		}
		for _, want := range []string{"Read(//home/dev/.local/state/opfence/**)", "Edit(//home/dev/.config/opfence/**)", "Edit(//home/dev/Program Files/opfence)"} {
			if !contains(s.Permissions.Deny, want) {
				t.Errorf("%s: permissions.deny lacks %s: %v", goos, want, s.Permissions.Deny)
			}
		}
		h := s.Hooks["PreToolUse"][0]
		if h.Matcher != "^mcp__" || h.Hooks[0].OnFailure != "block" ||
			h.Hooks[0].Command != `'/home/dev/Program Files/opfence' --user-config '/home/dev/it'\''s here/config.yaml' hook claude-code` {
			t.Errorf("%s: hook %+v", goos, h)
		}
	}
}

func TestSrtSettingsGolden(t *testing.T) {
	got, err := SrtSettings(SrtOptions{HTTPPort: 41001, SOCKSPort: 41002, GOOS: "linux", Paths: testPaths,
		DenyRead: []string{"/run/user/1000/bus"}, AllowWrite: []string{"/home/dev/project", "/tmp"}})
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "srt-settings-linux.json", got)
}

// A custom config file outside an opfence folder protects only the file,
// not its folder (which could be the home folder).
func TestCustomConfigProtectsFileOnly(t *testing.T) {
	p := testPaths
	p.ConfigFile = "/home/dev/opfence.yaml"
	got := pathsOf(p.protectedWrites())
	if contains(got, "/home/dev") || !contains(got, "/home/dev/opfence.yaml") {
		t.Fatal(got)
	}
}

func TestShellQuote(t *testing.T) {
	for in, want := range map[string]string{
		"/usr/local/bin/opfence": "/usr/local/bin/opfence",
		"a b":                    "'a b'",
		"it's":                   `'it'\''s'`,
		"$(rm -rf ~)":            "'$(rm -rf ~)'",
		"":                       "''",
	} {
		if got := ShellQuote(in); got != want {
			t.Errorf("ShellQuote(%q) = %s, want %s", in, got, want)
		}
	}
}

func TestLinuxSecretSockets(t *testing.T) {
	rt := t.TempDir()
	for _, f := range []string{"bus", "keyring", "other.sock"} {
		if err := os.WriteFile(filepath.Join(rt, f), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	env := map[string]string{
		"DBUS_SESSION_BUS_ADDRESS": "unix:abstract=/tmp/dbus-x,guid=1;unix:path=" + filepath.Join(rt, "other.sock") + ",guid=2;unix:path=/missing",
		"XDG_RUNTIME_DIR":          rt,
	}
	got := LinuxSecretSockets(func(k string) string { return env[k] })
	want := []string{filepath.Join(rt, "other.sock"), filepath.Join(rt, "bus"), filepath.Join(rt, "keyring")}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestSetEnv(t *testing.T) {
	got := SetEnv([]string{"PATH=/bin", "HTTPS_PROXY=corp", "https_proxy=corp", "A=1"}, map[string]string{"HTTPS_PROXY": "x", "https_proxy": "x"}, false)
	if strings.Join(got, " ") != "PATH=/bin A=1 HTTPS_PROXY=x https_proxy=x" {
		t.Fatal(got)
	}
	got = SetEnv([]string{"Path=C:\\", "https_proxy=corp"}, map[string]string{"HTTPS_PROXY": "x", "https_proxy": "x"}, true)
	if strings.Join(got, " ") != "Path=C:\\ HTTPS_PROXY=x" {
		t.Fatal(got)
	}
}

func TestCAEnv(t *testing.T) {
	env := CAEnv("/c/ca.pem", "/c/ca-bundle.pem")
	if env["NODE_EXTRA_CA_CERTS"] != "/c/ca.pem" || env["SSL_CERT_FILE"] != "/c/ca-bundle.pem" || env["GIT_SSL_CAINFO"] != "/c/ca-bundle.pem" {
		t.Fatal(env)
	}
	if env := CAEnv("/c/ca.pem", ""); len(env) != 1 {
		t.Fatalf("without a bundle only the additive variable is set: %v", env)
	}
}

func TestWriteCAFiles(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "roots.pem")
	root := "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"
	if err := os.WriteFile(base, []byte(root), 0o644); err != nil {
		t.Fatal(err)
	}
	ca := []byte("-----BEGIN CERTIFICATE-----\nBBBB\n-----END CERTIFICATE-----\n")
	f, err := WriteCAFiles(filepath.Join(dir, "out"), ca, base)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(f.Bundle)
	if !bytes.HasPrefix(b, []byte(root[:len(root)-1])) || !bytes.HasSuffix(b, ca) {
		t.Fatalf("bundle:\n%s", b)
	}
	if c, _ := os.ReadFile(f.CA); !bytes.Equal(c, ca) {
		t.Fatal("ca.pem")
	}
	if _, err := WriteCAFiles(dir, ca, filepath.Join(dir, "missing.pem")); err == nil {
		t.Fatal("missing base accepted")
	}
	if f, err := WriteCAFiles(filepath.Join(dir, "nobase"), ca, ""); err != nil || f.Bundle != "" {
		t.Fatal(f, err)
	}
}

func TestVersions(t *testing.T) {
	v, ok := ParseVersion("2.1.301 (Claude Code)\n")
	if !ok || v != [3]int{2, 1, 301} {
		t.Fatal(v, ok)
	}
	if !Older([3]int{2, 1, 284}, MinClaudeVersion) || Older(v, MinClaudeVersion) || Older(MinClaudeVersion, MinClaudeVersion) {
		t.Fatal("Older")
	}
	if _, ok := ParseVersion("claude"); ok {
		t.Fatal("parsed nothing")
	}
}

func TestClaudeSettingsWarnings(t *testing.T) {
	dir := t.TempDir()
	user := filepath.Join(dir, "settings.json")
	managed := filepath.Join(dir, "managed.json")
	os.WriteFile(user, []byte(`{"sandbox":{"excludedCommands":["docker *"]}}`), 0o644)
	os.WriteFile(managed, []byte(`{"sandbox":{"network":{"allowManagedDomainsOnly":true}}}`), 0o644)
	got := ClaudeSettingsWarnings(user, managed)
	if len(got) != 2 || !strings.Contains(got[0], "docker *") || !strings.Contains(got[1], "ignore Opfence's proxy ports") {
		t.Fatal(got)
	}
	if got := ClaudeSettingsWarnings(filepath.Join(dir, "none"), filepath.Join(dir, "none")); len(got) != 0 {
		t.Fatal(got)
	}
}

// Fake tokens are assembled at run time so secret scanners do not flag the
// source.
var (
	vercelTok  = "vcp_AbCdEfGhIjKlMnOpQrStUvWx"
	railwayTok = "4f1c2a7e-9b3d-4c8e-a1f2-0d9e8b7c6a5f"
	githubTok  = "ghp" + "_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789"
	sbpTok     = "sbp" + "_" + strings.Repeat("0123456789abcdef", 3)[:40]
)

func TestProtectEnv(t *testing.T) {
	c, err := catalog.Embedded()
	if err != nil {
		t.Fatal(err)
	}
	stored := []*secrets.Secret{{Provider: "railway", Name: "RAILWAY_TOKEN", Value: railwayTok, Placeholder: "00000000-1111-4222-8333-444444444444"}}
	env := []string{
		"PATH=/bin",
		"MY_RAILWAY=" + railwayTok, // stored value under any name
		"VERCEL_TOKEN=" + vercelTok,
		"OTHER_VERCEL=" + vercelTok, // same key twice: one session secret
		"DATABASE_URL=postgres://x?token=" + sbpTok,
		"GITHUB_TOKEN=" + githubTok,
		"AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE",
		"AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		"RAILWAY_TOKEN=00000000-1111-4222-8333-444444444444", // already a placeholder
	}
	out, session, changes, err := ProtectEnv(env, c, stored)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(out, "\n")
	for _, real := range []string{railwayTok, vercelTok, sbpTok, "AKIAIOSFODNN7EXAMPLE", "bPxRfiCYEXAMPLEKEY"} {
		if strings.Contains(joined, real) {
			t.Errorf("real key %s left in the environment:\n%s", real, joined)
		}
	}
	if !strings.Contains(joined, "MY_RAILWAY=00000000-1111-4222-8333-444444444444") || !strings.Contains(joined, "PATH=/bin") {
		t.Errorf("env:\n%s", joined)
	}
	if !strings.Contains(joined, "GITHUB_TOKEN="+githubTok) || !strings.Contains(joined, "DATABASE_URL=postgres://x?token=sbp_") {
		t.Errorf("env:\n%s", joined)
	}
	if len(session) != 4 {
		t.Fatalf("session secrets: %d", len(session))
	}
	for _, s := range session {
		if len(s.Placeholder) != len(s.Value) || s.Placeholder == s.Value || s.Group != "env" {
			t.Errorf("placeholder %q group %q for %s", s.Placeholder, s.Group, s.Provider)
		}
	}
	var acts []string
	for _, ch := range changes {
		acts = append(acts, ch.Var+":"+ch.Action)
	}
	want := "AWS_ACCESS_KEY_ID:session AWS_SECRET_ACCESS_KEY:session DATABASE_URL:session GITHUB_TOKEN:kept MY_RAILWAY:placeholder OTHER_VERCEL:session VERCEL_TOKEN:session"
	if strings.Join(acts, " ") != want {
		t.Errorf("changes %s\nwant    %s", strings.Join(acts, " "), want)
	}
}

func contains(xs []string, x string) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}
