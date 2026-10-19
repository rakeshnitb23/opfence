package launch

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestAgentFor(t *testing.T) {
	for cmd, want := range map[string]string{
		"codex": "Codex", "/usr/local/bin/codex": "Codex", "cursor-agent": "Cursor", "agent": "Cursor",
		"gemini": "Gemini CLI", "claude": "", "node": "",
	} {
		a := AgentFor(cmd)
		got := ""
		if a != nil {
			got = a.Name
		}
		if got != want {
			t.Errorf("%s: got %q, want %q", cmd, got, want)
		}
	}
}

func TestAgentArgs(t *testing.T) {
	codex, cursor, gemini := AgentFor("codex"), AgentFor("cursor-agent"), AgentFor("gemini")
	cases := []struct {
		a    *Agent
		args []string
		want []string
	}{
		{codex, []string{"exec", "fix it"}, []string{"-s", "danger-full-access", "-c", "x=1", "exec", "fix it"}},
		{codex, []string{"-s", "read-only"}, []string{"-c", "x=1", "-s", "read-only"}},
		{codex, []string{"--sandbox=workspace-write"}, []string{"-c", "x=1", "--sandbox=workspace-write"}},
		{codex, []string{"--yolo"}, []string{"-c", "x=1", "--yolo"}},
		// A flag after "--" is the agent's prompt, not a flag.
		{codex, []string{"--", "-s"}, []string{"-s", "danger-full-access", "-c", "x=1", "--", "-s"}},
		{cursor, []string{"-p", "hi"}, []string{"--sandbox", "disabled", "-c", "x=1", "-p", "hi"}},
		{cursor, []string{"--sandbox", "enabled"}, []string{"-c", "x=1", "--sandbox", "enabled"}},
		{gemini, []string{"-p", "hi"}, []string{"-c", "x=1", "-p", "hi"}},
	}
	for _, tc := range cases {
		if got := tc.a.Args(tc.args, []string{"-c", "x=1"}); !slices.Equal(got, tc.want) {
			t.Errorf("%s %q: got %q, want %q", tc.a.Name, tc.args, got, tc.want)
		}
	}
}

func TestAgentState(t *testing.T) {
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	codex := AgentFor("codex")
	if got := codex.StateDir("/home/u", env(nil)); got != filepath.Join("/home/u", ".codex") {
		t.Errorf("codex state dir %q", got)
	}
	if got := codex.StateDir("/home/u", env(map[string]string{"CODEX_HOME": "/srv/codex"})); got != "/srv/codex" {
		t.Errorf("CODEX_HOME ignored: %q", got)
	}
	home, cwd := t.TempDir(), t.TempDir()
	deny, watch, err := codex.Guard(home, cwd, env(nil))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{".codex/config.toml", ".codex/hooks.json", ".codex/.env", ".codex/rules"} {
		if !slices.Contains(deny, filepath.Join(home, filepath.FromSlash(f))) {
			t.Errorf("%s not denied: %q", f, deny)
		}
	}
	// The rules folder is created so the sandbox protects a real folder.
	if info, err := os.Stat(filepath.Join(home, ".codex", "rules")); err != nil || !info.IsDir() {
		t.Errorf("rules folder not created: %v", err)
	}
	// No .codex in the project: its files are denied (the sandbox blocks
	// .codex) and nothing is created there.
	if !slices.Contains(deny, filepath.Join(cwd, ".codex", "rules")) || len(watch) != 0 {
		t.Errorf("project paths: deny %q, watch %q", deny, watch)
	}
	if _, err := os.Stat(filepath.Join(cwd, ".codex")); err == nil {
		t.Error(".codex created in the project")
	}

	// Gemini refuses an empty settings.json, so a missing one in an
	// existing folder is watched, not denied; an existing one is denied.
	gemini := AgentFor("gemini")
	if err := os.MkdirAll(filepath.Join(cwd, ".gemini"), 0o755); err != nil {
		t.Fatal(err)
	}
	deny, watch, err = gemini.Guard(home, cwd, env(nil))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(watch, []string{filepath.Join(home, ".gemini", "settings.json"), filepath.Join(cwd, ".gemini", "settings.json")}) || len(deny) != 0 {
		t.Errorf("gemini: deny %q, watch %q", deny, watch)
	}
	if err := os.WriteFile(filepath.Join(home, ".gemini", "settings.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if deny, _, _ = gemini.Guard(home, cwd, env(nil)); !slices.Equal(deny, []string{filepath.Join(home, ".gemini", "settings.json")}) {
		t.Errorf("gemini existing settings: deny %q", deny)
	}
	if e := codex.Env("/c/ca.pem", "/c/bundle.pem"); e["CODEX_CA_CERTIFICATE"] != "/c/ca.pem" {
		t.Errorf("codex env %v", e)
	}
	if e := AgentFor("gemini").Env("/c/ca.pem", ""); len(e) != 0 {
		t.Errorf("gemini env %v", e)
	}
}

// TestCodexHookHash checks the trust hash against the value Codex 0.163.0
// printed for the same hook (app-server hooks/list, currentHash).
func TestCodexHookHash(t *testing.T) {
	got := CodexHookHash("pre_tool_use", "^mcp__", "/usr/local/bin/opfence hook codex")
	if want := "sha256:29a394df5732a0fa129003cc309b512ae557898f9d3561f50c65468f41a28b98"; got != want {
		t.Fatalf("got %s, want %s", got, want)
	}
}

func TestCodexConfig(t *testing.T) {
	servers, err := ParseCodexServers([]byte(`[
		{"name": "supabase", "enabled": true, "transport": {"type": "stdio", "command": "npx", "env_vars": ["MY_VAR", {"name": "REMOTE", "source": "remote"}]}},
		{"name": "vercel", "enabled": true, "transport": {"type": "streamable_http", "url": "https://mcp.vercel.com"}},
		{"name": "off", "enabled": false, "transport": {"type": "stdio", "command": "x"}},
		{"name": "has.dot", "enabled": true, "transport": {"type": "stdio", "command": "x"}}
	]`))
	if err != nil {
		t.Fatal(err)
	}
	args, skipped := CodexConfig(CodexOptions{Servers: servers, EnvVars: []string{"HTTPS_PROXY", "MY_VAR"}, HookCommand: `/bin/opfence hook codex`})
	if !slices.Equal(skipped, []string{"has.dot"}) {
		t.Errorf("skipped %q", skipped)
	}
	joined := strings.Join(args, "\n")
	for _, want := range []string{
		`mcp_servers.supabase.env_vars=["MY_VAR",{"name"="REMOTE","source"="remote"},"HTTPS_PROXY"]`,
		`mcp_servers.supabase.default_tools_approval_mode="prompt"`,
		`hooks.PreToolUse=[{matcher="^mcp__",hooks=[{type="command",command="/bin/opfence hook codex",timeout=30}]}]`,
		`hooks.PermissionRequest=[{matcher="^mcp__",hooks=[{type="command",command="/bin/opfence hook codex",timeout=30}]}]`,
		`"/<session-flags>/config.toml:pre_tool_use:0:0"={trusted_hash="` + CodexHookHash("pre_tool_use", "^mcp__", "/bin/opfence hook codex") + `"}`,
		`"/<session-flags>/config.toml:permission_request:0:0"={trusted_hash="` + CodexHookHash("permission_request", "^mcp__", "/bin/opfence hook codex") + `"}`,
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %s in:\n%s", want, joined)
		}
	}
	for _, not := range []string{"vercel", "mcp_servers.off"} {
		if strings.Contains(joined, not) {
			t.Errorf("%s configured:\n%s", not, joined)
		}
	}
	for i := 0; i < len(args); i += 2 {
		if args[i] != "-c" {
			t.Fatalf("args[%d] = %q, want -c", i, args[i])
		}
	}

	// With every server's name usable, the hooks cover the stdio servers
	// only; the proxy decides remote ones.
	args, _ = CodexConfig(CodexOptions{Servers: servers[:3], HookCommand: "opfence hook codex"})
	if joined := strings.Join(args, "\n"); !strings.Contains(joined, `hooks.PreToolUse=[{matcher="^mcp__(?:supabase|off)__",`) ||
		!strings.Contains(joined, CodexHookHash("permission_request", "^mcp__(?:supabase|off)__", "opfence hook codex")) {
		t.Errorf("stdio-only matcher missing:\n%s", joined)
	}
	if args, _ = CodexConfig(CodexOptions{Servers: servers[1:2], HookCommand: "opfence hook codex"}); len(args) != 0 {
		t.Errorf("remote servers only: %q", args)
	}
	args, _ = CodexConfig(CodexOptions{ServersUnknown: true, HookCommand: "opfence hook codex"})
	if !strings.Contains(strings.Join(args, "\n"), `matcher="^mcp__",`) {
		t.Errorf("unknown servers: %q", args)
	}
}

func TestTOMLString(t *testing.T) {
	if got := tomlString(`a "b" \ <c>`); got != `"a \"b\" \\ <c>"` {
		t.Errorf("got %s", got)
	}
}
