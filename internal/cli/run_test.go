package cli

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// isolate points every Opfence folder at temporary ones and the keychain at
// memory. The state folder is short, because Unix socket paths are limited.
func isolate(t *testing.T) (stateDir string) {
	t.Helper()
	memoryStore(t)
	base, err := os.MkdirTemp("", "opf")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(base) })
	// macOS ignores the XDG variables for the cache and config dirs.
	t.Setenv("HOME", filepath.Join(base, "h"))
	t.Setenv("XDG_STATE_HOME", filepath.Join(base, "s"))
	t.Setenv("XDG_CACHE_HOME", filepath.Join(base, "c"))
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(base, "cfg"))
	t.Setenv("OPFENCE_CONFIG", "")
	t.Setenv(envSession, "")
	for _, k := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "NO_PROXY", "no_proxy"} {
		t.Setenv(k, "")
	}
	return filepath.Join(base, "s", "opfence")
}

func TestRunKind(t *testing.T) {
	for _, tc := range []struct {
		args      []string
		srt, weak bool
		goos      string
		want, err string
	}{
		{args: []string{"claude"}, goos: "linux", want: "claude"},
		{args: []string{"/usr/local/bin/claude", "-p", "hi"}, goos: "darwin", want: "claude"},
		{args: []string{"claude", "--settings", "x.json"}, goos: "linux", err: "passes its own --settings"},
		{args: []string{"claude", "--settings=x.json"}, goos: "linux", err: "passes its own --settings"},
		{args: []string{"claude"}, goos: "windows", err: "does not run on native Windows"},
		{args: []string{"codex"}, goos: "linux", err: "is not Claude Code"},
		{args: []string{"codex"}, srt: true, goos: "linux", want: "srt"},
		{args: []string{"npm", "run", "dev"}, weak: true, goos: "windows", want: "weak"},
		{args: []string{"x"}, srt: true, weak: true, goos: "linux", err: "choose one"},
	} {
		got, err := runKind(tc.args, tc.srt, tc.weak, tc.goos)
		if tc.err != "" {
			if err == nil || !strings.Contains(err.Error(), tc.err) {
				t.Errorf("%v: err %v, want %q", tc.args, err, tc.err)
			}
			continue
		}
		if err != nil || got != tc.want {
			t.Errorf("%v: %q %v, want %q", tc.args, got, err, tc.want)
		}
	}
}

// helperResult is what the helper child reports about its environment.
type helperResult struct {
	Env   map[string]string `json:"env"`
	Probe []check           `json:"probe"`
}

// TestHelperChild is not a test: opfence run starts the test binary with
// this test selected, and it reports what it saw. It runs opfence doctor's
// sandbox checks, which must find every way out, because this child runs
// without a sandbox.
func TestHelperChild(t *testing.T) {
	out := os.Getenv("OPFENCE_HELPER_OUT")
	if out == "" {
		return
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		os.Exit(90)
	}
	defer l.Close()
	env := defaultDoctorEnv
	env.directTarget = l.Addr().String()
	doctorTestEnv = &env
	code, stdout, _ := run(t, "doctor", "--probe", "--json")
	r := helperResult{Env: map[string]string{}}
	for _, k := range []string{"VERCEL_TOKEN", "HTTPS_PROXY", "NO_PROXY", "NODE_USE_ENV_PROXY", "SSL_CERT_FILE", "NODE_EXTRA_CA_CERTS", envSession} {
		r.Env[k] = os.Getenv(k)
	}
	_ = json.Unmarshal([]byte(stdout), &r.Probe)
	data, _ := json.Marshal(r)
	if os.WriteFile(out, data, 0o600) != nil || code != exitFail {
		os.Exit(91)
	}
	os.Exit(7)
}

func TestRunWeak(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix sockets and signals")
	}
	stateDir := isolate(t)
	vercel := "vcp_AbCdEfGhIjKlMnOpQrStUvWx"
	t.Setenv("VERCEL_TOKEN", vercel)
	out := filepath.Join(t.TempDir(), "child.json")
	t.Setenv("OPFENCE_HELPER_OUT", out)
	code, _, errOut := run(t, "run", "--weak", "--", os.Args[0], "-test.run=^TestHelperChild$")
	if code != 7 {
		t.Fatalf("exit %d, want the child's 7\n%s", code, errOut)
	}
	if !strings.Contains(errOut, "weak mode") || !strings.Contains(errOut, "VERCEL_TOKEN: placeholder for this session") {
		t.Errorf("banner:\n%s", errOut)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var r helperResult
	if err := json.Unmarshal(data, &r); err != nil {
		t.Fatal(err)
	}
	e := r.Env
	if e["VERCEL_TOKEN"] == vercel || len(e["VERCEL_TOKEN"]) != len(vercel) || !strings.HasPrefix(e["VERCEL_TOKEN"], "vcp_") {
		t.Errorf("child saw VERCEL_TOKEN=%q", e["VERCEL_TOKEN"])
	}
	if !strings.HasPrefix(e["HTTPS_PROXY"], "http://127.0.0.1:") || e["NODE_USE_ENV_PROXY"] != "1" || e["NO_PROXY"] == "" || e[envSession] == "" {
		t.Errorf("child env %v", e)
	}
	if !strings.HasSuffix(e["NODE_EXTRA_CA_CERTS"], filepath.Join("opfence", "ca.pem")) {
		t.Errorf("NODE_EXTRA_CA_CERTS=%s", e["NODE_EXTRA_CA_CERTS"])
	}
	status := map[string]string{}
	for _, c := range r.Probe {
		status[c.Name] = c.Status
	}
	// Unsandboxed, the probe must see each way out; through the weak
	// listener it must still find Opfence.
	for name, want := range map[string]string{
		"approval sockets": "fail", "state folder": "fail", "Opfence config": "fail", "direct connections": "fail", "proxy": "ok",
	} {
		if status[name] != want {
			t.Errorf("probe %s: %q, want %q (all: %v)", name, status[name], want, status)
		}
	}
	if e["SSL_CERT_FILE"] != "" && status["CA files"] != "ok" {
		t.Errorf("CA files: %q", status["CA files"])
	}
	// The session's socket is gone once run returns.
	if socks, _ := filepath.Glob(filepath.Join(stateDir, "control*.sock")); len(socks) != 0 {
		t.Errorf("sockets left behind: %v", socks)
	}
	if logData, err := os.ReadFile(filepath.Join(stateDir, "opfence.log")); err != nil {
		t.Errorf("run log: %v", err)
	} else if strings.Contains(string(logData), "panic") {
		t.Errorf("run log:\n%s", logData)
	}
}

// opfence run -- claude passes its settings with --settings and points
// Claude Code itself at the agent listener, not the sandbox's ports.
func TestRunClaudeSettings(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no sandbox on Windows")
	}
	isolate(t)
	bin := t.TempDir()
	out := filepath.Join(t.TempDir(), "args")
	script := "#!/bin/sh\n[ \"$1\" = --version ] && { echo '2.1.300 (Claude Code)'; exit 0; }\nprintf '%s\\n' \"$@\" > \"$OUT\"\nenv > \"$OUT.env\"\nexit 3\n"
	if err := os.WriteFile(filepath.Join(bin, "claude"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("OUT", out)
	code, _, errOut := run(t, "run", "--", filepath.Join(bin, "claude"), "-p", "hello")
	if code != 3 {
		t.Fatalf("exit %d\n%s", code, errOut)
	}
	if strings.Contains(errOut, "is older than") {
		t.Errorf("version warning for a new enough version:\n%s", errOut)
	}
	raw, _ := os.ReadFile(out)
	args := strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
	if len(args) < 4 || args[0] != "--settings" || args[len(args)-2] != "-p" || args[len(args)-1] != "hello" {
		t.Fatalf("args %q", args)
	}
	settings := strings.Join(args[1:len(args)-2], "\n")
	var s struct {
		Sandbox struct {
			Enabled bool
			Network struct{ HTTPProxyPort, SOCKSProxyPort int }
		}
		Hooks map[string][]struct{ Hooks []struct{ Command string } }
	}
	if err := json.Unmarshal([]byte(settings), &s); err != nil {
		t.Fatalf("settings %v:\n%s", err, settings)
	}
	if !s.Sandbox.Enabled || s.Sandbox.Network.HTTPProxyPort == 0 || s.Sandbox.Network.SOCKSProxyPort == 0 {
		t.Errorf("sandbox %+v", s.Sandbox)
	}
	if cmd := s.Hooks["PreToolUse"][0].Hooks[0].Command; !strings.HasSuffix(cmd, " hook claude-code") {
		t.Errorf("hook %q", cmd)
	}
	envRaw, _ := os.ReadFile(out + ".env")
	env := map[string]string{}
	for _, l := range strings.Split(string(envRaw), "\n") {
		if k, v, ok := strings.Cut(l, "="); ok {
			env[k] = v
		}
	}
	agent := env[envAgentPort]
	if agent == "" || !strings.HasSuffix(env["HTTPS_PROXY"], ":"+agent) {
		t.Errorf("Claude Code's own proxy %q should be the agent listener %q", env["HTTPS_PROXY"], agent)
	}
	for _, p := range []int{s.Sandbox.Network.HTTPProxyPort, s.Sandbox.Network.SOCKSProxyPort} {
		if agent == itoa(p) {
			t.Errorf("agent listener reused a sandbox port %d", p)
		}
	}
}

func itoa(n int) string { return strconv.Itoa(n) }

type recordRunner struct{ cmds []string }

func (r *recordRunner) Run(name string, args ...string) error {
	r.cmds = append(r.cmds, name+" "+strings.Join(args, " "))
	return nil
}

func TestTrustInstallAndUninstall(t *testing.T) {
	stateDir := isolate(t)
	r := &recordRunner{}
	oldR, oldOS := trustRunner, trustGOOS
	trustRunner, trustGOOS = r, "darwin"
	t.Cleanup(func() { trustRunner, trustGOOS = oldR, oldOS })

	code, out, errOut := run(t, "trust")
	if code != exitOK || !strings.Contains(out, "now trusted") || len(r.cmds) != 1 || !strings.HasPrefix(r.cmds[0], "security add-trusted-cert") {
		t.Fatalf("trust: %d %s %s %v", code, out, errOut, r.cmds)
	}
	manifest := filepath.Join(stateDir, "trust.json")
	if _, err := os.Stat(manifest); err != nil {
		t.Fatal("no manifest")
	}
	if code, out, _ := run(t, "trust"); code != exitOK || !strings.Contains(out, "already trusted") || len(r.cmds) != 1 {
		t.Fatalf("second trust: %d %s %v", code, out, r.cmds)
	}
	code, out, _ = run(t, "trust", "--uninstall")
	if code != exitOK || !strings.Contains(out, "undone") || len(r.cmds) != 3 ||
		!strings.HasPrefix(r.cmds[1], "security remove-trusted-cert") || !strings.HasPrefix(r.cmds[2], "security delete-certificate -Z") {
		t.Fatalf("uninstall: %d %s %v", code, out, r.cmds)
	}
	if _, err := os.Stat(manifest); !os.IsNotExist(err) {
		t.Fatal("manifest left after a clean uninstall")
	}
	if code, out, _ := run(t, "trust", "--uninstall"); code != exitOK || !strings.Contains(out, "nothing to undo") {
		t.Fatalf("second uninstall: %d %s", code, out)
	}
}

func TestDoctorReportsEachCheck(t *testing.T) {
	isolate(t)
	t.Setenv("CLAUDE_CONFIG_DIR", t.TempDir())
	found := map[string]bool{"claude": true, "bwrap": true}
	doctorTestEnv = &doctorEnv{
		goos:   "linux",
		getenv: os.Getenv,
		lookPath: func(name string) (string, error) {
			if found[name] {
				return "/usr/bin/" + name, nil
			}
			return "", os.ErrNotExist
		},
		output: func(context.Context, string, ...string) ([]byte, error) {
			return []byte("2.1.200 (Claude Code)\n"), nil
		},
	}
	t.Cleanup(func() { doctorTestEnv = nil })
	code, out, _ := run(t, "doctor")
	if code != exitFail {
		t.Errorf("exit %d, want 1 (socat is missing)", code)
	}
	for _, want := range []string{
		"ok    policy: 5 providers",
		"ok    keychain: 0 API keys stored",
		"warn  CA: not made yet",
		"ok    CA trust: programs started with opfence run",
		"warn  Claude Code: 2.1.200 is older than 2.1.285",
		"FAIL  sandbox: missing socat",
		"skip  sandbox runtime",
		"skip  state folder",
		"skip  audit log",
		"approvals:",
		"skip  sandbox checks",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}
