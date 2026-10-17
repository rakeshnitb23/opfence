package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/rakeshnitb23/opfence/internal/approve"
	"github.com/rakeshnitb23/opfence/internal/audit"
	"github.com/rakeshnitb23/opfence/internal/launch"
	"github.com/rakeshnitb23/opfence/internal/policy"
	"github.com/rakeshnitb23/opfence/internal/proxy"
	"github.com/rakeshnitb23/opfence/internal/secrets"
	"github.com/rakeshnitb23/opfence/internal/trust"
)

// check is one line of opfence doctor's report.
type check struct {
	Name   string `json:"name"`
	Status string `json:"status"` // ok, warn, fail, skip
	Detail string `json:"detail"`
	Fix    string `json:"fix,omitempty"`
}

// doctorEnv holds what doctor looks at, so tests can replace it.
type doctorEnv struct {
	goos     string
	getenv   func(string) string
	lookPath func(string) (string, error)
	// output runs a command and returns its standard output.
	output func(ctx context.Context, name string, args ...string) ([]byte, error)
	// directTarget is dialled to check that the sandbox blocks direct
	// connections.
	directTarget string
}

var defaultDoctorEnv = doctorEnv{
	goos:     runtime.GOOS,
	getenv:   os.Getenv,
	lookPath: exec.LookPath,
	output: func(ctx context.Context, name string, args ...string) ([]byte, error) {
		return exec.CommandContext(ctx, name, args...).Output()
	},
	directTarget: "1.1.1.1:443",
}

// doctorTestEnv replaces defaultDoctorEnv in tests.
var doctorTestEnv *doctorEnv

func newDoctorCmd(g *globalOptions) *cobra.Command {
	var probe, asJSON bool
	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Check that Opfence is set up and that the sandbox keeps the agent away from it",
		Long: `Doctor checks the catalog and policy, the keychain, the CA and whether it is
trusted, Claude Code's version, settings and sandbox dependencies, the state
folder and the audit log.

It also checks, from inside a sandbox, that a sandboxed agent cannot reach
the keychain, the approval sockets or the state folder, cannot write your
Opfence config or binary, cannot connect anywhere directly, and that its
proxy really is Opfence. Run inside a session (ask Claude to run
"opfence doctor" in a session started with opfence run), doctor does only
these checks. Outside one, it runs them through Anthropic's sandbox runtime
(srt) when that is installed.

Exits 1 when a check fails.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			env := defaultDoctorEnv
			if doctorTestEnv != nil {
				env = *doctorTestEnv
			}
			var checks []check
			if probe || env.getenv(envSession) != "" {
				checks = probeChecks(g, env)
			} else {
				checks = outsideChecks(cmd, g, env)
				checks = append(checks, sandboxChecks(cmd, g, env)...)
			}
			out := cmd.OutOrStdout()
			if asJSON {
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				if err := enc.Encode(checks); err != nil {
					return err
				}
			} else {
				printChecks(out, checks)
			}
			for _, c := range checks {
				if c.Status == "fail" {
					return failError{"a check failed"}
				}
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&probe, "probe", false, "run only the checks meant for inside a sandbox")
	cmd.Flags().BoolVar(&asJSON, "json", false, "print the checks as JSON")
	return cmd
}

func printChecks(w io.Writer, checks []check) {
	mark := map[string]string{"ok": "ok  ", "warn": "warn", "fail": "FAIL", "skip": "skip"}
	for _, c := range checks {
		fmt.Fprintf(w, "%s  %s: %s\n", mark[c.Status], c.Name, c.Detail)
		if c.Fix != "" && c.Status != "ok" {
			fmt.Fprintf(w, "      %s\n", c.Fix)
		}
	}
}

// outsideChecks look at the machine as the user.
func outsideChecks(cmd *cobra.Command, g *globalOptions, env doctorEnv) []check {
	var out []check
	add := func(c check) { out = append(out, c) }

	eng, err := g.engine()
	if err != nil {
		add(check{Name: "policy", Status: "fail", Detail: err.Error(), Fix: "fix the file named above; opfence policy check explains each problem"})
	} else {
		c := check{Name: "policy", Status: "ok", Detail: fmt.Sprintf("%d providers in the catalog, %s mode", len(eng.Catalog.Providers), eng.Policy.Mode)}
		if len(eng.Policy.Warnings) > 0 {
			c.Status, c.Detail = "warn", strings.Join(eng.Policy.Warnings, "; ")
		}
		add(c)
	}

	vault := &secrets.Vault{Store: openStore()}
	stored, err := vault.List()
	if err != nil {
		vault = nil
		add(check{Name: "keychain", Status: "warn", Detail: "cannot be read: " + err.Error(),
			Fix: "without a keychain Opfence still decides requests, but cannot hold your API keys or keep one CA between runs"})
	} else {
		add(check{Name: "keychain", Status: "ok", Detail: fmt.Sprintf("%d API keys stored", len(stored))})
	}

	var certPEM []byte
	if vault != nil {
		if c, _, err := vault.CA(); err == nil {
			certPEM = c
			add(check{Name: "CA", Status: "ok", Detail: "kept in your keychain"})
		} else if errors.Is(err, secrets.ErrNotFound) {
			add(check{Name: "CA", Status: "warn", Detail: "not made yet", Fix: "opfence run, opfence proxy or opfence trust makes it"})
		} else {
			add(check{Name: "CA", Status: "warn", Detail: err.Error()})
		}
	}
	add(trustCheck(env, certPEM))
	out = append(out, claudeChecks(env)...)

	if p, err := env.lookPath("srt"); err == nil {
		add(check{Name: "sandbox runtime", Status: "ok", Detail: "srt at " + p})
	} else {
		add(check{Name: "sandbox runtime", Status: "skip", Detail: "srt is not installed (needed only for opfence run --srt)",
			Fix: "npm install -g @anthropic-ai/sandbox-runtime"})
	}

	stateDir, err := audit.StateDir()
	if err == nil {
		if info, serr := os.Stat(stateDir); serr != nil {
			add(check{Name: "state folder", Status: "skip", Detail: stateDir + " does not exist yet"})
		} else if env.goos != "windows" && info.Mode().Perm()&0o077 != 0 {
			add(check{Name: "state folder", Status: "warn", Detail: fmt.Sprintf("%s is readable by other users (%v)", stateDir, info.Mode().Perm()), Fix: "chmod 700 " + stateDir})
		} else {
			add(check{Name: "state folder", Status: "ok", Detail: stateDir})
		}
		logPath := filepath.Join(stateDir, "audit.jsonl")
		if data, rerr := os.ReadFile(logPath); rerr == nil {
			if n, verr := audit.Verify(bytes.NewReader(data)); verr != nil {
				add(check{Name: "audit log", Status: "fail", Detail: verr.Error(), Fix: "the log was edited or damaged; keep a copy for investigation, then move it aside"})
			} else {
				add(check{Name: "audit log", Status: "ok", Detail: fmt.Sprintf("chain intact, %d entries", n)})
			}
		} else {
			add(check{Name: "audit log", Status: "skip", Detail: "no entries yet"})
		}
	}

	phone := ""
	if cfg, err := approve.LoadPhone(openStore()); err == nil {
		phone = ", and your phone through " + cfg.Server
	}
	switch {
	case approve.NewDesktop() != nil:
		add(check{Name: "approvals", Status: "ok", Detail: "desktop dialogs and opfence approve" + phone})
	case phone != "":
		add(check{Name: "approvals", Status: "ok", Detail: "opfence approve" + phone + " (no desktop dialog available)"})
	default:
		add(check{Name: "approvals", Status: "warn", Detail: "no desktop dialog available (needs osascript, or zenity or kdialog with a display)",
			Fix: "answer requests with opfence approve in another terminal, or set up your phone with opfence phone setup"})
	}
	return out
}

func trustCheck(env doctorEnv, certPEM []byte) check {
	c := check{Name: "CA trust"}
	path, err := trustManifestPath()
	if err != nil {
		c.Status, c.Detail = "warn", err.Error()
		return c
	}
	m, err := trust.Load(path)
	if err != nil {
		c.Status, c.Detail = "warn", err.Error()
		return c
	}
	if m != nil && certPEM != nil {
		if sum, _ := trust.SHA256(certPEM); sum != m.CertSHA256 {
			c.Status, c.Detail, c.Fix = "warn", "the trusted CA is not the one in your keychain", "opfence trust"
			return c
		}
	}
	if m != nil && len(m.Steps) > 0 {
		var where []string
		for _, s := range m.Steps {
			where = append(where, s.Description)
		}
		c.Status, c.Detail = "ok", strings.Join(where, "; ")
		return c
	}
	switch env.goos {
	case "linux":
		c.Status, c.Detail = "ok", "programs started with opfence run get the CA through SSL_CERT_FILE and similar variables"
	case "darwin":
		c.Status, c.Detail, c.Fix = "warn", "not in your login keychain; Go programs such as gh and terraform ignore SSL_CERT_FILE on macOS", "opfence trust"
	default:
		c.Status, c.Detail, c.Fix = "warn", "not in your certificate store", "opfence trust"
	}
	return c
}

func claudeChecks(env doctorEnv) []check {
	var out []check
	claude, err := env.lookPath("claude")
	if err != nil {
		out = append(out, check{Name: "Claude Code", Status: "skip", Detail: "claude is not on your PATH"})
	} else {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		raw, verr := env.output(ctx, claude, "--version")
		cancel()
		v, ok := launch.ParseVersion(string(raw))
		switch {
		case verr != nil || !ok:
			out = append(out, check{Name: "Claude Code", Status: "warn", Detail: "could not read the version of " + claude})
		case launch.Older(v, launch.MinClaudeVersion):
			out = append(out, check{Name: "Claude Code", Status: "warn",
				Detail: fmt.Sprintf("%s is older than %s, so a repository's settings can still loosen the sandbox", launch.FormatVersion(v), launch.FormatVersion(launch.MinClaudeVersion)),
				Fix:    "claude update"})
		default:
			out = append(out, check{Name: "Claude Code", Status: "ok", Detail: launch.FormatVersion(v)})
		}
	}
	switch env.goos {
	case "linux":
		var missing []string
		for _, t := range []string{"bwrap", "socat"} {
			if _, err := env.lookPath(t); err != nil {
				missing = append(missing, t)
			}
		}
		if len(missing) > 0 {
			out = append(out, check{Name: "sandbox", Status: "fail", Detail: "missing " + strings.Join(missing, " and ") + "; Claude Code's sandbox cannot start, so opfence run -- claude will not",
				Fix: "install bubblewrap and socat (for example: sudo apt install bubblewrap socat)"})
		} else {
			out = append(out, check{Name: "sandbox", Status: "ok", Detail: "bubblewrap and socat installed"})
		}
	case "darwin":
		if _, err := env.lookPath("sandbox-exec"); err != nil {
			out = append(out, check{Name: "sandbox", Status: "fail", Detail: "sandbox-exec not found"})
		} else {
			out = append(out, check{Name: "sandbox", Status: "ok", Detail: "Seatbelt (sandbox-exec)"})
		}
	default:
		out = append(out, check{Name: "sandbox", Status: "warn", Detail: "Claude Code's sandbox does not run on " + env.goos + "; only opfence run --weak is available",
			Fix: "use WSL2 for a sandboxed agent"})
	}
	home, _ := os.UserHomeDir()
	cwd, _ := os.Getwd()
	for _, w := range launch.ClaudeSettingsWarnings(launch.UserSettingsPath(env.getenv, home), launch.ManagedSettingsPath(env.goos), launch.ProjectSettingsFiles(cwd)...) {
		out = append(out, check{Name: "Claude Code settings", Status: "warn", Detail: w})
	}
	return out
}

// sandboxChecks runs the probe through srt with a temporary session.
func sandboxChecks(cmd *cobra.Command, g *globalOptions, env doctorEnv) []check {
	skip := check{Name: "sandbox checks", Status: "skip",
		Detail: "not checked from here",
		Fix:    `ask Claude to run "opfence doctor" in a session started with opfence run -- claude, or install srt so doctor can check by itself`}
	srtPath, err := env.lookPath("srt")
	if err != nil || env.goos == "windows" {
		return []check{skip}
	}
	stateDir, err := audit.StateDir()
	if err != nil {
		return []check{skip}
	}
	s, err := openSession(g, sessionOptions{warn: io.Discard, logf: func(string, ...any) {}})
	if err != nil {
		skip.Detail = "could not start a test session: " + err.Error()
		return []check{skip}
	}
	defer s.Close()
	h, so, err := s.listen(listenSpec{via: "srt", http: "127.0.0.1:0", socks: "127.0.0.1:0"})
	if err != nil {
		skip.Detail = err.Error()
		return []check{skip}
	}
	paths, err := runPaths(g, stateDir)
	if err != nil {
		skip.Detail = err.Error()
		return []check{skip}
	}
	cwd, _ := os.Getwd()
	var denyRead []string
	if env.goos == "linux" {
		denyRead = launch.LinuxSecretSockets(env.getenv)
	}
	settings, err := launch.SrtSettings(launch.SrtOptions{HTTPPort: launch.Port(h), SOCKSPort: launch.Port(so), GOOS: env.goos,
		Paths: paths, DenyRead: denyRead, AllowWrite: []string{cwd, os.TempDir()}})
	if err != nil {
		skip.Detail = err.Error()
		return []check{skip}
	}
	file := filepath.Join(paths.CertDir, "srt-doctor-"+s.id+".json")
	if err := os.WriteFile(file, settings, 0o644); err != nil {
		skip.Detail = err.Error()
		return []check{skip}
	}
	defer os.Remove(file)
	vars := launch.CAEnv(s.caFiles.CA, s.caFiles.Bundle)
	vars[envSession] = s.id
	ctx, cancel := context.WithTimeout(cmd.Context(), 60*time.Second)
	defer cancel()
	c := exec.CommandContext(ctx, srtPath, "--settings", file, "--", paths.Executable, "doctor", "--probe", "--json")
	c.Env = launch.SetEnv(os.Environ(), vars, false)
	raw, err := c.Output()
	var checks []check
	if jerr := json.Unmarshal(raw, &checks); jerr != nil || len(checks) == 0 {
		detail := "the probe did not report"
		if err != nil {
			detail += ": " + err.Error()
		}
		return []check{{Name: "sandbox checks", Status: "fail", Detail: detail + " (srt may not be able to start its sandbox here)"}}
	}
	for i := range checks {
		checks[i].Name = "sandbox: " + checks[i].Name
	}
	return checks
}

// probeChecks run inside a sandbox and look for every way out of it.
func probeChecks(g *globalOptions, env doctorEnv) []check {
	var out []check
	add := func(c check) { out = append(out, c) }
	blocked := func(name string, reachable bool, detail, fix string) {
		if reachable {
			add(check{Name: name, Status: "fail", Detail: detail, Fix: fix})
		} else {
			add(check{Name: name, Status: "ok", Detail: "blocked"})
		}
	}

	_, kerr := openStore().Get("index")
	blocked("keychain", kerr == nil || errors.Is(kerr, secrets.ErrNotFound),
		"the sandbox can reach your keychain, so an agent could read your stored API keys",
		"on Linux, check that the D-Bus session socket is denied; on macOS, report this: Opfence needs its own keychain access control")

	stateDir, _ := audit.StateDir()
	socks, _ := filepath.Glob(filepath.Join(stateDir, "control*.sock"))
	reach := false
	for _, s := range socks {
		if c, err := net.DialTimeout("unix", s, time.Second); err == nil {
			c.Close()
			reach = true
		}
	}
	blocked("approval sockets", reach, "the sandbox can connect to an approval socket, so an agent could approve its own requests",
		"start the agent with opfence run, which denies the sandbox the state folder")

	_, rerr := os.ReadFile(filepath.Join(stateDir, "audit.jsonl"))
	entries, _ := os.ReadDir(stateDir)
	blocked("state folder", rerr == nil || len(entries) > 0, "the sandbox can read "+stateDir, "start the agent with opfence run")

	cfg := g.userConfig
	if cfg == "" {
		cfg = policy.UserConfigPath()
	}
	if cfg != "" {
		blocked("Opfence config", canWriteNear(cfg), "the sandbox can write next to "+cfg+", so an agent could loosen your policy", "start the agent with opfence run")
	}
	if exe, err := os.Executable(); err == nil {
		f, werr := os.OpenFile(exe, os.O_WRONLY, 0)
		if werr == nil {
			f.Close()
		}
		blocked("opfence binary", werr == nil, "the sandbox can overwrite "+exe+", which the hook runs", "install opfence outside your project folder")
	}

	add(proxyCheck(env))
	add(caCheck(env))

	if c, err := net.DialTimeout("tcp", env.directTarget, 3*time.Second); err == nil {
		c.Close()
		add(check{Name: "direct connections", Status: "fail", Detail: "connected to " + env.directTarget + " without the proxy", Fix: "the sandbox's network isolation is off"})
	} else {
		add(check{Name: "direct connections", Status: "ok", Detail: "blocked"})
	}

	if p := env.getenv(envAgentPort); p != "" {
		c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", p), time.Second)
		if err == nil {
			c.Close()
		}
		blocked("agent listener", err == nil, "the sandbox can reach the listener meant for Claude Code itself, which tunnels any host",
			"report this: the sandbox should only reach its own proxy ports")
	}
	return out
}

// canWriteNear reports whether a file can be created in the config file's
// folder or, when that does not exist yet, in its nearest existing parent
// (from where the folder and a config could be created).
func canWriteNear(cfg string) bool {
	dir := filepath.Dir(cfg)
	for {
		if _, err := os.Stat(dir); err == nil {
			break
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return false
		}
		dir = parent
	}
	f, err := os.CreateTemp(dir, ".opfence-probe-*")
	if err != nil {
		return false
	}
	f.Close()
	os.Remove(f.Name())
	return true
}

func proxyCheck(env doctorEnv) check {
	c := check{Name: "proxy"}
	proxyURL := env.getenv("HTTP_PROXY")
	if proxyURL == "" {
		proxyURL = env.getenv("http_proxy")
	}
	if proxyURL == "" {
		c.Status, c.Detail, c.Fix = "fail", "HTTP_PROXY is not set, so programs here are not sent to Opfence", "start the agent with opfence run"
		return c
	}
	u, err := url.Parse(proxyURL)
	if err != nil {
		c.Status, c.Detail = "fail", "HTTP_PROXY is not a URL: "+err.Error()
		return c
	}
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{Proxy: http.ProxyURL(u)}}
	resp, err := client.Get("http://" + proxy.ProbeHost + "/")
	if err != nil {
		c.Status, c.Detail = "fail", "the proxy did not answer: "+err.Error()
		return c
	}
	defer resp.Body.Close()
	var p proxy.Probe
	if json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&p) != nil || !p.Opfence {
		c.Status, c.Detail = "fail", "the proxy at "+proxyURL+" is not Opfence"
		return c
	}
	if s := env.getenv(envSession); s != "" && p.Session != s {
		c.Status, c.Detail = "warn", fmt.Sprintf("Opfence answered for session %s, not this session's %s", p.Session, s)
		return c
	}
	c.Status, c.Detail = "ok", fmt.Sprintf("Opfence session %s, %s mode, via %s", p.Session, p.Mode, p.Via)
	return c
}

func caCheck(env doctorEnv) check {
	c := check{Name: "CA files"}
	ca := env.getenv("NODE_EXTRA_CA_CERTS")
	caPEM, err := os.ReadFile(ca)
	if ca == "" || err != nil {
		c.Status, c.Detail, c.Fix = "fail", "NODE_EXTRA_CA_CERTS does not name a readable Opfence CA", "start the agent with opfence run"
		return c
	}
	bundle := env.getenv("SSL_CERT_FILE")
	if bundle == "" {
		c.Status, c.Detail = "warn", "SSL_CERT_FILE is not set; only Node programs will trust Opfence's CA"
		return c
	}
	data, err := os.ReadFile(bundle)
	if err != nil || !bytes.Contains(data, bytes.TrimSpace(caPEM)) {
		c.Status, c.Detail = "fail", "SSL_CERT_FILE ("+bundle+") does not contain Opfence's CA, so HTTPS to APIs will fail here"
		return c
	}
	c.Status, c.Detail = "ok", "readable, and the bundle holds Opfence's CA ("+strconv.Itoa(bytes.Count(data, []byte("BEGIN CERTIFICATE")))+" certificates)"
	return c
}
