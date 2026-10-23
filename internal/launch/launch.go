// Package launch prepares programs to run behind the Opfence proxy
// (docs/ARCHITECTURE.md §8.7): the Claude Code settings passed with
// --settings, the srt settings file, the CA files and the child's
// environment. It builds values; internal/cli starts the processes.
package launch

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// Paths are the files and folders the sandbox must be kept away from, or
// must be able to read.
type Paths struct {
	// StateDir holds the audit log, control sockets and trust manifest. The
	// sandbox may neither read nor write it: with the control socket an agent
	// could approve its own requests.
	StateDir string
	// ConfigFile is the user's policy. The sandbox and Claude Code's file
	// tools may not write it, or an agent could loosen its own policy.
	ConfigFile string
	// CertDir holds the CA certificate and bundle, which the sandbox reads.
	CertDir string
	// Executable is the opfence binary the hook runs; nothing may replace it.
	Executable string
	// ProjectDir is the folder the agent starts in. Claude Code reads hooks,
	// environment variables and permissions from settings files there, and
	// hooks run outside the sandbox, so the sandbox may not write them.
	ProjectDir string
}

// ProjectSettingsFiles are the Claude Code settings files in a project.
func ProjectSettingsFiles(dir string) []string {
	return []string{filepath.Join(dir, ".claude", "settings.json"), filepath.Join(dir, ".claude", "settings.local.json")}
}

// CertDir is where the CA files live: the user cache folder, outside the
// state folder the sandbox cannot read.
func CertDir() (string, error) {
	d, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, "opfence"), nil
}

// protectedPath is a file or folder that is kept from the agent.
type protectedPath struct {
	path string
	dir  bool
}

// protectedWrites lists what neither sandboxed commands nor file tools may
// write. The config file's folder is included when it is Opfence's own
// folder, so an agent cannot create a config where none exists yet.
func (p Paths) protectedWrites() []protectedPath {
	var out []protectedPath
	if p.ConfigFile != "" {
		if dir := filepath.Dir(p.ConfigFile); filepath.Base(dir) == "opfence" {
			out = append(out, protectedPath{dir, true})
		} else {
			out = append(out, protectedPath{p.ConfigFile, false})
		}
	}
	for _, x := range []protectedPath{{p.StateDir, true}, {p.CertDir, true}, {p.Executable, false}} {
		if x.path != "" {
			out = append(out, x)
		}
	}
	if p.ProjectDir != "" {
		for _, f := range ProjectSettingsFiles(p.ProjectDir) {
			out = append(out, protectedPath{f, false})
		}
	}
	return out
}

func pathsOf(ps []protectedPath) []string {
	out := []string{}
	for _, p := range ps {
		out = append(out, p.path)
	}
	return out
}

// ClaudeOptions configures the settings for opfence run -- claude.
type ClaudeOptions struct {
	HTTPPort, SOCKSPort int
	GOOS                string
	Paths               Paths
	// DenyRead adds paths sandboxed commands may not read, such as the
	// D-Bus session socket that reaches the Linux keychain.
	DenyRead []string
	// HookArgs are global flags the hook needs to load the same catalog and
	// policy as the proxy (--catalog DIR, --user-config FILE).
	HookArgs []string
	// Env pins environment variables Claude Code, its hooks and its MCP
	// servers get, so a project's settings cannot point them elsewhere.
	Env map[string]string
}

type claudeSettings struct {
	Sandbox         claudeSandbox          `json:"sandbox"`
	Permissions     claudePermissions      `json:"permissions"`
	Hooks           map[string][]hookGroup `json:"hooks"`
	DisableAllHooks bool                   `json:"disableAllHooks"`
	Env             map[string]string      `json:"env,omitempty"`
}

type claudeSandbox struct {
	Enabled                      bool          `json:"enabled"`
	FailIfUnavailable            bool          `json:"failIfUnavailable"`
	AllowUnsandboxedCommands     bool          `json:"allowUnsandboxedCommands"`
	Network                      claudeNetwork `json:"network"`
	Filesystem                   filesystem    `json:"filesystem"`
	EnableWeakerNetworkIsolation bool          `json:"enableWeakerNetworkIsolation,omitempty"`
}

type claudeNetwork struct {
	HTTPProxyPort  int `json:"httpProxyPort"`
	SOCKSProxyPort int `json:"socksProxyPort"`
}

type filesystem struct {
	DenyRead   []string `json:"denyRead"`
	AllowWrite []string `json:"allowWrite,omitempty"`
	DenyWrite  []string `json:"denyWrite"`
}

type claudePermissions struct {
	Deny []string `json:"deny"`
}

type hookGroup struct {
	Matcher string        `json:"matcher"`
	Hooks   []hookHandler `json:"hooks"`
}

type hookHandler struct {
	Type      string `json:"type"`
	Command   string `json:"command"`
	Timeout   int    `json:"timeout"`
	OnFailure string `json:"onFailure"`
}

// ClaudeSettings returns the JSON for claude --settings. Claude Code treats
// --settings as a trusted scope: it may set the proxy ports, and turning off
// unsandboxed retries there makes the sandbox admin-required, so a
// repository's own settings cannot take commands out of it.
//
// Claude Code's file tools, MCP servers and hooks run outside the sandbox.
// Permission deny rules keep the file tools off Opfence's state, config and
// binary; the PreToolUse hook decides MCP tool calls; and the agent
// listener (see opfence run) sees MCP servers' traffic to catalog APIs.
// disableAllHooks and env are set because --settings outranks a project's
// settings: a project cannot turn the hook off or move the proxy, CA or
// config the hook and MCP servers use.
func ClaudeSettings(o ClaudeOptions) ([]byte, error) {
	deny := append([]string{}, o.DenyRead...)
	if o.Paths.StateDir != "" {
		deny = append([]string{o.Paths.StateDir}, deny...)
	}
	writes := o.Paths.protectedWrites()
	s := claudeSettings{
		Sandbox: claudeSandbox{
			Enabled:           true,
			FailIfUnavailable: true,
			Network:           claudeNetwork{HTTPProxyPort: o.HTTPPort, SOCKSProxyPort: o.SOCKSPort},
			Filesystem:        filesystem{DenyRead: nonNil(deny), DenyWrite: pathsOf(writes)},
			// Go programs on macOS verify certificates through trustd, which
			// Seatbelt blocks unless this is set; without it gh, terraform and
			// other Go CLIs fail against Opfence's CA.
			EnableWeakerNetworkIsolation: o.GOOS == "darwin",
		},
		Permissions: claudePermissions{Deny: []string{}},
		Env:         o.Env,
		Hooks: map[string][]hookGroup{"PreToolUse": {{
			Matcher: "^mcp__",
			Hooks: []hookHandler{{
				Type: "command", Command: HookCommand(o.Paths.Executable, o.HookArgs), Timeout: 30,
				OnFailure: "block",
			}},
		}}},
	}
	if o.Paths.StateDir != "" {
		s.Permissions.Deny = append(s.Permissions.Deny, "Read("+ruleGlob(protectedPath{o.Paths.StateDir, true})+")")
	}
	if o.GOOS == "linux" {
		// Opfence's own environment, in /proc/<pid>/environ, holds the real
		// keys it replaced with placeholders.
		s.Permissions.Deny = append(s.Permissions.Deny, "Read(//proc/**)")
	}
	for _, p := range writes {
		s.Permissions.Deny = append(s.Permissions.Deny, "Edit("+ruleGlob(p)+")")
	}
	out, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(out, '\n'), nil
}

// ruleGlob writes an absolute path in Claude Code's permission rule syntax,
// where "//" starts an absolute path and a folder covers everything in it.
func ruleGlob(p protectedPath) string {
	g := "//" + strings.TrimPrefix(filepath.ToSlash(p.path), "/")
	if p.dir {
		g += "/**"
	}
	return g
}

// HookCommand is the shell command Claude Code runs for the hook.
func HookCommand(exe string, args []string) string {
	return AgentHookCommand(exe, args, "claude-code")
}

// AgentHookCommand is the shell command an agent runs for opfence hook
// <agent>.
func AgentHookCommand(exe string, args []string, agent string) string {
	if exe == "" {
		exe = "opfence"
	}
	parts := []string{ShellQuote(exe)}
	for _, a := range args {
		parts = append(parts, ShellQuote(a))
	}
	return strings.Join(append(parts, "hook", agent), " ")
}

// ShellQuote quotes s for a POSIX shell when it needs it.
func ShellQuote(s string) string {
	if s != "" && strings.Trim(s, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_./=:@+,") == "" {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// SrtOptions configures the settings file for opfence run --srt.
type SrtOptions struct {
	HTTPPort, SOCKSPort int
	GOOS                string
	Paths               Paths
	DenyRead            []string
	// AllowWrite lists the folders the agent may write: its working folder,
	// the temporary folder and an agent preset's state folder.
	AllowWrite []string
	// DenyWrite adds files the agent may not write inside those folders,
	// such as an agent's own config.
	DenyWrite []string
}

type srtSettings struct {
	Network                      srtNetwork `json:"network"`
	Filesystem                   filesystem `json:"filesystem"`
	EnableWeakerNetworkIsolation bool       `json:"enableWeakerNetworkIsolation"`
}

type srtNetwork struct {
	AllowedDomains []string `json:"allowedDomains"`
	DeniedDomains  []string `json:"deniedDomains"`
	HTTPProxyPort  int      `json:"httpProxyPort"`
	SOCKSProxyPort int      `json:"socksProxyPort"`
}

// SrtSettings returns the settings file for Anthropic's sandbox runtime
// (srt), which uses the same sandbox as Claude Code. With the proxy ports
// set, Opfence decides every connection; the empty domain list only
// matters if srt ever ignored the ports, in which case it denies all.
func SrtSettings(o SrtOptions) ([]byte, error) {
	deny := append([]string{}, o.DenyRead...)
	if o.Paths.StateDir != "" {
		deny = append([]string{o.Paths.StateDir}, deny...)
	}
	s := srtSettings{
		Network: srtNetwork{AllowedDomains: []string{}, DeniedDomains: []string{}, HTTPProxyPort: o.HTTPPort, SOCKSProxyPort: o.SOCKSPort},
		Filesystem: filesystem{
			DenyRead:   nonNil(deny),
			AllowWrite: nonNil(o.AllowWrite),
			DenyWrite:  append(pathsOf(o.Paths.protectedWrites()), o.DenyWrite...),
		},
		EnableWeakerNetworkIsolation: o.GOOS == "darwin",
	}
	out, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(out, '\n'), nil
}

// LinuxSecretSockets returns the existing Unix socket paths through which a
// process reaches the Linux keychain (the session D-Bus and
// gnome-keyring's control folder). An abstract D-Bus address needs no entry:
// the sandbox's network namespace already cuts it off.
func LinuxSecretSockets(getenv func(string) string) []string {
	var out []string
	add := func(p string) {
		if p == "" || !filepath.IsAbs(p) {
			return
		}
		if _, err := os.Lstat(p); err != nil {
			return
		}
		for _, x := range out {
			if x == p {
				return
			}
		}
		out = append(out, p)
	}
	for _, addr := range strings.Split(getenv("DBUS_SESSION_BUS_ADDRESS"), ";") {
		rest, ok := strings.CutPrefix(strings.TrimSpace(addr), "unix:")
		if !ok {
			continue
		}
		for _, kv := range strings.Split(rest, ",") {
			if p, ok := strings.CutPrefix(kv, "path="); ok {
				add(p)
			}
		}
	}
	if rt := getenv("XDG_RUNTIME_DIR"); rt != "" {
		add(filepath.Join(rt, "bus"))
		add(filepath.Join(rt, "keyring"))
	}
	return out
}

// ProxyEnv points HTTP clients at an Opfence listener. Localhost stays
// direct: the agent's own local servers and IDE connection are not APIs.
// NODE_USE_ENV_PROXY makes Node's built-in fetch honour the variables.
func ProxyEnv(httpAddr string) map[string]string {
	u := "http://" + httpAddr
	env := map[string]string{
		"HTTP_PROXY": u, "HTTPS_PROXY": u, "http_proxy": u, "https_proxy": u,
		"NO_PROXY": "localhost,127.0.0.1,::1", "no_proxy": "localhost,127.0.0.1,::1",
		"NODE_USE_ENV_PROXY": "1",
	}
	// gcloud (and gsutil) use their own proxy properties before
	// HTTPS_PROXY, and a corporate setup or a gcloud config file may set
	// them; these variables override both.
	if host, port, err := net.SplitHostPort(httpAddr); err == nil {
		env["CLOUDSDK_PROXY_TYPE"], env["CLOUDSDK_PROXY_ADDRESS"], env["CLOUDSDK_PROXY_PORT"] = "http", host, port
	}
	return env
}

// CAEnv points TLS clients at Opfence's CA. Variables that replace a
// tool's trust store get the bundle (system roots plus Opfence's CA);
// NODE_EXTRA_CA_CERTS adds to Node's own roots, so it gets the CA alone.
// Without a bundle (no system roots file, as on Windows) only the additive
// variable is set, because a replacing one would break every other host.
func CAEnv(caFile, bundleFile string) map[string]string {
	env := map[string]string{"NODE_EXTRA_CA_CERTS": caFile}
	if bundleFile != "" {
		// CLOUDSDK_CORE_CUSTOM_CA_CERTS_FILE is gcloud's (and gsutil's)
		// core/custom_ca_certs_file property, which it reads instead of
		// REQUESTS_CA_BUNDLE.
		for _, k := range []string{"SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "GIT_SSL_CAINFO", "AWS_CA_BUNDLE", "DENO_CERT", "CLOUDSDK_CORE_CUSTOM_CA_CERTS_FILE"} {
			env[k] = bundleFile
		}
	}
	return env
}

// SetEnv returns environ with vars set, replacing earlier values. Names
// compare case-insensitively on Windows, as the OS does.
func SetEnv(environ []string, vars map[string]string, windows bool) []string {
	norm := func(k string) string {
		if windows {
			return strings.ToUpper(k)
		}
		return k
	}
	set := map[string]bool{}
	for k := range vars {
		set[norm(k)] = true
	}
	out := make([]string, 0, len(environ)+len(vars))
	for _, kv := range environ {
		k, _, _ := strings.Cut(kv, "=")
		if !set[norm(k)] {
			out = append(out, kv)
		}
	}
	keys := make([]string, 0, len(vars))
	for k := range vars {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	seen := map[string]bool{}
	for _, k := range keys {
		if seen[norm(k)] {
			continue // on Windows HTTP_PROXY and http_proxy are one variable
		}
		seen[norm(k)] = true
		out = append(out, k+"="+vars[k])
	}
	return out
}

// Port returns the port of a listener address such as 127.0.0.1:8080.
func Port(addr string) int {
	i := strings.LastIndexByte(addr, ':')
	n, _ := strconv.Atoi(addr[i+1:])
	return n
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
