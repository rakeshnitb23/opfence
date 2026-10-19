package launch

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// Agent is what opfence run --srt adds for a coding agent it recognises by
// its command name (docs/ARCHITECTURE.md §8.7). The whole agent runs in the
// sandbox runtime, so its own backend must be reachable, its state folder
// writable, and its own sandbox off.
type Agent struct {
	// Name is the agent's name in messages: Codex, Cursor or Gemini CLI.
	Name string
	// Hosts are its backend hosts (model API, sign-in, telemetry), tunnelled
	// for the session like the built-in passthrough hosts.
	Hosts []string
	// stateDir finds the folder the agent keeps sessions, logs and
	// credentials in.
	stateDir func(home string, getenv func(string) string) string
	// guarded are files and folders (ending in "/") in the state folder
	// that change what the agent runs or trusts when it next starts,
	// perhaps outside Opfence; projectGuarded are the same in the working
	// folder.
	guarded        []string
	projectGuarded []string
	// emptyOK says the agent reads a missing guarded file that the sandbox
	// shows as an empty file (its placeholder for a path it keeps from
	// being created) as if it were missing. Gemini CLI, for one, refuses to
	// start on an empty settings.json.
	emptyOK bool
	// sandboxFlags are the agent's own sandbox flags; when the user gave
	// none, offFlags turn its sandbox off (srt is the sandbox, and a
	// sandbox cannot start inside it).
	sandboxFlags []string
	offFlags     []string
}

var agents = map[string]*Agent{
	"codex": {
		Name: "Codex",
		// codex-rs model-provider-info, login, analytics and otel config.
		Hosts: []string{"api.openai.com", "chatgpt.com", "auth.openai.com", "ab.chatgpt.com"},
		stateDir: func(home string, getenv func(string) string) string {
			if d := getenv("CODEX_HOME"); d != "" {
				return d
			}
			return filepath.Join(home, ".codex")
		},
		// config.toml and hooks.json hold hooks and their trust (the user
		// layer is the one Codex trusts hook hashes from) and MCP server
		// commands; rules approve shell commands; .env is loaded into
		// Codex's environment. A trusted project's .codex folder has its
		// own config, hooks and rules.
		guarded:        []string{"config.toml", "hooks.json", ".env", "requirements.toml", "rules/"},
		projectGuarded: []string{".codex/config.toml", ".codex/hooks.json", ".codex/rules/"},
		// Checked with Codex 0.163.0 under srt.
		emptyOK:      true,
		sandboxFlags: []string{"-s", "--sandbox", "--full-auto", "--dangerously-bypass-approvals-and-sandbox", "--yolo"},
		offFlags:     []string{"-s", "danger-full-access"},
	},
	"cursor": {
		Name: "Cursor",
		// Cursor's network configuration page; it pins certificates.
		Hosts: []string{"cursor.com", "*.cursor.com", "*.cursor.sh", "*.cursorapi.com", "*.cursor-cdn.com"},
		stateDir: func(home string, getenv func(string) string) string {
			if d := getenv("CURSOR_CONFIG_DIR"); d != "" {
				return d
			}
			return filepath.Join(home, ".cursor")
		},
		guarded:        []string{"cli-config.json", "hooks.json", "mcp.json", "mcp-approvals.json", "sandbox.json"},
		projectGuarded: []string{".cursor/cli.json", ".cursor/hooks.json", ".cursor/mcp.json", ".cursor/sandbox.json"},
		sandboxFlags:   []string{"--sandbox"},
		offFlags:       []string{"--sandbox", "disabled"},
	},
	"gemini": {
		Name:  "Gemini CLI",
		Hosts: []string{"generativelanguage.googleapis.com", "cloudcode-pa.googleapis.com", "play.googleapis.com", "oauth2.googleapis.com"},
		stateDir: func(home string, _ func(string) string) string {
			return filepath.Join(home, ".gemini")
		},
		// settings.json holds hooks and MCP servers.
		guarded:        []string{"settings.json"},
		projectGuarded: []string{".gemini/settings.json"},
	},
}

// AgentFor returns the preset for a command, or nil.
func AgentFor(command string) *Agent {
	name := strings.TrimSuffix(filepath.Base(command), ".exe")
	switch name {
	case "cursor-agent", "agent":
		name = "cursor"
	}
	return agents[name]
}

// IsCodex reports whether a is Codex's preset.
func (a *Agent) IsCodex() bool { return a == agents["codex"] }

// StateDir is the agent's state folder, which the sandbox may write.
func (a *Agent) StateDir(home string, getenv func(string) string) string {
	return a.stateDir(home, getenv)
}

// Guard prepares the agent's state folder and returns the paths the sandbox
// may not write (deny) and those it cannot keep from being created, which
// opfence run checks after the session (watch).
//
// A path the sandbox runtime keeps from being created is shown inside the
// sandbox as an empty file at its first missing component. That is
// harmless where a whole folder is missing (the agent sees no config
// there), so such paths are denied. A missing folder whose parent exists
// is created empty, as the agent itself would. A missing file whose folder
// exists is denied only when the agent reads an empty file as missing;
// otherwise it is watched.
func (a *Agent) Guard(home, cwd string, getenv func(string) string) (deny, watch []string, err error) {
	dir := a.StateDir(home, getenv)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, nil, err
	}
	var paths []string
	for _, f := range a.guarded {
		paths = append(paths, filepath.Join(dir, filepath.FromSlash(f))+tail(f))
	}
	for _, f := range a.projectGuarded {
		paths = append(paths, filepath.Join(cwd, filepath.FromSlash(f))+tail(f))
	}
	for _, p := range paths {
		folder := strings.HasSuffix(p, "/")
		p = strings.TrimSuffix(p, "/")
		if _, err := os.Lstat(p); err == nil {
			deny = append(deny, p)
			continue
		}
		if _, err := os.Stat(filepath.Dir(p)); err != nil {
			deny = append(deny, p)
			continue
		}
		switch {
		case folder:
			if err := os.Mkdir(p, 0o700); err != nil {
				return nil, nil, err
			}
			deny = append(deny, p)
		case a.emptyOK:
			deny = append(deny, p)
		default:
			watch = append(watch, p)
		}
	}
	return deny, watch, nil
}

func tail(f string) string {
	if strings.HasSuffix(f, "/") {
		return "/"
	}
	return ""
}

// Env is what the agent needs besides the proxy and CA variables every
// child gets.
func (a *Agent) Env(caFile, bundleFile string) map[string]string {
	env := map[string]string{}
	if a.IsCodex() {
		// Codex reads its own variable before SSL_CERT_FILE and adds the
		// file to its native roots, so the CA alone is enough.
		env["CODEX_CA_CERTIFICATE"] = caFile
	}
	return env
}

// Args returns args (the agent's arguments, without the command) with the
// agent's sandbox turned off, unless the user chose a sandbox setting, and
// extra global options; both go first, before any subcommand.
func (a *Agent) Args(args []string, extra []string) []string {
	var front []string
	if len(a.offFlags) > 0 && !hasFlag(args, a.sandboxFlags) {
		front = append(front, a.offFlags...)
	}
	front = append(front, extra...)
	return append(front, args...)
}

// hasFlag reports whether args hold one of flags, as "-f", "--flag" or
// "--flag=value", before a "--".
func hasFlag(args, flags []string) bool {
	for _, a := range args {
		if a == "--" {
			return false
		}
		name, _, _ := strings.Cut(a, "=")
		if slices.Contains(flags, name) {
			return true
		}
	}
	return false
}
