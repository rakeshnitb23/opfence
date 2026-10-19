package launch

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strings"
)

// CodexServer is one MCP server as `codex mcp list --json` prints it.
type CodexServer struct {
	Name      string `json:"name"`
	Enabled   bool   `json:"enabled"`
	Transport struct {
		Type string `json:"type"`
		// EnvVars are names (strings) or {name, source} tables.
		EnvVars []any `json:"env_vars"`
	} `json:"transport"`
}

// ParseCodexServers reads `codex mcp list --json`.
func ParseCodexServers(data []byte) ([]CodexServer, error) {
	var out []CodexServer
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("reading codex mcp list --json: %w", err)
	}
	return out, nil
}

// CodexOptions configures the -c options opfence run passes to Codex.
type CodexOptions struct {
	Servers []CodexServer
	// ServersUnknown says the server list could not be read; the hook then
	// covers every MCP tool.
	ServersUnknown bool
	// EnvVars are the variables Codex must pass to stdio MCP servers: the
	// proxy and CA variables and those holding placeholders. Codex gives
	// stdio servers a fixed environment without them otherwise.
	EnvVars []string
	// HookCommand runs opfence hook codex.
	HookCommand string
}

// codexHookTimeout is the hooks' timeout in seconds. It is part of the
// trust hash.
const codexHookTimeout = 30

var codexServerName = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

// CodexConfig returns Codex's -c options: for each enabled stdio server the
// variables it must get and approval prompts for every tool, so that a call
// Opfence asks about reaches Codex's prompt instead of its own automatic
// approval; and the hooks for those servers' tools with the trust for
// them. Remote servers are left to the proxy, which sees their traffic, so
// nothing is asked twice. It also returns the names of servers it had to
// skip (a name -c cannot address).
func CodexConfig(o CodexOptions) (args []string, skipped []string) {
	var names []string
	for _, s := range o.Servers {
		if s.Transport.Type != "stdio" {
			continue
		}
		if !codexServerName.MatchString(s.Name) {
			skipped = append(skipped, s.Name)
			continue
		}
		names = append(names, s.Name)
		if !s.Enabled {
			continue
		}
		var vars []string
		seen := map[string]bool{}
		for _, v := range s.Transport.EnvVars {
			switch v := v.(type) {
			case string:
				seen[v] = true
				vars = append(vars, tomlString(v))
			case map[string]any:
				name, _ := v["name"].(string)
				seen[name] = true
				vars = append(vars, tomlInline(v))
			}
		}
		for _, name := range o.EnvVars {
			if !seen[name] {
				seen[name] = true
				vars = append(vars, tomlString(name))
			}
		}
		prefix := "mcp_servers." + s.Name + "."
		args = append(args,
			"-c", prefix+"env_vars=["+strings.Join(vars, ",")+"]",
			"-c", prefix+`default_tools_approval_mode="prompt"`)
	}
	// Tool names are mcp__<server>__<tool>. A server whose name could not
	// be read safely widens the hook to every MCP tool.
	matcher := "^mcp__"
	switch {
	case !o.ServersUnknown && len(skipped) == 0 && len(names) == 0:
		return args, skipped
	case !o.ServersUnknown && len(skipped) == 0:
		matcher = "^mcp__(?:" + strings.Join(names, "|") + ")__"
	}
	for _, event := range []string{"PreToolUse", "PermissionRequest"} {
		args = append(args, "-c", "hooks."+event+"="+codexHookTOML(matcher, o.HookCommand))
	}
	args = append(args, "-c", "hooks.state={"+
		tomlString(codexHookKey("pre_tool_use"))+"={trusted_hash="+tomlString(CodexHookHash("pre_tool_use", matcher, o.HookCommand))+"},"+
		tomlString(codexHookKey("permission_request"))+"={trusted_hash="+tomlString(CodexHookHash("permission_request", matcher, o.HookCommand))+"}}")
	return args, skipped
}

func codexHookTOML(matcher, command string) string {
	return fmt.Sprintf(`[{matcher=%s,hooks=[{type="command",command=%s,timeout=%d}]}]`, tomlString(matcher), tomlString(command), codexHookTimeout)
}

// codexHookKey is Codex's key for the first hook of an event in the -c
// layer, under which its trust is recorded.
func codexHookKey(event string) string {
	return "/<session-flags>/config.toml:" + event + ":0:0"
}

// CodexHookHash is the trust hash Codex computes for Opfence's hook: the
// SHA-256 of the hook's normalized identity as JSON with sorted keys
// (codex-rs hooks/src/engine/discovery.rs hook_hash and
// config/src/fingerprint.rs version_for_toml). Codex runs a hook from
// config only when its recorded trusted hash matches.
func CodexHookHash(event, matcher, command string) string {
	identity := map[string]any{
		"event_name": event,
		"matcher":    matcher,
		"hooks": []any{map[string]any{
			"async":   false,
			"command": command,
			"timeout": codexHookTimeout,
			"type":    "command",
		}},
	}
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(identity) // maps encode with sorted keys
	sum := sha256.Sum256(bytes.TrimSuffix(b.Bytes(), []byte("\n")))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// tomlString writes s as a TOML basic string. JSON's string escapes are a
// subset of TOML's.
func tomlString(s string) string {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(s)
	return strings.TrimSuffix(b.String(), "\n")
}

// tomlInline writes a table of strings as a TOML inline table.
func tomlInline(m map[string]any) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		if v, ok := m[k].(string); ok {
			parts = append(parts, tomlString(k)+"="+tomlString(v))
		}
	}
	return "{" + strings.Join(parts, ",") + "}"
}
