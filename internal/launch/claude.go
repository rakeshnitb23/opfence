package launch

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// MinClaudeVersion is the first Claude Code release that ignores a
// repository's proxy ports and unsandboxing settings once --settings turns
// off unsandboxed retries (the admin-required sandbox).
var MinClaudeVersion = [3]int{2, 1, 285}

var versionRe = regexp.MustCompile(`(\d+)\.(\d+)\.(\d+)`)

// ParseVersion finds the first x.y.z in s, as printed by claude --version.
func ParseVersion(s string) ([3]int, bool) {
	m := versionRe.FindStringSubmatch(s)
	if m == nil {
		return [3]int{}, false
	}
	var v [3]int
	for i := range v {
		v[i], _ = strconv.Atoi(m[i+1])
	}
	return v, true
}

// Older reports whether a is an earlier version than b.
func Older(a, b [3]int) bool {
	for i := range a {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return false
}

// FormatVersion writes x.y.z.
func FormatVersion(v [3]int) string { return fmt.Sprintf("%d.%d.%d", v[0], v[1], v[2]) }

// ManagedSettingsPath is where an administrator's Claude Code settings live.
func ManagedSettingsPath(goos string) string {
	switch goos {
	case "darwin":
		return "/Library/Application Support/ClaudeCode/managed-settings.json"
	case "windows":
		return `C:\Program Files\ClaudeCode\managed-settings.json`
	}
	return "/etc/claude-code/managed-settings.json"
}

// UserSettingsPath is the user's Claude Code settings file.
func UserSettingsPath(getenv func(string) string, home string) string {
	if d := getenv("CLAUDE_CONFIG_DIR"); d != "" {
		return filepath.Join(d, "settings.json")
	}
	return filepath.Join(home, ".claude", "settings.json")
}

type settingsProbe struct {
	Sandbox struct {
		ExcludedCommands []string `json:"excludedCommands"`
		Network          struct {
			AllowManagedDomainsOnly bool `json:"allowManagedDomainsOnly"`
			HTTPProxyPort           *int `json:"httpProxyPort"`
		} `json:"network"`
		AllowUnsandboxedCommands *bool `json:"allowUnsandboxedCommands"`
	} `json:"sandbox"`
	Hooks           map[string]json.RawMessage `json:"hooks"`
	Env             map[string]json.RawMessage `json:"env"`
	DisableAllHooks bool                       `json:"disableAllHooks"`
}

// ClaudeSettingsWarnings reads the user's, the administrator's and the
// project's Claude Code settings for anything that would undo what opfence
// run sets up. Unreadable or missing files are skipped.
func ClaudeSettingsWarnings(userFile, managedFile string, projectFiles ...string) []string {
	var out []string
	if s, ok := readSettings(userFile); ok && len(s.Sandbox.ExcludedCommands) > 0 {
		out = append(out, fmt.Sprintf("%s lists sandbox.excludedCommands %q: those commands run outside the sandbox and can reach APIs without Opfence", userFile, s.Sandbox.ExcludedCommands))
	}
	if s, ok := readSettings(managedFile); ok {
		if s.Sandbox.Network.AllowManagedDomainsOnly || s.Sandbox.Network.HTTPProxyPort != nil {
			out = append(out, fmt.Sprintf("%s (your administrator's settings) controls the sandbox proxy, so Claude Code will ignore Opfence's proxy ports", managedFile))
		}
		if v := s.Sandbox.AllowUnsandboxedCommands; v != nil && *v {
			out = append(out, fmt.Sprintf("%s allows unsandboxed commands, which can reach APIs without Opfence", managedFile))
		}
		if len(s.Sandbox.ExcludedCommands) > 0 {
			out = append(out, fmt.Sprintf("%s lists sandbox.excludedCommands %q: those commands run outside the sandbox", managedFile, s.Sandbox.ExcludedCommands))
		}
		if s.DisableAllHooks {
			out = append(out, fmt.Sprintf("%s turns off all hooks, so Opfence's hook cannot decide MCP tool calls", managedFile))
		}
	}
	// A repository's settings, or an earlier agent, can add hooks: they run
	// outside the sandbox with your access. Opfence keeps the sandbox from
	// writing these files but cannot vouch for what is already there.
	for _, f := range projectFiles {
		s, ok := readSettings(f)
		if !ok {
			continue
		}
		if len(s.Hooks) > 0 {
			events := make([]string, 0, len(s.Hooks))
			for e := range s.Hooks {
				events = append(events, e)
			}
			sort.Strings(events)
			out = append(out, fmt.Sprintf("%s adds %s hooks: they run outside the sandbox with your access, so check what they run", f, strings.Join(events, ", ")))
		}
		if len(s.Env) > 0 {
			names := make([]string, 0, len(s.Env))
			for k := range s.Env {
				names = append(names, k)
			}
			sort.Strings(names)
			out = append(out, fmt.Sprintf("%s sets environment variables %s for Claude Code and its MCP servers; Opfence's own proxy, certificate and config variables override them", f, strings.Join(names, ", ")))
		}
	}
	return out
}

func readSettings(path string) (settingsProbe, bool) {
	var s settingsProbe
	data, err := os.ReadFile(path)
	if err != nil {
		return s, false
	}
	return s, json.Unmarshal(data, &s) == nil
}
