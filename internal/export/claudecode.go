package export

import (
	"encoding/json"
	"sort"

	"github.com/rakeshnitb23/opfence/internal/catalog"
	"github.com/rakeshnitb23/opfence/internal/classes"
	"github.com/rakeshnitb23/opfence/internal/policy"
)

// ClaudeCodeOptions configures the Claude Code export.
type ClaudeCodeOptions struct {
	// HookCommand runs the PreToolUse hook; default "opfence hook claude-code".
	HookCommand string
}

// claudeSettings is the fragment written for Claude Code's settings.json.
type claudeSettings struct {
	Permissions claudePermissions      `json:"permissions"`
	Hooks       map[string][]hookGroup `json:"hooks"`
}

type claudePermissions struct {
	Deny []string `json:"deny"`
	Ask  []string `json:"ask"`
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

// ClaudeCode writes a Claude Code settings fragment.
//
// The PreToolUse hook decides every MCP tool call live, with its arguments
// and environment. Claude Code applies deny and ask rules whatever a hook
// returns, so a static rule that is stricter than the hook's answer would
// override it (an ask rule on execute_sql would prompt even for a SELECT).
// The static rules are therefore only the floor: the decision a tool gets
// for every argument in every environment. They keep the dangerous tools
// gated if the hook is ever removed, and never contradict it.
func ClaudeCode(c *catalog.Catalog, p *policy.Effective, opts ClaudeCodeOptions) ([]byte, error) {
	if p == nil {
		p = policy.Resolve(nil, nil)
	}
	if opts.HookCommand == "" {
		opts.HookCommand = "opfence hook claude-code"
	}
	s := claudeSettings{
		Permissions: claudePermissions{Deny: []string{}, Ask: []string{}},
		Hooks: map[string][]hookGroup{"PreToolUse": {{
			Matcher: "^mcp__",
			Hooks: []hookHandler{{
				Type: "command", Command: opts.HookCommand, Timeout: 30,
				// A hook that fails or times out must block, not let the call through.
				OnFailure: "block",
			}},
		}}},
	}
	for _, prov := range c.Providers {
		names := MCPServerNames(p, prov)
		for _, r := range sortedRules(p, prov) {
			var tools []string
			switch {
			case r.Match.MCP != nil:
				for _, n := range names {
					tools = append(tools, "mcp__"+n+"__"+r.Match.MCP.Tool)
				}
			case r.Match.CLI != nil:
				tools = []string{"Bash(" + r.Match.CLI.Command + " *)"}
			default:
				continue
			}
			switch Floor(p, r) {
			case classes.Deny:
				s.Permissions.Deny = append(s.Permissions.Deny, tools...)
			case classes.Ask, classes.Confirm:
				s.Permissions.Ask = append(s.Permissions.Ask, tools...)
			}
		}
	}
	sort.Strings(s.Permissions.Deny)
	sort.Strings(s.Permissions.Ask)
	out, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(out, '\n'), nil
}
