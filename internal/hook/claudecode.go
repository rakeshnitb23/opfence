// Package hook implements agent hooks that let Opfence decide tool calls the
// proxy never sees, such as MCP servers Claude Code runs outside its sandbox.
package hook

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/rakeshnitb23/opfence/internal/catalog"
	"github.com/rakeshnitb23/opfence/internal/classes"
	"github.com/rakeshnitb23/opfence/internal/engine"
)

// MaxInput caps the hook input read from stdin.
const MaxInput = 4 << 20

// ClaudeCodeInput is the part of Claude Code's PreToolUse hook input Opfence
// reads.
type ClaudeCodeInput struct {
	HookEventName string         `json:"hook_event_name"`
	ToolName      string         `json:"tool_name"`
	ToolInput     map[string]any `json:"tool_input"`
	Cwd           string         `json:"cwd"`
}

type claudeOutput struct {
	HookSpecificOutput struct {
		HookEventName            string `json:"hookEventName"`
		PermissionDecision       string `json:"permissionDecision"`
		PermissionDecisionReason string `json:"permissionDecisionReason"`
	} `json:"hookSpecificOutput"`
}

// EngineFor builds the engine for a hook call; cwd is the project directory
// Claude Code reports, where the repository's opfence.yaml lives.
type EngineFor func(cwd string) (*engine.Engine, error)

// ClaudeCode handles one PreToolUse call: it reads the input, decides MCP
// tool calls for servers in the catalog and writes Claude Code's decision
// JSON. Calls it knows nothing about (other tools, unknown servers) get no
// output, which leaves them to Claude Code's normal permission flow. Any
// error is returned; the caller must exit 2 so Claude Code blocks the call.
func ClaudeCode(in io.Reader, out io.Writer, engineFor EngineFor) error {
	data, err := io.ReadAll(io.LimitReader(in, MaxInput+1))
	if err != nil {
		return fmt.Errorf("reading hook input: %w", err)
	}
	if len(data) > MaxInput {
		return errors.New("hook input is larger than 4 MiB")
	}
	var input ClaudeCodeInput
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := dec.Decode(&input); err != nil {
		return fmt.Errorf("hook input is not valid JSON: %w", err)
	}
	if input.HookEventName != "" && input.HookEventName != "PreToolUse" {
		return nil
	}
	server, tool, ok := SplitMCPToolName(input.ToolName)
	if !ok {
		return nil
	}
	eng, err := engineFor(input.Cwd)
	if err != nil {
		return err
	}
	if id, ok := eng.Policy.Servers[server]; ok && eng.Catalog.Provider(id) == nil {
		return fmt.Errorf("servers: %s maps to %q, which is not a catalog provider", server, id)
	}
	prov := ProviderForServer(eng.Catalog, eng.Policy.Servers, server)
	if prov == nil {
		return nil
	}
	res := eng.EvaluateTool(prov, tool, input.ToolInput)
	ev := res.Evaluations[0]

	var o claudeOutput
	o.HookSpecificOutput.HookEventName = "PreToolUse"
	o.HookSpecificOutput.PermissionDecision, o.HookSpecificOutput.PermissionDecisionReason = claudeDecision(ev)
	enc := json.NewEncoder(out)
	enc.SetEscapeHTML(false)
	return enc.Encode(o)
}

func claudeDecision(ev engine.Evaluation) (string, string) {
	rule := "no catalog rule"
	if ev.Rule != nil {
		rule = ev.Rule.ID
	}
	what := fmt.Sprintf("%s: %s in %s (%s; %s)", ev.Card, ev.Class, ev.Environment, rule, ev.DecisionSource)
	switch ev.Decision {
	case classes.Allow:
		return "allow", "Opfence allows " + what
	case classes.Ask:
		return "ask", "Opfence asks before " + what
	case classes.Confirm:
		target := ev.Resource
		if target == "" {
			target = "the target"
		}
		return "ask", fmt.Sprintf("Opfence needs confirmation: check that %s is the one you mean. %s", target, what)
	default:
		return "deny", "Opfence denies " + what + ". Change your Opfence policy if this should be allowed."
	}
}

// SplitMCPToolName splits Claude Code's "mcp__<server>__<tool>".
func SplitMCPToolName(name string) (server, tool string, ok bool) {
	rest, found := strings.CutPrefix(name, "mcp__")
	if !found {
		return "", "", false
	}
	server, tool, found = strings.Cut(rest, "__")
	if !found || server == "" || tool == "" {
		return "", "", false
	}
	return server, tool, true
}

// ProviderForServer finds the catalog provider for a Claude Code MCP server
// name: the user's servers: aliases first, then the catalog's common names.
// Plugin servers ("plugin_<plugin>_<server>") and claude.ai connectors
// ("claude_ai_<server>") are matched by their server part.
func ProviderForServer(c *catalog.Catalog, aliases map[string]string, server string) *catalog.Provider {
	if id, ok := aliases[server]; ok {
		return c.Provider(id)
	}
	if p := c.ProviderForMCPName(server); p != nil {
		return p
	}
	lower := strings.ToLower(server)
	for _, p := range c.Providers {
		if p.MCP == nil {
			continue
		}
		for _, n := range p.MCP.Names {
			n = strings.ToLower(n)
			if lower == "claude_ai_"+n || (strings.HasPrefix(lower, "plugin_") && strings.HasSuffix(lower, "_"+n)) {
				return p
			}
		}
	}
	return nil
}
