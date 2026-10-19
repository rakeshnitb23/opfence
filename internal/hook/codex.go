package hook

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/rakeshnitb23/opfence/internal/classes"
)

// CodexInput is the part of Codex's PreToolUse and PermissionRequest hook
// input Opfence reads (codex-rs hooks/schema/generated).
type CodexInput struct {
	HookEventName  string         `json:"hook_event_name"`
	ToolName       string         `json:"tool_name"`
	ToolInput      map[string]any `json:"tool_input"`
	Cwd            string         `json:"cwd"`
	PermissionMode string         `json:"permission_mode"`
}

type codexPreToolUse struct {
	HookSpecificOutput struct {
		HookEventName            string `json:"hookEventName"`
		PermissionDecision       string `json:"permissionDecision"`
		PermissionDecisionReason string `json:"permissionDecisionReason"`
	} `json:"hookSpecificOutput"`
}

type codexPermissionRequest struct {
	HookSpecificOutput struct {
		HookEventName string `json:"hookEventName"`
		Decision      struct {
			Behavior string `json:"behavior"`
			Message  string `json:"message,omitempty"`
		} `json:"decision"`
	} `json:"hookSpecificOutput"`
}

// Codex handles one Codex hook call for an MCP tool. Codex's PreToolUse can
// only deny, and its PermissionRequest (an approval prompt about to be
// shown) can allow or deny; neither can ask. So:
//
//   - deny: both events deny.
//   - allow: PermissionRequest allows, so Codex does not prompt.
//   - ask and confirm: no output, so Codex prompts. When Codex cannot
//     prompt (approval policy never, reported as bypassPermissions)
//     PreToolUse denies instead, since nobody would be asked.
//
// Calls it knows nothing about get no output. Any error is returned; the
// caller must exit 2 with the error on stderr, which Codex takes as a deny.
func Codex(in io.Reader, out io.Writer, engineFor EngineFor) error {
	data, err := io.ReadAll(io.LimitReader(in, MaxInput+1))
	if err != nil {
		return fmt.Errorf("reading hook input: %w", err)
	}
	if len(data) > MaxInput {
		return errors.New("hook input is larger than 4 MiB")
	}
	var input CodexInput
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := dec.Decode(&input); err != nil {
		return fmt.Errorf("hook input is not valid JSON: %w", err)
	}
	if input.HookEventName != "PreToolUse" && input.HookEventName != "PermissionRequest" {
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
	ev := eng.EvaluateTool(prov, tool, input.ToolInput).Evaluations[0]
	_, reason := claudeDecision(ev)

	var o any
	switch {
	case input.HookEventName == "PreToolUse" && ev.Decision == classes.Deny:
		o = codexDeny(reason)
	case input.HookEventName == "PreToolUse" && ev.Decision != classes.Allow && input.PermissionMode == "bypassPermissions":
		o = codexDeny(reason + " Codex is set never to ask (approval policy never), so Opfence denies it.")
	case input.HookEventName == "PermissionRequest" && (ev.Decision == classes.Deny || ev.Decision == classes.Allow):
		var p codexPermissionRequest
		p.HookSpecificOutput.HookEventName = "PermissionRequest"
		p.HookSpecificOutput.Decision.Behavior = "allow"
		if ev.Decision == classes.Deny {
			p.HookSpecificOutput.Decision.Behavior = "deny"
			p.HookSpecificOutput.Decision.Message = reason
		}
		o = p
	default:
		return nil
	}
	enc := json.NewEncoder(out)
	enc.SetEscapeHTML(false)
	return enc.Encode(o)
}

func codexDeny(reason string) codexPreToolUse {
	var p codexPreToolUse
	p.HookSpecificOutput.HookEventName = "PreToolUse"
	p.HookSpecificOutput.PermissionDecision = "deny"
	p.HookSpecificOutput.PermissionDecisionReason = reason
	return p
}
