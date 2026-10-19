package hook

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/rakeshnitb23/opfence/internal/classes"
	"github.com/rakeshnitb23/opfence/internal/engine"
	"github.com/rakeshnitb23/opfence/internal/policy"
)

// runCodex runs one Codex hook call and returns what it printed, decoded.
func runCodex(t *testing.T, user *policy.File, event, tool, args, mode string) (map[string]any, error) {
	t.Helper()
	c := embedded(t)
	in := `{"hook_event_name":"` + event + `","tool_name":"` + tool + `","tool_input":` + args + `,"cwd":"/repo","permission_mode":"` + mode + `"}`
	var out bytes.Buffer
	err := Codex(strings.NewReader(in), &out, func(string) (*engine.Engine, error) {
		return engine.New(c, policy.Resolve(user, nil)), nil
	})
	if err != nil || out.Len() == 0 {
		return nil, err
	}
	var o map[string]any
	if jerr := json.Unmarshal(out.Bytes(), &o); jerr != nil {
		t.Fatalf("hook printed invalid JSON %q: %v", out.String(), jerr)
	}
	return o, nil
}

// codexVerdict sums up a hook output: "" (nothing), "deny" from
// PreToolUse, or "allow"/"deny" from PermissionRequest.
func codexVerdict(t *testing.T, event string, o map[string]any) string {
	t.Helper()
	if o == nil {
		return ""
	}
	h := o["hookSpecificOutput"].(map[string]any)
	if h["hookEventName"] != event {
		t.Fatalf("hookEventName %v, want %s", h["hookEventName"], event)
	}
	if event == "PreToolUse" {
		if h["permissionDecisionReason"] == "" {
			t.Fatal("deny without a reason, which Codex rejects")
		}
		return h["permissionDecision"].(string)
	}
	d := h["decision"].(map[string]any)
	if d["behavior"] == "deny" && d["message"] == "" {
		t.Fatal("deny without a message")
	}
	return d["behavior"].(string)
}

func TestCodexDecisions(t *testing.T) {
	deny := &policy.File{Rules: []policy.RuleOverride{{Rule: "supabase-mcp.*", Decision: classes.Deny}}}
	read := `{"project_id":"p1","query":"select 1"}`
	drop := `{"project_id":"p1","query":"drop table users"}`
	cases := []struct {
		name        string
		user        *policy.File
		event, args string
		mode        string
		want        string
	}{
		{"allowed read skips the prompt", nil, "PermissionRequest", read, "default", "allow"},
		{"allowed read, PreToolUse silent", nil, "PreToolUse", read, "default", ""},
		{"confirm leaves the prompt", nil, "PermissionRequest", drop, "default", ""},
		{"confirm passes PreToolUse", nil, "PreToolUse", drop, "default", ""},
		{"confirm without prompts is denied", nil, "PreToolUse", drop, "bypassPermissions", "deny"},
		{"allowed without prompts runs", nil, "PreToolUse", read, "bypassPermissions", ""},
		{"deny in PreToolUse", deny, "PreToolUse", read, "default", "deny"},
		{"deny in PermissionRequest", deny, "PermissionRequest", read, "default", "deny"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			o, err := runCodex(t, tc.user, tc.event, "mcp__supabase__execute_sql", tc.args, tc.mode)
			if err != nil {
				t.Fatal(err)
			}
			if got := codexVerdict(t, tc.event, o); got != tc.want {
				t.Fatalf("got %q, want %q (%v)", got, tc.want, o)
			}
		})
	}
}

func TestCodexIgnores(t *testing.T) {
	for _, tc := range []struct{ event, tool string }{
		{"PreToolUse", "Bash"},
		{"PreToolUse", "mcp__acme-wiki__search"},
		{"PostToolUse", "mcp__supabase__execute_sql"},
	} {
		o, err := runCodex(t, nil, tc.event, tc.tool, `{"query":"drop table users"}`, "bypassPermissions")
		if err != nil || o != nil {
			t.Errorf("%s %s: got %v, %v; want no output", tc.event, tc.tool, o, err)
		}
	}
}

func TestCodexBadInput(t *testing.T) {
	var out bytes.Buffer
	if err := Codex(strings.NewReader("{"), &out, nil); err == nil {
		t.Fatal("invalid JSON did not fail")
	}
}
