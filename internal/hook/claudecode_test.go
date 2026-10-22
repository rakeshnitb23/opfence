package hook

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/rakeshnitb23/opfence/internal/catalog"
	"github.com/rakeshnitb23/opfence/internal/classes"
	"github.com/rakeshnitb23/opfence/internal/engine"
	"github.com/rakeshnitb23/opfence/internal/policy"
)

func embedded(t *testing.T) *catalog.Catalog {
	t.Helper()
	c, err := catalog.Embedded()
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// runHook runs one hook call and returns Claude Code's decision and reason,
// or "" when the hook printed nothing.
func runHook(t *testing.T, user *policy.File, input string) (decision, reason string, err error) {
	t.Helper()
	c := embedded(t)
	var out bytes.Buffer
	err = ClaudeCode(strings.NewReader(input), &out, func(string) (*engine.Engine, error) {
		return engine.New(c, policy.Resolve(user, nil)), nil
	})
	if err != nil || out.Len() == 0 {
		return "", "", err
	}
	var o claudeOutput
	if jerr := json.Unmarshal(out.Bytes(), &o); jerr != nil {
		t.Fatalf("hook printed invalid JSON %q: %v", out.String(), jerr)
	}
	if o.HookSpecificOutput.HookEventName != "PreToolUse" {
		t.Fatalf("hookEventName %q", o.HookSpecificOutput.HookEventName)
	}
	return o.HookSpecificOutput.PermissionDecision, o.HookSpecificOutput.PermissionDecisionReason, nil
}

func toolCall(tool, args string) string {
	return `{"hook_event_name":"PreToolUse","tool_name":"` + tool + `","tool_input":` + args + `,"cwd":"/repo"}`
}

func TestDecisions(t *testing.T) {
	cases := []struct {
		name, tool, args, want, reason string
	}{
		{"read SQL", "mcp__supabase__execute_sql", `{"project_id":"p1","query":"select 1"}`, "allow", "Opfence allows"},
		{"destructive SQL", "mcp__supabase__execute_sql", `{"project_id":"p1","query":"drop table users"}`, "ask", "Opfence needs confirmation: check that"},
		{"the SQL in the reason", "mcp__supabase__execute_sql", `{"project_id":"p1","query":"/* tidy */ delete from orders"}`, "ask", "Run SQL on project p1: DELETE from orders (every row) — irreversible in production"},
		{"delete", "mcp__supabase__delete_branch", `{"branch_id":"br1"}`, "ask", "Opfence asks before"},
		{"money", "mcp__supabase__create_project", `{"name":"x"}`, "ask", "money"},
		{"unknown tool", "mcp__supabase__brand_new_tool", `{}`, "ask", "no catalog rule"},
		{"claude.ai connector", "mcp__claude_ai_Supabase__list_tables", `{"project_id":"p1"}`, "allow", ""},
		{"plugin server", "mcp__plugin_supabase_supabase__list_tables", `{"project_id":"p1"}`, "allow", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d, reason, err := runHook(t, nil, toolCall(tc.tool, tc.args))
			if err != nil {
				t.Fatal(err)
			}
			if d != tc.want || !strings.Contains(reason, tc.reason) {
				t.Fatalf("got %s %q, want %s containing %q", d, reason, tc.want, tc.reason)
			}
		})
	}
}

func TestDenyNamesThePolicy(t *testing.T) {
	user := &policy.File{Rules: []policy.RuleOverride{{Rule: "supabase-mcp.*", Decision: classes.Deny}}}
	d, reason, err := runHook(t, user, toolCall("mcp__supabase__list_tables", `{"project_id":"p1"}`))
	if err != nil {
		t.Fatal(err)
	}
	if d != "deny" || !strings.Contains(reason, "Change your Opfence policy") {
		t.Fatalf("got %s %q", d, reason)
	}
}

func TestNoOutput(t *testing.T) {
	for name, in := range map[string]string{
		"built-in tool":   toolCall("Bash", `{"command":"ls"}`),
		"unknown server":  toolCall("mcp__acme-wiki__search", `{}`),
		"other event":     `{"hook_event_name":"PostToolUse","tool_name":"mcp__supabase__execute_sql","tool_input":{}}`,
		"malformed name":  toolCall("mcp__supabase", `{}`),
		"empty tool part": toolCall("mcp__supabase__", `{}`),
	} {
		d, _, err := runHook(t, nil, in)
		if err != nil || d != "" {
			t.Errorf("%s: got %q, %v; want no output", name, d, err)
		}
	}
}

func TestAlias(t *testing.T) {
	user := &policy.File{Servers: map[string]string{"db-prod": "supabase-mcp"}}
	d, _, err := runHook(t, user, toolCall("mcp__db-prod__delete_branch", `{"branch_id":"br1"}`))
	if err != nil || d != "ask" {
		t.Fatalf("got %q, %v; want ask", d, err)
	}
	user = &policy.File{Servers: map[string]string{"db-prod": "no-such-provider"}}
	if _, _, err := runHook(t, user, toolCall("mcp__db-prod__delete_branch", `{}`)); err == nil {
		t.Fatal("alias to a missing provider was accepted")
	}
}

func TestBadInputIsAnError(t *testing.T) {
	for name, in := range map[string]string{
		"invalid JSON": `{"tool_name":`,
		"too large":    `{"tool_input":{"x":"` + strings.Repeat("a", MaxInput) + `"}}`,
	} {
		if _, _, err := runHook(t, nil, in); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
}

func TestSplitMCPToolName(t *testing.T) {
	s, tool, ok := SplitMCPToolName("mcp__my_server__do__thing")
	if !ok || s != "my_server" || tool != "do__thing" {
		t.Fatalf("got %q %q %v", s, tool, ok)
	}
}
