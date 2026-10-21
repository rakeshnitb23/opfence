package hook

import (
	"bytes"
	"encoding/json"
	"io/fs"
	"path"
	"strings"
	"testing"
	"testing/fstest"

	catalogdata "github.com/rakeshnitb23/opfence/catalog"
	"github.com/rakeshnitb23/opfence/internal/catalog"
	"github.com/rakeshnitb23/opfence/internal/decode"
	"github.com/rakeshnitb23/opfence/internal/engine"
	"github.com/rakeshnitb23/opfence/internal/fixture"
	"github.com/rakeshnitb23/opfence/internal/policy"
	"github.com/rakeshnitb23/opfence/internal/request"
)

// Every MCP tool call in the catalog's fixtures gets exactly the same hook
// output from a lazily loaded catalog, whose rules load on demand, as from
// a full load.
func TestLazyHookMatchesFull(t *testing.T) {
	full := embedded(t)
	lazy, err := catalog.LoadLazy(catalogdata.FS)
	if err != nil {
		t.Fatal(err)
	}
	fullEng := engine.New(full, nil)
	calls := 0
	for _, p := range full.Providers {
		if p.MCP == nil {
			continue
		}
		user := &policy.File{Servers: map[string]string{"opfx": p.ID}}
		for _, r := range p.Rules {
			for _, tc := range r.Tests {
				for _, call := range toolCalls(t, full, fullEng, p, tc.Fixture) {
					input, err := json.Marshal(map[string]any{
						"hook_event_name": "PreToolUse", "tool_name": "mcp__opfx__" + call.tool,
						"tool_input": call.args, "cwd": "/repo",
					})
					if err != nil {
						t.Fatal(err)
					}
					want := hookOutput(t, full, user, input)
					if got := hookOutput(t, lazy, user, input); got != want {
						t.Fatalf("%s %s: lazy hook printed\n%s\nfull hook printed\n%s", r.ID, tc.Fixture, got, want)
					}
					calls++
				}
			}
		}
	}
	if calls < 1000 {
		t.Fatalf("compared only %d tool calls", calls)
	}
	t.Logf("%d tool calls decided alike", calls)
}

type toolCallArgs struct {
	tool string
	args map[string]any
}

// toolCalls returns the MCP tool calls in a fixture: a .json tool call, or
// the tools/call operations of a .http request.
func toolCalls(t *testing.T, c *catalog.Catalog, eng *engine.Engine, p *catalog.Provider, file string) []toolCallArgs {
	t.Helper()
	data, err := fs.ReadFile(c.FS, path.Join(p.Dir, file))
	if err != nil {
		t.Fatal(err)
	}
	if strings.HasSuffix(file, ".json") {
		call, err := fixture.ParseToolCall(data)
		if err != nil {
			t.Fatalf("%s: %v", file, err)
		}
		return []toolCallArgs{{call.Tool, call.Arguments}}
	}
	req, _, err := request.ParseFixture(data)
	if err != nil {
		t.Fatalf("%s: %v", file, err)
	}
	var out []toolCallArgs
	for _, ev := range eng.Evaluate(req).Evaluations {
		if ev.Op.Protocol == decode.MCP && ev.Op.MCPMethod == "tools/call" && ev.Op.Tool != "" {
			out = append(out, toolCallArgs{ev.Op.Tool, ev.Op.Args})
		}
	}
	return out
}

func hookOutput(t *testing.T, c *catalog.Catalog, user *policy.File, input []byte) string {
	t.Helper()
	var out bytes.Buffer
	err := ClaudeCode(bytes.NewReader(input), &out, func(string) (*engine.Engine, error) {
		return engine.New(c, policy.Resolve(user, nil)), nil
	})
	if err != nil {
		return "error: " + err.Error()
	}
	return out.String()
}

// A provider whose rules fail to load blocks the call instead of deciding
// it without them, in both hooks.
func TestLazyLoadErrorBlocks(t *testing.T) {
	m := fstest.MapFS{
		"local-mcp/provider.yaml": {Data: []byte("provider: local-mcp\ntitle: Local\nmcp: { names: [local] }\n")},
		"local-mcp/r.yaml": {Data: []byte("operations:\n  - id: local-mcp.app.destroy\n    match: { mcp: { tool: destroy } }\n" +
			"    class: fatal\n    card: Destroy\n    status: community\n")},
	}
	c, err := catalog.LoadLazy(m)
	if err != nil {
		t.Fatal(err)
	}
	engineFor := func(string) (*engine.Engine, error) { return engine.New(c, nil), nil }
	in := `{"hook_event_name":"PreToolUse","tool_name":"mcp__local__destroy","tool_input":{},"cwd":"/repo"}`
	var out bytes.Buffer
	if err := ClaudeCode(strings.NewReader(in), &out, engineFor); err == nil || out.Len() != 0 {
		t.Fatalf("Claude Code hook: err %v, output %q; want an error and no output", err, out.String())
	}
	in = `{"hook_event_name":"PreToolUse","tool_name":"mcp__local__destroy","tool_input":{},"cwd":"/repo","permission_mode":"default"}`
	if err := Codex(strings.NewReader(in), &out, engineFor); err == nil || out.Len() != 0 {
		t.Fatalf("Codex hook: err %v, output %q; want an error and no output", err, out.String())
	}
	// The engine, asked directly, falls back to unknown.
	res := engine.New(c, nil).EvaluateTool(c.Provider("local-mcp"), "destroy", nil)
	if ev := res.Evaluations[0]; ev.Rule != nil || !strings.Contains(ev.ClassSource, "could not be loaded") {
		t.Fatalf("engine evaluation %+v", ev)
	}
}
