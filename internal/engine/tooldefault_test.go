package engine

import (
	"testing"

	"github.com/rakeshnitb23/opfence/internal/catalog"
	"github.com/rakeshnitb23/opfence/internal/classes"
	"github.com/rakeshnitb23/opfence/internal/policy"
)

func lambdaTool(t *testing.T, user, repo *policy.File, tool string, args map[string]any) Evaluation {
	t.Helper()
	c, err := catalog.Embedded()
	if err != nil {
		t.Fatal(err)
	}
	e := New(c, policy.Resolve(user, repo))
	return e.EvaluateTool(c.Provider("aws-lambda-tool-mcp"), tool, args).Evaluations[0]
}

// A server whose tools the user names decides each tool by its provider's
// defaults.mcp_tools, as a rule of its own with the tool as resource.
func TestToolDefault(t *testing.T) {
	ev := lambdaTool(t, nil, nil, "orders_lookup", map[string]any{"parameters": map[string]any{"id": "42"}})
	if ev.Rule == nil || ev.Rule.ID != "aws-lambda-tool-mcp.tool.orders_lookup" || ev.Rule.Status != catalog.ToolDefault {
		t.Fatalf("rule: %+v", ev.Rule)
	}
	if ev.Class != classes.Irreversible || ev.Decision != classes.Confirm || ev.Resource != "orders_lookup" {
		t.Fatalf("got %s %s resource %q (%s)", ev.Class, ev.Decision, ev.Resource, ev.ClassSource)
	}
	if ev.Card != "AWS Lambda Tool MCP tool orders_lookup" {
		t.Fatalf("card %q", ev.Card)
	}

	// A name that could not be part of a rule id keeps unknown.
	for _, tool := range []string{"bad*name", "a/b", "", "[x]", "?"} {
		if ev := lambdaTool(t, nil, nil, tool, nil); ev.Rule != nil || ev.Class != classes.Unknown {
			t.Errorf("%q: rule %v class %s", tool, ev.Rule, ev.Class)
		}
	}
}

func TestToolDefaultPolicy(t *testing.T) {
	// The user's config can allow one function by its rule id.
	user := &policy.File{Rules: []policy.RuleOverride{{Rule: "aws-lambda-tool-mcp.tool.orders_lookup", Decision: classes.Allow}}}
	if ev := lambdaTool(t, user, nil, "orders_lookup", nil); ev.Decision != classes.Allow {
		t.Fatalf("user override: %s (%s)", ev.Decision, ev.DecisionSource)
	}
	if ev := lambdaTool(t, user, nil, "orders_refund", nil); ev.Decision != classes.Confirm {
		t.Fatalf("another function: %s (%s)", ev.Decision, ev.DecisionSource)
	}
	// The repository's opfence.yaml can only make it stricter.
	repo := &policy.File{Path: "opfence.yaml", Rules: []policy.RuleOverride{{Rule: "aws-lambda-tool-mcp.tool.*", Decision: classes.Allow}}}
	if ev := lambdaTool(t, nil, repo, "orders_refund", nil); ev.Decision != classes.Confirm {
		t.Fatalf("repo override loosened: %s (%s)", ev.Decision, ev.DecisionSource)
	}
	deny := &policy.File{Path: "opfence.yaml", Rules: []policy.RuleOverride{{Rule: "aws-lambda-tool-mcp.tool.orders_refund", Decision: classes.Deny}}}
	if ev := lambdaTool(t, nil, deny, "orders_refund", nil); ev.Decision != classes.Deny {
		t.Fatalf("repo deny: %s (%s)", ev.Decision, ev.DecisionSource)
	}

	// Environments map function names with the argument path "tool", which
	// comes from the tool name, never from an argument called tool.
	envs := &policy.File{Environments: map[string]map[string]map[string][]string{
		policy.Development: {"aws-lambda-tool-mcp": {catalog.ToolArg: {"orders_dev"}}},
	}}
	if ev := lambdaTool(t, envs, nil, "orders_dev", nil); ev.Environment != policy.Development || ev.Decision != classes.Ask {
		t.Fatalf("mapped function: %s %s (%s)", ev.Environment, ev.Decision, ev.EnvSource)
	}
	spoof := map[string]any{"tool": "orders_dev", "parameters": map[string]any{"tool": "orders_dev"}}
	if ev := lambdaTool(t, envs, nil, "orders_prod", spoof); ev.Environment != policy.Production || ev.Resource != "orders_prod" {
		t.Fatalf("argument named tool decided: %s resource %q (%s)", ev.Environment, ev.Resource, ev.EnvSource)
	}
}

// Providers without the default keep unknown for tools no rule names.
func TestNoToolDefault(t *testing.T) {
	c, err := catalog.Embedded()
	if err != nil {
		t.Fatal(err)
	}
	e := New(c, policy.Resolve(nil, nil))
	ev := e.EvaluateTool(c.Provider("terraform-mcp"), "brand_new_tool", nil).Evaluations[0]
	if ev.Rule != nil || ev.Class != classes.Unknown {
		t.Fatalf("rule %v class %s", ev.Rule, ev.Class)
	}
}
