package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func runIn(t *testing.T, stdin string, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errb bytes.Buffer
	code = Main(args, strings.NewReader(stdin), &out, &errb)
	return code, out.String(), errb.String()
}

// noUser keeps the developer's own config out of a test.
func noUser(t *testing.T) string {
	return "--user-config=" + filepath.Join(t.TempDir(), "none.yaml")
}

func TestExportTargets(t *testing.T) {
	code, out, errOut := run(t, noUser(t), "export", "--target", "openshell")
	if code != exitOK || !strings.Contains(out, "opfence_railway:") || !strings.Contains(out, "decisions for production") {
		t.Fatalf("openshell: exit %d\n%s%s", code, out, errOut)
	}
	code, out, _ = run(t, noUser(t), "export", "--target", "openshell", "--environment", "development")
	if code != exitOK || !strings.Contains(out, "decisions for development") {
		t.Fatalf("openshell development: exit %d", code)
	}

	path := filepath.Join(t.TempDir(), "settings.json")
	if code, _, errOut := run(t, noUser(t), "export", "--target", "claude-code", "--hook-command", "/usr/local/bin/opfence hook claude-code", "-o", path); code != exitOK {
		t.Fatalf("claude-code: exit %d %s", code, errOut)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var settings struct {
		Permissions struct{ Ask []string }
		Hooks       map[string][]struct {
			Hooks []struct{ Command string }
		}
	}
	if err := json.Unmarshal(data, &settings); err != nil {
		t.Fatal(err)
	}
	if got := settings.Hooks["PreToolUse"][0].Hooks[0].Command; got != "/usr/local/bin/opfence hook claude-code" {
		t.Fatalf("hook command %q", got)
	}
	if !strings.Contains(strings.Join(settings.Permissions.Ask, " "), "mcp__supabase__create_project") {
		t.Fatalf("ask rules %v", settings.Permissions.Ask)
	}

	code, out, _ = run(t, noUser(t), "export", "--target", "mcp-annotations")
	if code != exitOK || !strings.Contains(out, `"execute_sql"`) {
		t.Fatalf("mcp-annotations: exit %d", code)
	}
}

func TestExportErrors(t *testing.T) {
	for _, args := range [][]string{
		{"export"},
		{"export", "--target", "nginx"},
		{"export", "--target", "openshell", "--environment", "qa"},
	} {
		if code, _, _ := run(t, append([]string{noUser(t)}, args...)...); code != exitError {
			t.Errorf("%v: exit %d, want %d", args, code, exitError)
		}
	}
}

func TestHookCommand(t *testing.T) {
	repo := t.TempDir()
	in := `{"hook_event_name":"PreToolUse","tool_name":"mcp__supabase__list_tables","tool_input":{"project_id":"p1"},"cwd":"` + repo + `"}`
	code, out, errOut := runIn(t, in, noUser(t), "hook", "claude-code")
	if code != exitOK || !strings.Contains(out, `"permissionDecision":"allow"`) {
		t.Fatalf("exit %d\n%s%s", code, out, errOut)
	}

	// The repository policy is read from the project Claude Code reports.
	mustWrite(t, filepath.Join(repo, "opfence.yaml"), "version: 1\nrules:\n  - rule: supabase-mcp.database.list-tables\n    decision: deny\n")
	code, out, errOut = runIn(t, in, noUser(t), "hook", "claude-code")
	if code != exitOK || !strings.Contains(out, `"permissionDecision":"deny"`) {
		t.Fatalf("with repo policy: exit %d\n%s%s", code, out, errOut)
	}

	// Errors exit 2, which Claude Code treats as a block.
	code, out, errOut = runIn(t, `{"tool_name":`, noUser(t), "hook", "claude-code")
	if code != 2 || out != "" || !strings.Contains(errOut, "not valid JSON") {
		t.Fatalf("bad input: exit %d\nstdout %q\nstderr %q", code, out, errOut)
	}
	if strings.Contains(errOut, "Usage:") {
		t.Fatalf("usage printed on hook error:\n%s", errOut)
	}
}

func TestPolicyCheckCatalogWarnings(t *testing.T) {
	path := filepath.Join(t.TempDir(), "opfence.yaml")
	mustWrite(t, path, "version: 1\nrules:\n  - rule: supabase-mcp.database.tables\n    decision: deny\n  - rule: github.*\n    decision: ask\nenvironments:\n  production:\n    railwy:\n      projectId: [p1]\n")
	code, out, errOut := run(t, noUser(t), "--policy", path, "policy", "check")
	if code != exitOK {
		t.Fatalf("exit %d %s", code, errOut)
	}
	for _, want := range []string{"rule supabase-mcp.database.tables matches no catalog rule", "environments.production.railwy: no catalog provider"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing warning %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "github.*") {
		t.Errorf("glob that matches rules was flagged:\n%s", out)
	}
}

// Overrides of the rules defaults.mcp_tools makes (<provider>.tool.<tool>)
// match no catalog rule but are not typos.
func TestPolicyCheckToolDefaultOverrides(t *testing.T) {
	path := filepath.Join(t.TempDir(), "opfence.yaml")
	mustWrite(t, path, "version: 1\nrules:\n  - rule: aws-lambda-tool-mcp.tool.orders_lookup\n    decision: deny\n  - rule: aws-lambda-tool-mcp.tool.orders_*\n    decision: deny\n  - rule: aws-lambda-tool-mcp.*\n    decision: deny\n  - rule: terraform-mcp.tool.anything\n    decision: deny\n")
	code, out, errOut := run(t, noUser(t), "--policy", path, "policy", "check")
	if code != exitOK {
		t.Fatalf("exit %d %s", code, errOut)
	}
	if strings.Contains(out, "aws-lambda-tool-mcp") {
		t.Errorf("tool default override flagged:\n%s", out)
	}
	if !strings.Contains(out, "rule terraform-mcp.tool.anything matches no catalog rule") {
		t.Errorf("override of a provider without the default not flagged:\n%s", out)
	}
}

// Hooks load the embedded catalog lazily, and a --catalog folder whole,
// because nothing else has validated it.
func TestHookCatalogLoading(t *testing.T) {
	g := &globalOptions{}
	c, err := g.loadCatalogLazy()
	if err != nil {
		t.Fatal(err)
	}
	if !c.Lazy() {
		t.Error("the embedded catalog is not loaded lazily for hooks")
	}
	g.catalogDir = filepath.Join("..", "..", "catalog")
	c, err = g.loadCatalogLazy()
	if err != nil {
		t.Fatal(err)
	}
	if c.Lazy() {
		t.Error("a --catalog folder was loaded lazily")
	}
}

// The proxy and explain decide requests one at a time, so they load the
// embedded catalog lazily, and decide exactly as a full load does.
func TestLazyEngineDecidesLikeFull(t *testing.T) {
	g := &globalOptions{userConfig: filepath.Join(t.TempDir(), "none.yaml")}
	lazy, err := g.lazyEngine()
	if err != nil {
		t.Fatal(err)
	}
	full, err := g.engine()
	if err != nil {
		t.Fatal(err)
	}
	if !lazy.Catalog.Lazy() || full.Catalog.Lazy() {
		t.Fatalf("lazy %v, full %v", lazy.Catalog.Lazy(), full.Catalog.Lazy())
	}
	for _, c := range []struct{ prov, tool string }{
		{"terraform-mcp", "create_run"}, {"stripe-mcp", "create_refund"}, {"aws-api-mcp", "call_aws"}, {"github-mcp", "delete_file"},
	} {
		args := map[string]any{"cli_command": "aws s3 rm s3://b/k", "run_type": "is_destroy"}
		a := lazy.EvaluateTool(lazy.Catalog.Provider(c.prov), c.tool, args)
		b := full.EvaluateTool(full.Catalog.Provider(c.prov), c.tool, args)
		if a.Decision != b.Decision || a.Evaluations[0].Card != b.Evaluations[0].Card || a.Evaluations[0].Class != b.Evaluations[0].Class {
			t.Errorf("%s %s: lazy %s %s %q, full %s %s %q", c.prov, c.tool, a.Decision, a.Evaluations[0].Class, a.Evaluations[0].Card,
				b.Decision, b.Evaluations[0].Class, b.Evaluations[0].Card)
		}
	}
}
