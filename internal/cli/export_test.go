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
