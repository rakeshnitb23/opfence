package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func run(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errb bytes.Buffer
	code = Main(args, strings.NewReader(""), &out, &errb)
	return code, out.String(), errb.String()
}

func TestVersion(t *testing.T) {
	code, out, _ := run(t, "version")
	if code != exitOK {
		t.Fatalf("exit %d", code)
	}
	if !strings.HasPrefix(out, "opfence ") {
		t.Fatalf("unexpected output %q", out)
	}
}

func TestUnknownCommand(t *testing.T) {
	code, _, errOut := run(t, "no-such-command")
	if code != exitError {
		t.Fatalf("exit %d, want %d", code, exitError)
	}
	if !strings.Contains(errOut, "unknown command") {
		t.Fatalf("stderr %q", errOut)
	}
}

func TestCatalogValidateEmbedded(t *testing.T) {
	code, out, errOut := run(t, "catalog", "validate")
	if code != exitOK || !strings.Contains(out, "catalog OK") {
		t.Fatalf("exit %d\nstdout %s\nstderr %s", code, out, errOut)
	}
}

func TestCatalogValidateDir(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, dir+"/acme/provider.yaml", "provider: acme\ntitle: Acme\nhosts: [api.acme.dev]\n")
	mustWrite(t, dir+"/acme/x.yaml", "operations:\n  - id: acme.x.delete\n    match: { rest: { method: DELETE, path: /x } }\n    class: nope\n    card: x\n    status: draft\n")
	code, _, errOut := run(t, "--catalog", dir, "catalog", "validate")
	if code != exitFail {
		t.Fatalf("exit %d, want %d", code, exitFail)
	}
	if !strings.Contains(errOut, `acme/x.yaml:2: acme.x.delete: unknown class "nope"`) {
		t.Fatalf("stderr %q", errOut)
	}
}

func TestCatalogList(t *testing.T) {
	code, out, _ := run(t, "catalog", "list", "--provider", "railway", "--class", "irreversible")
	if code != exitOK || !strings.Contains(out, "railway.volume.delete") || !strings.Contains(out, "graphql mutation volumeDelete") {
		t.Fatalf("exit %d, output:\n%s", code, out)
	}
	if code, _, _ := run(t, "catalog", "list", "--class", "fatal"); code != exitError {
		t.Fatalf("bad class accepted, exit %d", code)
	}
	if code, _, _ := run(t, "catalog", "list", "--provider", "nope"); code != exitError {
		t.Fatalf("bad provider accepted, exit %d", code)
	}
	code, out, _ = run(t, "catalog", "providers")
	if code != exitOK || !strings.Contains(out, "backboard.railway.com") {
		t.Fatalf("providers output:\n%s", out)
	}
}

func mustWrite(t *testing.T, path, data string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestExplain(t *testing.T) {
	code, out, errOut := run(t, "--user-config", "/nonexistent", "explain", "../../catalog/railway/fixtures/volume-delete.http")
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	for _, want := range []string{"railway.volume.delete", "irreversible", "CONFIRM", "Delete Railway volume vol-pg-data"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	code, out, _ = run(t, "--user-config", "/nonexistent", "explain", "--json", "../../catalog/railway/fixtures/volume-delete.http")
	if code != exitOK || !strings.Contains(out, `"decision": "confirm"`) {
		t.Errorf("json output:\n%s", out)
	}
	dir := t.TempDir()
	mustWrite(t, dir+"/opfence.yaml", "version: 1\nenvironments:\n  development:\n    railway: { volumeId: [vol-pg-data] }\n")
	mustWrite(t, dir+"/user.yaml", "version: 1\nenvironments:\n  development:\n    railway: { volumeId: [vol-pg-data] }\n")
	code, out, _ = run(t, "--user-config", dir+"/user.yaml", "--policy", dir+"/opfence.yaml", "explain", "../../catalog/railway/fixtures/volume-delete.http")
	if code != exitOK || !strings.Contains(out, "environment development") || !strings.Contains(out, "decision    ASK") {
		t.Errorf("user mapping not applied:\n%s", out)
	}
	if code, _, _ := run(t, "--user-config", "/nonexistent", "--policy", dir+"/missing.yaml", "explain", "x.http"); code != exitError {
		t.Errorf("missing --policy file accepted")
	}
}

func TestTestCommand(t *testing.T) {
	code, out, _ := run(t, "test")
	if code != exitOK || !strings.Contains(out, "0 failed") {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	dir := t.TempDir()
	mustWrite(t, dir+"/acme/provider.yaml", "provider: acme\ntitle: Acme\nhosts: [api.acme.dev]\n")
	mustWrite(t, dir+"/acme/x.yaml", "operations:\n  - id: acme.x.delete\n    match: { rest: { method: DELETE, path: /x } }\n    class: delete\n    card: x\n    status: draft\n    tests: [{ fixture: fixtures/x.http, expect: irreversible }]\n")
	mustWrite(t, dir+"/acme/fixtures/x.http", "DELETE /x HTTP/1.1\nHost: api.acme.dev\n\n")
	code, out, _ = run(t, "--catalog", dir, "test")
	if code != exitFail || !strings.Contains(out, "FAIL  acme.x.delete") {
		t.Fatalf("broken rule passed: exit %d\n%s", code, out)
	}
}

func TestPolicyCheck(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, dir+"/opfence.yaml", "version: 1\ndecisions:\n  production: { irreversible: allow }\n")
	code, out, _ := run(t, "--user-config", "/nonexistent", "--policy", dir+"/opfence.yaml", "policy", "check")
	if code != exitOK || !strings.Contains(out, "warning:") || !strings.Contains(out, "irreversible   ask          ask          confirm") {
		t.Fatalf("exit %d:\n%s", code, out)
	}
}
