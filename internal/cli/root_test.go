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
