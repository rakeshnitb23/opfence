package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rakeshnitb23/opfence/internal/secrets"
)

func memoryStore(t *testing.T) *secrets.Memory {
	t.Helper()
	m := &secrets.Memory{}
	old := openStore
	openStore = func() secrets.Store { return m }
	t.Cleanup(func() { openStore = old })
	return m
}

func TestInitAndSecrets(t *testing.T) {
	memoryStore(t)
	dir := t.TempDir()
	tok := "ghp" + "_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789" // assembled so scanners skip it
	orig := "GITHUB_TOKEN=" + tok + "\nAWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
	mustWrite(t, filepath.Join(dir, ".env"), orig)

	// Without a terminal or --yes, init only shows the plan.
	code, out, _ := run(t, "init", "--dir", dir)
	flat := strings.Join(strings.Fields(out), " ")
	if code != exitOK || !strings.Contains(flat, "move .env:1 GITHUB_TOKEN github") || !strings.Contains(flat, "skip .env:2 AWS_ACCESS_KEY_ID") || !strings.Contains(out, "--yes") {
		t.Fatalf("plan: exit %d\n%s", code, out)
	}
	if data, _ := os.ReadFile(filepath.Join(dir, ".env")); string(data) != orig {
		t.Fatal("plan changed the file")
	}

	code, out, errOut := run(t, "init", "--dir", dir, "--yes")
	if code != exitOK || !strings.Contains(out, "wrote placeholders to .env") {
		t.Fatalf("apply: exit %d\n%s%s", code, out, errOut)
	}
	data, _ := os.ReadFile(filepath.Join(dir, ".env"))
	if strings.Contains(string(data), tok) || !strings.HasPrefix(string(data), "GITHUB_TOKEN=ghp_") {
		t.Fatalf(".env after init:\n%s", data)
	}

	code, out, _ = run(t, "secrets", "list")
	if code != exitOK || !strings.Contains(out, "github/GITHUB_TOKEN") || strings.Contains(out, tok) {
		t.Fatalf("list: %s", out)
	}
	if code, out, _ := run(t, "init", "--dir", dir, "--yes"); code != exitOK || !strings.Contains(out, "1 already protected") || !strings.Contains(out, "Nothing to move") {
		t.Fatalf("second init: %s", out)
	}
	if code, _, errOut := run(t, "secrets", "rm", "github/GITHUB_TOKEN"); code != exitError || !strings.Contains(errOut, "init --undo") {
		t.Fatalf("rm with placeholder in use: exit %d %s", code, errOut)
	}
	if code, out, _ := run(t, "init", "--dir", dir, "--undo"); code != exitOK || !strings.Contains(out, "restored real values in .env") {
		t.Fatalf("undo: %s", out)
	}
	if data, _ := os.ReadFile(filepath.Join(dir, ".env")); string(data) != orig {
		t.Fatalf("undo left:\n%s", data)
	}
	if code, out, _ := run(t, "secrets", "rm", "github/GITHUB_TOKEN"); code != exitOK || !strings.Contains(out, "removed") {
		t.Fatalf("rm: exit %d %s", code, out)
	}
}
