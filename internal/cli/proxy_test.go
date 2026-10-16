package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rakeshnitb23/opfence/internal/audit"
)

func TestLogShowAndVerify(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, err := audit.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range []audit.Entry{
		{Event: "request", Host: "backboard.railway.com", Method: "POST", Path: "/graphql/v2", Decision: "confirm", Outcome: "blocked",
			Operations: []audit.Operation{{Rule: "railway.volume.delete", Class: "irreversible", Environment: "production", Decision: "confirm", Card: "Delete volume vol-pg-data"}}},
		{Event: "tunnel", Host: "registry.npmjs.org", Port: "443", Outcome: "tunneled", Reason: "passthrough"},
	} {
		if err := l.Record(e); err != nil {
			t.Fatal(err)
		}
	}
	code, out, errOut := run(t, "log", "--audit", path)
	if code != exitOK || !strings.Contains(out, "POST backboard.railway.com/graphql/v2") || !strings.Contains(out, "Delete volume vol-pg-data") || !strings.Contains(out, "passthrough") {
		t.Fatalf("exit %d\n%s%s", code, out, errOut)
	}
	if code, out, _ := run(t, "log", "--audit", path, "--verify"); code != exitOK || !strings.Contains(out, "chain intact, 2 entries") {
		t.Fatalf("verify: exit %d %s", code, out)
	}
	data, _ := os.ReadFile(path)
	if err := os.WriteFile(path, []byte(strings.Replace(string(data), "blocked", "forward", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, out, _ := run(t, "log", "--audit", path, "--verify"); code != exitFail || !strings.Contains(out, "line 2") {
		t.Fatalf("tampered log: exit %d %s", code, out)
	}
}

func TestProxyRefusesNonLoopback(t *testing.T) {
	code, _, errOut := run(t, noUser(t), "proxy", "--http", "0.0.0.0:0", "--audit", filepath.Join(t.TempDir(), "a.jsonl"))
	if code != exitError || !strings.Contains(errOut, "only listens on loopback") {
		t.Fatalf("exit %d %s", code, errOut)
	}
}
