package audit

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func writeEntries(t *testing.T, n int) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "state", "audit.jsonl")
	l, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := l.Record(Entry{Session: "s", Event: "request", Host: "api.github.com", Outcome: "forwarded", Reason: strings.Repeat("x", 5000)}); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	return path
}

func TestChainVerifies(t *testing.T) {
	path := writeEntries(t, 40)
	data, _ := os.ReadFile(path)
	n, err := Verify(bytes.NewReader(data))
	if err != nil || n != 40 {
		t.Fatalf("Verify = %d, %v", n, err)
	}
	if info, _ := os.Stat(path); info.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", info.Mode().Perm())
	}
	if info, _ := os.Stat(filepath.Dir(path)); info.Mode().Perm() != 0o700 {
		t.Fatalf("dir mode %v", info.Mode().Perm())
	}
	entries, err := Read(bytes.NewReader(data))
	if err != nil || len(entries) != 40 || entries[0].Prev != "" || entries[1].Prev == "" {
		t.Fatalf("Read: %d entries, %v", len(entries), err)
	}
}

func TestTamperingDetected(t *testing.T) {
	path := writeEntries(t, 5)
	data, _ := os.ReadFile(path)
	lines := strings.SplitAfter(string(data), "\n")
	lines = lines[:len(lines)-1] // trailing empty element
	cases := map[string]string{
		"edited":        strings.Join(lines[:2], "") + strings.Replace(lines[2], "forwarded", "blocked__", 1) + strings.Join(lines[3:], ""),
		"deleted":       strings.Join(lines[:2], "") + strings.Join(lines[3:], ""),
		"first deleted": strings.Join(lines[1:], ""),
		"swapped":       lines[0] + lines[2] + lines[1] + strings.Join(lines[3:], ""),
		"garbage":       lines[0] + "not json\n" + strings.Join(lines[1:], ""),
	}
	for name, tampered := range cases {
		if _, err := Verify(strings.NewReader(tampered)); !errors.Is(err, ErrBroken) {
			t.Errorf("%s: Verify = %v, want ErrBroken", name, err)
		}
	}
}

func TestChainContinuesAcrossOpens(t *testing.T) {
	path := writeEntries(t, 2)
	l, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Record(Entry{Event: "tunnel", Host: "registry.npmjs.org", Outcome: "tunneled"}); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	if n, err := Verify(bytes.NewReader(data)); err != nil || n != 3 {
		t.Fatalf("Verify = %d, %v", n, err)
	}
}
