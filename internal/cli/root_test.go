package cli

import (
	"bytes"
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
