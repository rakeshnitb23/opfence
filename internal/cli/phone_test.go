package cli

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rakeshnitb23/opfence/internal/approve"
	"github.com/rakeshnitb23/opfence/internal/policy"
	"github.com/rakeshnitb23/opfence/internal/secrets"
)

func runPhone(t *testing.T, stdin string, args ...string) (string, error) {
	t.Helper()
	root := newRootCmd()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetIn(strings.NewReader(stdin))
	root.SetArgs(append([]string{"phone"}, args...))
	err := root.Execute()
	return out.String(), err
}

func TestPhoneSetupAndOff(t *testing.T) {
	m := &secrets.Memory{}
	old := openStore
	openStore = func() secrets.Store { return m }
	t.Cleanup(func() { openStore = old })

	out, err := runPhone(t, "")
	if err != nil || !strings.Contains(out, "not set up") {
		t.Fatalf("%q %v", out, err)
	}
	out, err = runPhone(t, "", "setup", "--no-test")
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := approve.LoadPhone(m)
	if err != nil || cfg.Server != "https://ntfy.sh" || cfg.Token != "" {
		t.Fatalf("%+v %v", cfg, err)
	}
	if !strings.Contains(out, cfg.SubscribeURL()) || !strings.Contains(out, "█") || strings.Contains(out, cfg.Reply) {
		t.Fatalf("setup output:\n%s", out)
	}

	// Running setup again keeps the topics; a new server or --new-topics
	// makes new ones.
	if _, err := runPhone(t, "", "setup", "--no-test"); err != nil {
		t.Fatal(err)
	}
	if again, _ := approve.LoadPhone(m); again != cfg {
		t.Fatalf("topics changed: %+v", again)
	}
	if _, err := runPhone(t, "tk_abc\n", "setup", "--no-test", "--server", "https://ntfy.example.com/", "--token-stdin"); err != nil {
		t.Fatal(err)
	}
	other, _ := approve.LoadPhone(m)
	if other.Topic == cfg.Topic || other.Server != "https://ntfy.example.com" || other.Token != "tk_abc" {
		t.Fatalf("%+v", other)
	}
	// A button token is read from the next line, and kept on later runs.
	if _, err := runPhone(t, "tk_abc\ntk_btn\n", "setup", "--no-test", "--server", "https://ntfy.example.com/", "--token-stdin", "--button-token-stdin"); err != nil {
		t.Fatal(err)
	}
	if b, _ := approve.LoadPhone(m); b.Token != "tk_abc" || b.ButtonToken != "tk_btn" || b.Topic != other.Topic {
		t.Fatalf("%+v", b)
	}
	if _, err := runPhone(t, "", "setup", "--no-test", "--server", "https://ntfy.example.com/"); err != nil {
		t.Fatal(err)
	}
	if b, _ := approve.LoadPhone(m); b.ButtonToken != "tk_btn" {
		t.Fatalf("button token lost: %+v", b)
	}
	if _, err := runPhone(t, "tk_same\ntk_same\n", "setup", "--no-test", "--server", "https://ntfy.example.com/", "--token-stdin", "--button-token-stdin"); err == nil {
		t.Fatal("accepted a button token equal to the access token")
	}
	if _, err := runPhone(t, "", "setup", "--no-test", "--server", "ntfy.example.com"); err == nil {
		t.Fatal("accepted a server without a scheme")
	}

	if out, err := runPhone(t, "", "off"); err != nil || !strings.Contains(out, "off") {
		t.Fatalf("%q %v", out, err)
	}
	if _, err := approve.LoadPhone(m); err != secrets.ErrNotFound {
		t.Fatalf("still set up: %v", err)
	}
	if _, err := runPhone(t, "", "test"); err == nil || !strings.Contains(err.Error(), "not set up") {
		t.Fatalf("test without setup: %v", err)
	}
}

func TestPrintQR(t *testing.T) {
	var b bytes.Buffer
	if err := printQR(&b, "ntfy://ntfy.sh/opf-abc?display=Opfence"); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(b.String(), "\n"), "\n")
	// Version 3 at level M is 29 modules, plus a quiet zone of 2 each side.
	if w := len([]rune(lines[0])); w != 33 || len(lines) != 17 {
		t.Fatalf("%d lines of width %d", len(lines), w)
	}
	if strings.Trim(lines[0], "█") != "" {
		t.Fatalf("quiet zone not light: %q", lines[0])
	}
}

func TestStartApprovalsPhone(t *testing.T) {
	m := &secrets.Memory{}
	old := openStore
	openStore = func() secrets.Store { return m }
	t.Cleanup(func() { openStore = old })
	sock := filepath.Join(t.TempDir(), "c.sock")

	// Not set up: the default channels say nothing about the phone.
	var warn bytes.Buffer
	_, ctl, phone, how, err := startApprovals(&warn, policy.Resolve(nil, nil), sock, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctl.Close()
	if phone != nil || strings.Contains(warn.String(), "phone") || !strings.Contains(how, "denied after 1m0s") {
		t.Fatalf("phone=%v warn=%q how=%q", phone, warn.String(), how)
	}

	if err := approve.SavePhone(m, approve.PhoneConfig{Server: "https://ntfy.example.com", Topic: approve.NewTopic(), Reply: approve.NewTopic()}); err != nil {
		t.Fatal(err)
	}
	_, ctl, phone, how, err = startApprovals(&warn, policy.Resolve(nil, nil), sock, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctl.Close()
	if phone == nil || !strings.Contains(how, "your phone (https://ntfy.example.com)") || !strings.Contains(how, "denied after 1m30s") {
		t.Fatalf("phone=%v how=%q", phone, how)
	}

	// A repository timeout is never lengthened by the phone default.
	repo := &policy.File{Version: 1, Approvals: &policy.Approvals{Timeout: policy.Duration(75 * time.Second)}}
	_, ctl, _, how, _ = startApprovals(&warn, policy.Resolve(nil, repo), sock, nil)
	ctl.Close()
	if !strings.Contains(how, "denied after 1m15s") {
		t.Fatalf("repo limit: how=%q", how)
	}
	repo.Approvals.Timeout = policy.Duration(30 * time.Second)
	_, ctl, _, how, _ = startApprovals(&warn, policy.Resolve(nil, repo), sock, nil)
	ctl.Close()
	if !strings.Contains(how, "denied after 30s") {
		t.Fatalf("repo limit: how=%q", how)
	}

	// A timeout the user set is kept.
	user := &policy.File{Version: 1, Approvals: &policy.Approvals{Timeout: policy.Duration(20 * time.Second)}}
	_, ctl, _, how, _ = startApprovals(&warn, policy.Resolve(user, nil), sock, nil)
	ctl.Close()
	if !strings.Contains(how, "denied after 20s") {
		t.Fatalf("how=%q", how)
	}

	// Listing ntfy without setting it up warns.
	_ = approve.DeletePhone(m)
	user = &policy.File{Version: 1, Approvals: &policy.Approvals{Channels: []string{"ntfy"}}}
	if _, _, _, _, err := startApprovals(&warn, policy.Resolve(user, nil), sock, nil); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(warn.String(), "opfence phone setup") {
		t.Fatalf("warn=%q", warn.String())
	}
}
