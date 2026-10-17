package cli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rakeshnitb23/opfence/internal/approve"
	"github.com/rakeshnitb23/opfence/internal/catalog"
	"github.com/rakeshnitb23/opfence/internal/classes"
	"github.com/rakeshnitb23/opfence/internal/engine"
	"github.com/rakeshnitb23/opfence/internal/proxy"
)

func startBroker(t *testing.T) (*approve.Broker, string) {
	t.Helper()
	dir, err := os.MkdirTemp("", "opf")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	path := filepath.Join(dir, "c.sock")
	ctl, err := approve.ListenControl(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ctl.Close() })
	b := approve.NewBroker(5*time.Second, ctl)
	go ctl.Serve(b)
	return b, path
}

func hold(t *testing.T, b *approve.Broker, d classes.Decision, resource string) (<-chan proxy.Approval, approve.View) {
	t.Helper()
	p := proxy.Pending{Method: "POST", Host: "backboard.railway.com", Path: "/graphql/v2", Result: &engine.Result{
		Decision: d,
		Evaluations: []engine.Evaluation{{Rule: &catalog.Rule{ID: "railway.volume.delete"}, Class: classes.Irreversible, Decision: d,
			Environment: "production", Resource: resource, Card: "Delete Railway volume " + resource}},
	}}
	out := make(chan proxy.Approval, 1)
	go func() { out <- b.Approve(context.Background(), p) }()
	for i := 0; len(b.List()) == 0; i++ {
		if i > 2000 {
			t.Fatal("request never waited")
		}
		time.Sleep(time.Millisecond)
	}
	return out, b.List()[0]
}

func TestApproveCommands(t *testing.T) {
	b, sock := startBroker(t)
	res, v := hold(t, b, classes.Confirm, "vol-pg-data")
	code, out, _ := run(t, "approve", "--socket", sock, "--list")
	if code != exitOK || !strings.Contains(out, v.ID) || !strings.Contains(out, "Delete Railway volume vol-pg-data") {
		t.Fatalf("list: %d %s", code, out)
	}
	if code, _, errOut := run(t, "approve", "--socket", sock, v.ID, "--yes", "--typed", "vol"); code != exitError || !strings.Contains(errOut, `type "vol-pg-data" exactly`) {
		t.Fatalf("wrong typed: %d %s", code, errOut)
	}
	if code, out, _ := run(t, "approve", "--socket", sock, v.ID, "--yes", "--typed", "vol-pg-data"); code != exitOK || !strings.Contains(out, "approved") {
		t.Fatalf("approve: %d %s", code, out)
	}
	if a := <-res; !a.Approved || a.Channel != "cli" {
		t.Fatalf("%+v", a)
	}

	// Interactive: the human types the name in this terminal.
	res, _ = hold(t, b, classes.Confirm, "vol-2")
	code, out, errOut := runIn(t, "vol-2\n", "approve", "--socket", sock, "--max", "1")
	if code != exitOK || !strings.Contains(out, "Type vol-2 to confirm") {
		t.Fatalf("interactive: %d %s %s", code, out, errOut)
	}
	if a := <-res; !a.Approved {
		t.Fatalf("%+v", a)
	}
	// Interactive ask: Enter denies.
	res, _ = hold(t, b, classes.Ask, "vol-3")
	if code, _, _ := runIn(t, "\n", "approve", "--socket", sock, "--max", "1"); code != exitOK {
		t.Fatalf("interactive deny: %d", code)
	}
	if a := <-res; a.Approved {
		t.Fatalf("%+v", a)
	}
	if code, _, errOut := run(t, "approve", "--socket", filepath.Join(t.TempDir(), "none.sock"), "--list"); code != exitError || !strings.Contains(errOut, "no Opfence proxy is running") {
		t.Fatalf("no proxy: %d %s", code, errOut)
	}
}
