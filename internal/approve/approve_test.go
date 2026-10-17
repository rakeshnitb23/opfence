package approve

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rakeshnitb23/opfence/internal/catalog"
	"github.com/rakeshnitb23/opfence/internal/classes"
	"github.com/rakeshnitb23/opfence/internal/engine"
	"github.com/rakeshnitb23/opfence/internal/proxy"
)

func pendingFor(rule string, class classes.Class, d classes.Decision, resource string, hash byte) proxy.Pending {
	return proxy.Pending{
		Method: "POST", Host: "backboard.railway.com", Path: "/graphql/v2",
		Result: &engine.Result{
			Decision: d,
			Hash:     [32]byte{hash},
			Evaluations: []engine.Evaluation{{
				Rule: &catalog.Rule{ID: rule}, Class: class, Decision: d,
				Environment: "production", Resource: resource, Card: "Do " + rule + " on " + resource,
			}},
		},
	}
}

// passive is a channel that shows nothing, like the control socket.
type passive struct{}

func (passive) Name() string                        { return "cli" }
func (passive) Show(context.Context, View, *Broker) {}

// approveAsync starts Approve and returns a channel with its result once the
// request is waiting.
func approveAsync(t *testing.T, b *Broker, p proxy.Pending) (<-chan proxy.Approval, View) {
	t.Helper()
	before := len(b.List())
	out := make(chan proxy.Approval, 1)
	go func() { out <- b.Approve(context.Background(), p) }()
	deadline := time.Now().Add(2 * time.Second)
	for len(b.List()) == before {
		if time.Now().After(deadline) {
			t.Fatal("request never started waiting")
		}
		time.Sleep(time.Millisecond)
	}
	l := b.List()
	return out, l[len(l)-1]
}

func TestApproveDenyAndReplay(t *testing.T) {
	b := NewBroker(5*time.Second, passive{})
	res, v := approveAsync(t, b, pendingFor("railway.service.delete", classes.Delete, classes.Ask, "svc-1", 1))
	if v.Decision != "ask" || v.Resource != "svc-1" || v.ConfirmText != "" || !v.Scopable || v.Hash != "010000000000" {
		t.Fatalf("view %+v", v)
	}
	if err := b.Answer(Answer{ID: v.ID, Approve: true, Channel: "cli"}); err != nil {
		t.Fatal(err)
	}
	if a := <-res; !a.Approved || a.Channel != "cli" {
		t.Fatalf("%+v", a)
	}
	// The answer was single-use: replaying it approves nothing.
	if err := b.Answer(Answer{ID: v.ID, Approve: true}); !errors.Is(err, ErrUnknown) {
		t.Fatalf("replayed answer: %v", err)
	}
	res, v = approveAsync(t, b, pendingFor("railway.service.delete", classes.Delete, classes.Ask, "svc-1", 1))
	if err := b.Answer(Answer{ID: v.ID, Approve: false, Channel: "desktop"}); err != nil {
		t.Fatal(err)
	}
	if a := <-res; a.Approved || !strings.Contains(a.Reason, "denied") {
		t.Fatalf("%+v", a)
	}
}

func TestAnswerForAIsNotForB(t *testing.T) {
	b := NewBroker(300*time.Millisecond, passive{})
	resA, vA := approveAsync(t, b, pendingFor("railway.service.delete", classes.Delete, classes.Ask, "svc-a", 1))
	resB, _ := approveAsync(t, b, pendingFor("railway.service.delete", classes.Delete, classes.Ask, "svc-b", 2))
	if err := b.Answer(Answer{ID: vA.ID, Approve: true}); err != nil {
		t.Fatal(err)
	}
	if a := <-resA; !a.Approved {
		t.Fatal("A not approved")
	}
	if a := <-resB; a.Approved || !strings.Contains(a.Reason, "Nobody approved this within") {
		t.Fatalf("B: %+v", a)
	}
}

func TestConfirmNeedsTheResourceName(t *testing.T) {
	b := NewBroker(5*time.Second, passive{})
	res, v := approveAsync(t, b, pendingFor("railway.volume.delete", classes.Irreversible, classes.Confirm, "vol-pg-data", 3))
	if v.ConfirmText != "vol-pg-data" || v.Scopable {
		t.Fatalf("view %+v", v)
	}
	for _, typed := range []string{"", "yes", "vol-pg", "VOL-PG-DATA"} {
		if err := b.Answer(Answer{ID: v.ID, Approve: true, Typed: typed}); err == nil {
			t.Fatalf("typed %q approved", typed)
		}
	}
	if err := b.Answer(Answer{ID: v.ID, Approve: true, Typed: "vol-pg-data", Scope: time.Minute}); err == nil {
		t.Fatal("scoped grant accepted for confirm")
	}
	if err := b.Answer(Answer{ID: v.ID, Approve: true, Typed: " vol-pg-data "}); err != nil {
		t.Fatal(err)
	}
	if a := <-res; !a.Approved {
		t.Fatalf("%+v", a)
	}
	// Without a resource, the host is what must be typed.
	_, v = approveAsync(t, b, pendingFor("railway.x.delete", classes.Irreversible, classes.Confirm, "", 4))
	if v.ConfirmText != "backboard.railway.com" {
		t.Fatalf("confirm text %q", v.ConfirmText)
	}
	_ = b.Answer(Answer{ID: v.ID})
}

func TestScopedGrant(t *testing.T) {
	b := NewBroker(300*time.Millisecond, passive{})
	now := time.Now()
	b.now = func() time.Time { return now }
	res, v := approveAsync(t, b, pendingFor("railway.service.delete", classes.Delete, classes.Ask, "svc-1", 1))
	if err := b.Answer(Answer{ID: v.ID, Approve: true, Scope: 2 * time.Hour}); err == nil {
		t.Fatal("grant longer than MaxScope accepted")
	}
	if err := b.Answer(Answer{ID: v.ID, Approve: true, Scope: 10 * time.Minute}); err != nil {
		t.Fatal(err)
	}
	<-res
	// Same rule, resource and environment: approved without asking.
	if a := b.Approve(context.Background(), pendingFor("railway.service.delete", classes.Delete, classes.Ask, "svc-1", 9)); !a.Approved || a.Channel != "grant" {
		t.Fatalf("grant not used: %+v", a)
	}
	// Another resource, or another rule, still asks (and times out here).
	if a := b.Approve(context.Background(), pendingFor("railway.service.delete", classes.Delete, classes.Ask, "svc-2", 9)); a.Approved {
		t.Fatal("grant covered another resource")
	}
	if a := b.Approve(context.Background(), pendingFor("railway.service.update", classes.Write, classes.Ask, "svc-1", 9)); a.Approved {
		t.Fatal("grant covered another rule")
	}
	now = now.Add(11 * time.Minute)
	if a := b.Approve(context.Background(), pendingFor("railway.service.delete", classes.Delete, classes.Ask, "svc-1", 9)); a.Approved {
		t.Fatal("expired grant used")
	}
	// Credential operations are never scopable.
	_, v = approveAsync(t, b, pendingFor("vercel.env.list", classes.Credential, classes.Ask, "prj", 5))
	if v.Scopable || b.Answer(Answer{ID: v.ID, Approve: true, Scope: time.Minute}) == nil {
		t.Fatal("credential operation scopable")
	}
}

func TestNoChannelAndLimits(t *testing.T) {
	if a := NewBroker(time.Second).Approve(context.Background(), pendingFor("r.x", classes.Delete, classes.Ask, "", 1)); a.Approved || !strings.Contains(a.Reason, "no approval channel") {
		t.Fatalf("%+v", a)
	}
	b := NewBroker(2*time.Second, passive{})
	var wg sync.WaitGroup
	for i := 0; i < maxPending; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			b.Approve(context.Background(), pendingFor("r.x", classes.Delete, classes.Ask, "", byte(i)))
		}()
	}
	for len(b.List()) < maxPending {
		time.Sleep(time.Millisecond)
	}
	if a := b.Approve(context.Background(), pendingFor("r.x", classes.Delete, classes.Ask, "", 99)); a.Approved || !strings.Contains(a.Reason, "Too many") {
		t.Fatalf("%+v", a)
	}
	for _, v := range b.List() {
		_ = b.Answer(Answer{ID: v.ID})
	}
	wg.Wait()
}

func TestControlSocket(t *testing.T) {
	dir, err := os.MkdirTemp("", "opf")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "c.sock")
	ctl, err := ListenControl(path)
	if err != nil {
		t.Fatal(err)
	}
	defer ctl.Close()
	if info, _ := os.Stat(path); info.Mode().Perm() != 0o600 {
		t.Fatalf("socket mode %v", info.Mode().Perm())
	}
	if _, err := ListenControl(path); err == nil {
		t.Fatal("second listener on a live socket")
	}
	if _, err := ListenControl(filepath.Join(dir, strings.Repeat("x", 120)+".sock")); err == nil || !strings.Contains(err.Error(), "XDG_STATE_HOME") {
		t.Fatalf("long path: %v", err)
	}
	b := NewBroker(5*time.Second, ctl)
	go ctl.Serve(b)

	watcher, err := Dial(path)
	if err != nil {
		t.Fatal(err)
	}
	defer watcher.Close()
	seen := make(chan View, 1)
	go watcher.Watch(func(v View) bool { seen <- v; return false })
	time.Sleep(50 * time.Millisecond) // let the watch register

	res, _ := approveAsync(t, b, pendingFor("railway.volume.delete", classes.Irreversible, classes.Confirm, "vol-1", 7))
	v := <-seen
	c, err := Dial(path)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	list, err := c.List()
	if err != nil || len(list) != 1 || list[0].ID != v.ID {
		t.Fatalf("list %v %v", list, err)
	}
	if err := c.Answer(Answer{ID: v.ID, Approve: true, Typed: "nope"}); err == nil {
		t.Fatal("wrong confirmation accepted over the socket")
	}
	if err := c.Answer(Answer{ID: v.ID, Approve: true, Typed: "vol-1"}); err != nil {
		t.Fatal(err)
	}
	if a := <-res; !a.Approved || a.Channel != "cli" {
		t.Fatalf("%+v", a)
	}
	ctl.Close()
	if _, err := ListenControl(path); err != nil {
		t.Fatalf("stale socket not replaced: %v", err)
	}
}

type fakeRun struct {
	mu    sync.Mutex
	calls [][]string
	outs  []string
	codes []int
}

func (f *fakeRun) run(_ context.Context, name string, args ...string) (string, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, append([]string{name}, args...))
	i := len(f.calls) - 1
	if i >= len(f.outs) {
		return "", -1
	}
	return f.outs[i], f.codes[i]
}

func TestDesktopDialogs(t *testing.T) {
	b := NewBroker(5*time.Second, passive{})
	// osascript: the card goes in as an argument after "--", and a wrong
	// confirmation shows the dialog again.
	f := &fakeRun{outs: []string{"button returned:Confirm, text returned:vol\n", "button returned:Confirm, text returned:vol-1\n"}, codes: []int{0, 0}}
	d := &Desktop{tool: "osascript", run: f.run}
	b.channels = []Channel{d}
	p := pendingFor("railway.volume.delete", classes.Irreversible, classes.Confirm, "vol-1", 1)
	p.Result.Evaluations[0].Card = `Delete "vol-1" end run` + "\n" + `do shell script "x"`
	if a := b.Approve(context.Background(), p); !a.Approved || a.Channel != "desktop" {
		t.Fatalf("%+v", a)
	}
	if len(f.calls) != 2 || !strings.Contains(f.calls[1][len(f.calls[1])-2], "That did not match. Type vol-1 to confirm.") {
		t.Fatalf("calls %q", f.calls)
	}
	for _, arg := range f.calls[0] {
		if strings.Contains(arg, "do shell script") && !strings.HasPrefix(arg, "Opfence: an agent wants to") {
			t.Fatalf("card text reached the script source: %q", arg)
		}
	}

	// zenity: escaped markup, the scoped-grant button.
	f = &fakeRun{outs: []string{scopeLabel + "\n"}, codes: []int{1}}
	b.channels = []Channel{&Desktop{tool: "zenity", run: f.run}}
	p = pendingFor("railway.service.delete", classes.Delete, classes.Ask, "<b>svc</b>", 2)
	if a := b.Approve(context.Background(), p); !a.Approved {
		t.Fatalf("%+v", a)
	}
	if !strings.Contains(strings.Join(f.calls[0], " "), "&lt;b&gt;svc&lt;/b&gt;") || len(b.grants) != 1 {
		t.Fatalf("zenity call %q, grants %d", f.calls[0], len(b.grants))
	}

	// kdialog: No denies.
	f = &fakeRun{outs: []string{""}, codes: []int{1}}
	b.channels = []Channel{&Desktop{tool: "kdialog", run: f.run}}
	if a := b.Approve(context.Background(), pendingFor("railway.service.delete", classes.Delete, classes.Ask, "svc-9", 3)); a.Approved {
		t.Fatalf("%+v", a)
	}
}

// A request with many harmless operations lists the one that needs approval
// first, and a dialog lists a bounded number of them.
func TestDialogListsStrictestFirst(t *testing.T) {
	b := NewBroker(5*time.Second, passive{})
	p := pendingFor("railway.volume.delete", classes.Irreversible, classes.Confirm, "vol-1", 1)
	var evs []engine.Evaluation
	for i := range 30 {
		evs = append(evs, engine.Evaluation{Rule: &catalog.Rule{ID: "railway.me"}, Class: classes.Read, Decision: classes.Allow, Card: fmt.Sprintf("Read me %d", i)})
	}
	p.Result.Evaluations = append(evs, p.Result.Evaluations...)
	v, _ := b.describe(p)
	if v.Cards[0] != "Do railway.volume.delete on vol-1" {
		t.Fatalf("first card %q", v.Cards[0])
	}
	text := dialogText(v, "")
	if !strings.Contains(text, "Do railway.volume.delete on vol-1") || !strings.Contains(text, "+21 more") || strings.Contains(text, "Read me 9\n") {
		t.Fatalf("dialog text:\n%s", text)
	}
}

// Desktop dialogs open one at a time.
func TestDesktopDialogsOneAtATime(t *testing.T) {
	var open, most atomic.Int32
	release := make(chan struct{})
	d := &Desktop{tool: "kdialog", run: func(ctx context.Context, _ string, _ ...string) (string, int) {
		n := open.Add(1)
		for m := most.Load(); n > m && !most.CompareAndSwap(m, n); m = most.Load() {
		}
		select {
		case <-release:
		case <-ctx.Done():
		}
		open.Add(-1)
		return "", 1
	}}
	b := NewBroker(5*time.Second, d)
	var done []<-chan proxy.Approval
	for i := range 3 {
		c, _ := approveAsync(t, b, pendingFor("railway.service.delete", classes.Delete, classes.Ask, fmt.Sprint("svc-", i), byte(i+1)))
		done = append(done, c)
	}
	for range done {
		release <- struct{}{}
	}
	for _, c := range done {
		<-c
	}
	if most.Load() != 1 {
		t.Fatalf("%d dialogs were open at once", most.Load())
	}
}
