package approve

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/rakeshnitb23/opfence/internal/classes"
	"github.com/rakeshnitb23/opfence/internal/secrets"
)

// fakeNtfy implements the parts of ntfy's API the phone channel uses.
type fakeNtfy struct {
	t     *testing.T
	token string // required bearer token, if set
	// buttonToken, if set, is also accepted, but only to post to a topic
	// (what a write-only reply-topic user may do).
	buttonToken string

	mu      sync.Mutex
	n       int
	stored  map[string][]ntfyStored // topic -> messages
	subs    map[string][]chan ntfyStored
	pushes  []phoneMessage
	ids     []string // message id of each push
	deleted []string
	cut     chan struct{} // closed to drop every open stream
	hold    chan struct{} // if set, publish replies only once it is closed
}

type ntfyStored struct {
	id   string
	time int64
	msg  string
}

func newFakeNtfy(t *testing.T) (*fakeNtfy, *httptest.Server) {
	f := &fakeNtfy{t: t, stored: map[string][]ntfyStored{}, subs: map[string][]chan ntfyStored{}, cut: make(chan struct{})}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	return f, srv
}

func (f *fakeNtfy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	auth := r.Header.Get("Authorization")
	button := f.buttonToken != "" && auth == "Bearer "+f.buttonToken
	if button && !(r.Method == http.MethodPost && len(parts) == 1 && parts[0] != "") {
		http.Error(w, `{"code":40301,"error":"forbidden"}`, http.StatusForbidden)
		return
	}
	if f.token != "" && auth != "Bearer "+f.token && !button {
		http.Error(w, `{"code":40101,"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/":
		var m phoneMessage
		if err := json.NewDecoder(r.Body).Decode(&m); err != nil || m.Topic == "" {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		id := f.store(m.Topic, m.Message)
		f.mu.Lock()
		f.pushes = append(f.pushes, m)
		f.ids = append(f.ids, id)
		hold := f.hold
		f.mu.Unlock()
		if hold != nil {
			<-hold
		}
		fmt.Fprintf(w, `{"id":%q,"event":"message","topic":%q}`, id, m.Topic)
	case r.Method == http.MethodPost && len(parts) == 1:
		b, _ := io.ReadAll(r.Body)
		id := f.store(parts[0], string(b))
		fmt.Fprintf(w, `{"id":%q}`, id)
	case r.Method == http.MethodDelete && len(parts) == 2:
		f.mu.Lock()
		f.deleted = append(f.deleted, parts[1])
		f.mu.Unlock()
		fmt.Fprint(w, `{}`)
	case r.Method == http.MethodGet && len(parts) == 2 && parts[1] == "json":
		f.subscribe(w, r, parts[0])
	default:
		http.NotFound(w, r)
	}
}

func (f *fakeNtfy) store(topic, msg string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.n++
	m := ntfyStored{id: "m" + strconv.Itoa(f.n), time: time.Now().Unix(), msg: msg}
	f.stored[topic] = append(f.stored[topic], m)
	for _, c := range f.subs[topic] {
		c <- m
	}
	return m.id
}

func (f *fakeNtfy) subscribe(w http.ResponseWriter, r *http.Request, topic string) {
	since := r.URL.Query().Get("since")
	c := make(chan ntfyStored, 64)
	f.mu.Lock()
	var backlog []ntfyStored
	after := false
	for _, m := range f.stored[topic] {
		switch {
		case strings.HasPrefix(since, "m"):
			if after {
				backlog = append(backlog, m)
			}
			after = after || m.id == since
		default:
			if ts, _ := strconv.ParseInt(since, 10, 64); m.time >= ts {
				backlog = append(backlog, m)
			}
		}
	}
	f.subs[topic] = append(f.subs[topic], c)
	cut := f.cut
	f.mu.Unlock()
	defer func() {
		f.mu.Lock()
		f.subs[topic] = slices.DeleteFunc(f.subs[topic], func(x chan ntfyStored) bool { return x == c })
		f.mu.Unlock()
	}()
	write := func(ev, id, msg string) {
		b, _ := json.Marshal(phoneEvent{ID: id, Event: ev, Topic: topic, Message: msg})
		w.Write(append(b, '\n'))
		w.(http.Flusher).Flush()
	}
	write("open", "o", "")
	for _, m := range backlog {
		write("message", m.id, m.msg)
	}
	for {
		select {
		case m := <-c:
			write("message", m.id, m.msg)
		case <-cut:
			return
		case <-r.Context().Done():
			return
		}
	}
}

// drop closes every open stream, as a flaky network would.
func (f *fakeNtfy) drop() {
	f.mu.Lock()
	close(f.cut)
	f.cut = make(chan struct{})
	f.mu.Unlock()
}

func (f *fakeNtfy) subscribers(topic string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.subs[topic])
}

// push waits for the i-th push.
func (f *fakeNtfy) push(i int) (phoneMessage, string) {
	f.t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		f.mu.Lock()
		if len(f.pushes) > i {
			m, id := f.pushes[i], f.ids[i]
			f.mu.Unlock()
			return m, id
		}
		f.mu.Unlock()
		if time.Now().After(deadline) {
			f.t.Fatalf("push %d never arrived", i)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func (f *fakeNtfy) wasDeleted(id string) bool {
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		f.mu.Lock()
		ok := slices.Contains(f.deleted, id)
		f.mu.Unlock()
		if ok {
			return true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return false
}

// tap does what the ntfy app does when a button is tapped.
func tap(t *testing.T, m phoneMessage, label string) {
	t.Helper()
	for _, a := range m.Actions {
		if a.Label != label {
			continue
		}
		if a.Action != "http" {
			t.Fatalf("action %q is %s", label, a.Action)
		}
		req, _ := http.NewRequest(a.Method, a.URL, strings.NewReader(a.Body))
		for k, v := range a.Headers {
			req.Header.Set(k, v)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Fatalf("tap %q: %s", label, resp.Status)
		}
		return
	}
	t.Fatalf("no button %q in %+v", label, labels(m))
}

func labels(m phoneMessage) []string {
	var out []string
	for _, a := range m.Actions {
		out = append(out, a.Label)
	}
	return out
}

func post(t *testing.T, srv *httptest.Server, topic, body string) {
	t.Helper()
	resp, err := http.Post(srv.URL+"/"+topic, "text/plain", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
}

func testPhone(t *testing.T, srv *httptest.Server, timeout time.Duration) (*Phone, *Broker, *strings.Builder) {
	cfg := PhoneConfig{Server: srv.URL, Topic: NewTopic(), Reply: NewTopic()}
	var mu sync.Mutex
	logs := &strings.Builder{}
	p := NewPhone(cfg, func(f string, a ...any) { mu.Lock(); fmt.Fprintf(logs, f+"\n", a...); mu.Unlock() })
	p.grace = 0
	b := NewBroker(timeout, p)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go p.Listen(ctx, b)
	return p, b, logs
}

func waitSubscribed(t *testing.T, f *fakeNtfy, topic string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for f.subscribers(topic) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("never subscribed to the reply topic")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestPhoneApproveAndDeny(t *testing.T) {
	f, srv := newFakeNtfy(t)
	p, b, _ := testPhone(t, srv, 5*time.Second)
	waitSubscribed(t, f, p.cfg.Reply)

	res, v := approveAsync(t, b, pendingFor("railway.service.delete", classes.Delete, classes.Ask, "svc-1", 1))
	m, id := f.push(0)
	if m.Topic != p.cfg.Topic || !strings.Contains(m.Message, "Do railway.service.delete on svc-1") || !strings.Contains(m.Message, v.Hash) {
		t.Fatalf("push %+v", m)
	}
	if got := labels(m); !slices.Equal(got, []string{"Deny", "Approve", "Approve 10 min"}) {
		t.Fatalf("buttons %v", got)
	}
	for _, a := range m.Actions {
		if a.URL != srv.URL+"/"+p.cfg.Reply || a.Method != "POST" || !strings.HasPrefix(a.Body, "opf1") || !a.Clear {
			t.Fatalf("action %+v", a)
		}
	}
	tap(t, m, "Approve")
	if a := <-res; !a.Approved || a.Channel != "phone" {
		t.Fatalf("%+v", a)
	}
	if !f.wasDeleted(id) {
		t.Fatal("push was not removed after the answer")
	}

	res, _ = approveAsync(t, b, pendingFor("railway.service.delete", classes.Delete, classes.Ask, "svc-1", 2))
	m, _ = f.push(1)
	tap(t, m, "Deny")
	if a := <-res; a.Approved || !strings.Contains(a.Reason, "denied") || a.Channel != "phone" {
		t.Fatalf("%+v", a)
	}
}

// The phone can answer before ntfy has replied to the publish; the push is
// still removed.
func TestPhoneAnswerBeforePublishReply(t *testing.T) {
	f, srv := newFakeNtfy(t)
	f.hold = make(chan struct{})
	p, b, _ := testPhone(t, srv, 5*time.Second)
	waitSubscribed(t, f, p.cfg.Reply)
	res, _ := approveAsync(t, b, pendingFor("railway.service.delete", classes.Delete, classes.Ask, "svc-1", 1))
	m, id := f.push(0)
	tap(t, m, "Approve")
	if a := <-res; !a.Approved {
		t.Fatalf("%+v", a)
	}
	close(f.hold)
	if !f.wasDeleted(id) {
		t.Fatal("push was not removed")
	}
}

func TestPhoneScopedGrant(t *testing.T) {
	f, srv := newFakeNtfy(t)
	p, b, _ := testPhone(t, srv, 5*time.Second)
	waitSubscribed(t, f, p.cfg.Reply)
	res, _ := approveAsync(t, b, pendingFor("railway.service.delete", classes.Delete, classes.Ask, "svc-1", 1))
	m, _ := f.push(0)
	tap(t, m, "Approve 10 min")
	if a := <-res; !a.Approved {
		t.Fatalf("%+v", a)
	}
	if a := b.Approve(context.Background(), pendingFor("railway.service.delete", classes.Delete, classes.Ask, "svc-1", 9)); !a.Approved || a.Channel != "grant" {
		t.Fatalf("grant not applied: %+v", a)
	}
}

// Answers are bound: a token answers only its own request, a used token
// answers nothing more, and forged tokens or junk do nothing.
func TestPhoneAnswersAreBound(t *testing.T) {
	f, srv := newFakeNtfy(t)
	p, b, _ := testPhone(t, srv, 700*time.Millisecond)
	waitSubscribed(t, f, p.cfg.Reply)

	resA, _ := approveAsync(t, b, pendingFor("railway.service.delete", classes.Delete, classes.Ask, "svc-a", 1))
	mA, _ := f.push(0)
	resB, _ := approveAsync(t, b, pendingFor("railway.service.delete", classes.Delete, classes.Ask, "svc-b", 2))
	mB, _ := f.push(1)
	if mA.Actions[1].Body == mB.Actions[1].Body {
		t.Fatal("two requests share a token")
	}
	tap(t, mA, "Approve")
	if a := <-resA; !a.Approved {
		t.Fatalf("A: %+v", a)
	}
	// Replaying A's approve token, A's deny token, a forged token and junk
	// leave B waiting until it times out.
	tap(t, mA, "Approve")
	tap(t, mA, "Deny")
	post(t, srv, p.cfg.Reply, "opf1"+strings.Repeat("A", 22))
	post(t, srv, p.cfg.Reply, `{"id":"`+mB.Actions[1].Body[:10]+`","approve":true}`)
	post(t, srv, p.cfg.Reply, "approve")
	if a := <-resB; a.Approved || !strings.Contains(a.Reason, "Nobody approved") {
		t.Fatalf("B: %+v", a)
	}
	// B's tokens die with it.
	resC, _ := approveAsync(t, b, pendingFor("railway.service.delete", classes.Delete, classes.Ask, "svc-b", 2))
	tap(t, mB, "Approve")
	if a := <-resC; a.Approved {
		t.Fatalf("an expired request's token approved a new one: %+v", a)
	}
}

func TestPhoneConfirmCannotBeApproved(t *testing.T) {
	f, srv := newFakeNtfy(t)
	p, b, _ := testPhone(t, srv, 5*time.Second)
	waitSubscribed(t, f, p.cfg.Reply)
	res, _ := approveAsync(t, b, pendingFor("railway.volume.delete", classes.Irreversible, classes.Confirm, "prod-db", 1))
	m, _ := f.push(0)
	if got := labels(m); !slices.Equal(got, []string{"Deny"}) {
		t.Fatalf("confirm buttons %v", got)
	}
	if !strings.Contains(m.Message, "type prod-db") || !strings.HasPrefix(m.Title, "Confirm:") {
		t.Fatalf("push %+v", m)
	}
	tap(t, m, "Deny")
	if a := <-res; a.Approved {
		t.Fatalf("%+v", a)
	}
}

func TestPhoneRemovesPushOnTimeout(t *testing.T) {
	f, srv := newFakeNtfy(t)
	p, b, _ := testPhone(t, srv, 300*time.Millisecond)
	waitSubscribed(t, f, p.cfg.Reply)
	a := b.Approve(context.Background(), pendingFor("railway.service.delete", classes.Delete, classes.Ask, "svc-1", 1))
	if a.Approved {
		t.Fatal("approved without an answer")
	}
	_, id := f.push(0)
	if !f.wasDeleted(id) {
		t.Fatal("push was not removed after the timeout")
	}
}

// An answer posted while the stream is down arrives after the reconnect.
func TestPhoneReconnects(t *testing.T) {
	f, srv := newFakeNtfy(t)
	p, b, _ := testPhone(t, srv, 10*time.Second)
	waitSubscribed(t, f, p.cfg.Reply)
	post(t, srv, p.cfg.Reply, "earlier message") // gives the stream a last id
	time.Sleep(50 * time.Millisecond)
	res, _ := approveAsync(t, b, pendingFor("railway.service.delete", classes.Delete, classes.Ask, "svc-1", 1))
	m, _ := f.push(0)
	f.drop()
	tap(t, m, "Approve") // lands while nobody is subscribed
	select {
	case a := <-res:
		if !a.Approved {
			t.Fatalf("%+v", a)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("answer posted during the outage was lost")
	}
}

// A connection that goes silent is replaced.
func TestPhoneIdleStreamReconnects(t *testing.T) {
	f, srv := newFakeNtfy(t)
	cfg := PhoneConfig{Server: srv.URL, Topic: NewTopic(), Reply: NewTopic()}
	p := NewPhone(cfg, nil)
	p.idle = 100 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	opens := make(chan struct{}, 10)
	go p.listen(ctx, nil, func(string) {})
	// Count connections by watching subscriber churn.
	go func() {
		seen := 0
		for ctx.Err() == nil {
			if n := f.subscribers(cfg.Reply); n > 0 && seen == 0 {
				opens <- struct{}{}
			} else if n == 0 {
				seen = 0
				time.Sleep(time.Millisecond)
				continue
			}
			seen = 1
			time.Sleep(time.Millisecond)
		}
	}()
	for i := 0; i < 2; i++ {
		select {
		case <-opens:
		case <-time.After(5 * time.Second):
			t.Fatal("silent stream was not replaced")
		}
	}
}

func TestPhoneToken(t *testing.T) {
	f, srv := newFakeNtfy(t)
	f.token = "tk_" + strings.Repeat("x", 29)
	cfg := PhoneConfig{Server: srv.URL, Topic: NewTopic(), Reply: NewTopic(), Token: f.token}
	p := NewPhone(cfg, nil)
	p.grace = 0
	b := NewBroker(5*time.Second, p)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go p.Listen(ctx, b)
	waitSubscribed(t, f, cfg.Reply)
	res, _ := approveAsync(t, b, pendingFor("railway.service.delete", classes.Delete, classes.Ask, "svc-1", 1))
	m, _ := f.push(0)
	if m.Actions[1].Headers["Authorization"] != "Bearer "+f.token {
		t.Fatalf("button carries no token: %+v", m.Actions[1])
	}
	tap(t, m, "Approve")
	if a := <-res; !a.Approved {
		t.Fatalf("%+v", a)
	}
}

// With a button token, pushes carry only it, and Opfence publishes and
// reads with the access token.
func TestPhoneButtonToken(t *testing.T) {
	f, srv := newFakeNtfy(t)
	f.token = "tk_" + strings.Repeat("x", 29)
	f.buttonToken = "tk_" + strings.Repeat("b", 29)
	cfg := PhoneConfig{Server: srv.URL, Topic: NewTopic(), Reply: NewTopic(), Token: f.token, ButtonToken: f.buttonToken}
	p := NewPhone(cfg, nil)
	p.grace = 0
	b := NewBroker(5*time.Second, p)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go p.Listen(ctx, b)
	waitSubscribed(t, f, cfg.Reply)
	res, _ := approveAsync(t, b, pendingFor("railway.service.delete", classes.Delete, classes.Ask, "svc-1", 1))
	m, _ := f.push(0)
	raw, _ := json.Marshal(m)
	if strings.Contains(string(raw), f.token) {
		t.Fatalf("the access token travels in the push: %s", raw)
	}
	for _, a := range m.Actions {
		if a.Headers["Authorization"] != "Bearer "+f.buttonToken {
			t.Fatalf("button %q does not use the button token: %+v", a.Label, a)
		}
	}
	tap(t, m, "Approve")
	if a := <-res; !a.Approved {
		t.Fatalf("%+v", a)
	}
	if err := (PhoneConfig{Server: srv.URL, Topic: "a", Reply: "b", Token: "same", ButtonToken: "same"}).validate(); err == nil {
		t.Fatal("a button token equal to the access token was accepted")
	}
}

func TestPhoneTest(t *testing.T) {
	f, srv := newFakeNtfy(t)
	p := NewPhone(PhoneConfig{Server: srv.URL, Topic: NewTopic(), Reply: NewTopic()}, nil)
	done := make(chan error, 1)
	go func() { done <- p.Test(context.Background()) }()
	m, id := f.push(0)
	tap(t, m, "It works")
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if !f.wasDeleted(id) {
		t.Fatal("test push not removed")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	if err := p.Test(ctx); err == nil {
		t.Fatal("untapped test passed")
	}
}

func TestPhoneConfigStore(t *testing.T) {
	s := &secrets.Memory{}
	if _, err := LoadPhone(s); err != secrets.ErrNotFound {
		t.Fatalf("empty store: %v", err)
	}
	c := PhoneConfig{Server: "https://ntfy.sh", Topic: NewTopic(), Reply: NewTopic()}
	if len(c.Topic) != 30 || !validTopic(c.Topic) {
		t.Fatalf("topic %q", c.Topic)
	}
	if err := SavePhone(s, c); err != nil {
		t.Fatal(err)
	}
	got, err := LoadPhone(s)
	if err != nil || got != c {
		t.Fatalf("%+v %v", got, err)
	}
	if u := c.SubscribeURL(); u != "ntfy://ntfy.sh/"+c.Topic+"?display=Opfence" {
		t.Fatal(u)
	}
	if u := (PhoneConfig{Server: "http://10.0.0.2:8080/ntfy/", Topic: "a"}).SubscribeURL(); u != "ntfy://10.0.0.2:8080/ntfy/a?display=Opfence&secure=false" {
		t.Fatal(u)
	}
	for _, bad := range []PhoneConfig{
		{Server: "ntfy.sh", Topic: "a", Reply: "b"},
		{Server: "https://u:p@ntfy.sh", Topic: "a", Reply: "b"},
		{Server: "https://ntfy.sh", Topic: "a/b", Reply: "b"},
		{Server: "https://ntfy.sh", Topic: "a", Reply: "a"},
		{Server: "https://ntfy.sh", Topic: strings.Repeat("a", 65), Reply: "b"},
		{Server: "http://10.0.0.2:8080", Topic: "a", Reply: "b"},
	} {
		if SavePhone(s, bad) == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
	if err := DeletePhone(s); err != nil {
		t.Fatal(err)
	}
}

// A request dropped within the grace period never reaches the phone.
func TestPhoneGrace(t *testing.T) {
	f, srv := newFakeNtfy(t)
	p, b, _ := testPhone(t, srv, 100*time.Millisecond)
	p.grace = 300 * time.Millisecond
	waitSubscribed(t, f, p.cfg.Reply)
	for i := 0; i < 5; i++ {
		if a := b.Approve(context.Background(), pendingFor("railway.service.delete", classes.Delete, classes.Ask, "svc-1", byte(i))); a.Approved {
			t.Fatal("approved")
		}
	}
	time.Sleep(400 * time.Millisecond)
	f.mu.Lock()
	n := len(f.pushes)
	f.mu.Unlock()
	if n != 0 {
		t.Fatalf("%d pushes for requests dropped at once", n)
	}
}

func TestPhoneRateLimit(t *testing.T) {
	p := NewPhone(PhoneConfig{}, nil)
	for i := 0; i < phoneBurst; i++ {
		if !p.allow() {
			t.Fatalf("push %d refused", i)
		}
	}
	if p.allow() {
		t.Fatal("burst not limited")
	}
	p.mu.Lock()
	p.filled = p.filled.Add(-phoneRefill)
	p.mu.Unlock()
	if !p.allow() || p.allow() {
		t.Fatal("refill should allow exactly one more")
	}
}

// A line longer than the limit on the reply topic is skipped, and answers
// after it still arrive.
func TestPhoneOversizedLine(t *testing.T) {
	f, srv := newFakeNtfy(t)
	p, b, logs := testPhone(t, srv, 5*time.Second)
	waitSubscribed(t, f, p.cfg.Reply)
	post(t, srv, p.cfg.Reply, strings.Repeat("x", 80<<10))
	res, _ := approveAsync(t, b, pendingFor("railway.service.delete", classes.Delete, classes.Ask, "svc-1", 1))
	m, _ := f.push(0)
	tap(t, m, "Approve")
	select {
	case a := <-res:
		if !a.Approved {
			t.Fatalf("%+v", a)
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("answer lost after an oversized line; log:\n%s", logs.String())
	}
}

// The ending (host, hash, warnings) survives long cards and paths, and the
// encoded push stays under ntfy's 8 KB JSON limit.
func TestPhoneTextLimits(t *testing.T) {
	v := View{
		Method: "POST", Host: "api.example.com", Path: "/" + strings.Repeat("&", 5000),
		Hash: "abcdef012345", Via: "weak", Resource: strings.Repeat("é", 300),
		Classes: []string{"delete"}, ConfirmText: "prod-db",
	}
	for i := 0; i < 12; i++ {
		v.Cards = append(v.Cards, strings.Repeat("€", 400))
	}
	text := phoneText(v)
	for _, want := range []string{"Request abcdef012345", "POST api.example.com/&", "Weak mode", "type prod-db", "more (opfence approve"} {
		if !strings.Contains(text, want) {
			t.Errorf("text lacks %q", want)
		}
	}
	if !utf8.ValidString(text) || len(text) > maxPhoneText {
		t.Fatalf("text: %d bytes, valid %v", len(text), utf8.ValidString(text))
	}
	f, srv := newFakeNtfy(t)
	_ = f
	p := NewPhone(PhoneConfig{Server: srv.URL, Topic: NewTopic(), Reply: NewTopic()}, nil)
	var size int
	srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		size = len(b)
		fmt.Fprint(w, `{"id":"x"}`)
	})
	if _, err := p.publish(context.Background(), phoneMessage{Topic: p.cfg.Topic, Title: phoneTitle(v), Message: text, Actions: []phoneAction{p.button("Deny", newToken())}}); err != nil {
		t.Fatal(err)
	}
	if size == 0 || size > 8192 {
		t.Fatalf("push body is %d bytes", size)
	}
}

// Network errors name the server, never the topic.
func TestPhoneErrorsHideTopics(t *testing.T) {
	cfg := PhoneConfig{Server: "http://127.0.0.1:1", Topic: NewTopic(), Reply: NewTopic()}
	p := NewPhone(cfg, nil)
	_, err1 := p.publish(context.Background(), phoneMessage{Topic: cfg.Topic})
	err2 := p.remove("abc")
	_, err3 := p.stream(context.Background(), "0", nil, func(string) {})
	for _, err := range []error{err1, err2, err3} {
		if err == nil || strings.Contains(err.Error(), cfg.Topic) || strings.Contains(err.Error(), cfg.Reply) || !strings.Contains(err.Error(), cfg.Server) {
			t.Errorf("error %v", err)
		}
	}
}

// A scoped approve that loses the race to a deny adds no grant.
func TestScopedAnswerAfterDenyAddsNoGrant(t *testing.T) {
	b := NewBroker(5*time.Second, passive{})
	res, v := approveAsync(t, b, pendingFor("railway.service.delete", classes.Delete, classes.Ask, "svc-1", 1))
	if err := b.Answer(Answer{ID: v.ID, Approve: false, Channel: "desktop"}); err != nil {
		t.Fatal(err)
	}
	_ = b.Answer(Answer{ID: v.ID, Approve: true, Scope: ScopeOffer, Channel: "phone"})
	if a := <-res; a.Approved {
		t.Fatalf("%+v", a)
	}
	res, _ = approveAsync(t, b, pendingFor("railway.service.delete", classes.Delete, classes.Ask, "svc-1", 2))
	select {
	case a := <-res:
		t.Fatalf("a grant approved the next request: %+v", a)
	case <-time.After(100 * time.Millisecond):
	}
}
