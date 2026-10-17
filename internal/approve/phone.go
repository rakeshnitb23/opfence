package approve

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/rakeshnitb23/opfence/internal/secrets"
)

// PhoneConfig is what `opfence phone setup` keeps in the keychain. Topic is
// a bearer secret: anyone who can read it sees the pushes and can tap their
// buttons, so it never goes in a file the agent could read.
type PhoneConfig struct {
	Server string `json:"server"`          // ntfy server, such as https://ntfy.sh
	Topic  string `json:"topic"`           // the phone subscribes here
	Reply  string `json:"reply"`           // buttons post answers here; only Opfence reads it
	Token  string `json:"token,omitempty"` // ntfy access token, for servers that need one
}

// phoneAccount is the keychain item holding the PhoneConfig.
const phoneAccount = "phone"

// LoadPhone returns the stored phone settings, or secrets.ErrNotFound.
func LoadPhone(s secrets.Store) (PhoneConfig, error) {
	var c PhoneConfig
	raw, err := s.Get(phoneAccount)
	if err != nil {
		return c, err
	}
	if err := json.Unmarshal([]byte(raw), &c); err != nil {
		return c, fmt.Errorf("keychain item %q: %w", phoneAccount, err)
	}
	return c, c.validate()
}

// SavePhone stores phone settings.
func SavePhone(s secrets.Store, c PhoneConfig) error {
	if err := c.validate(); err != nil {
		return err
	}
	b, _ := json.Marshal(c)
	return s.Set(phoneAccount, string(b))
}

// DeletePhone removes the phone settings.
func DeletePhone(s secrets.Store) error { return s.Delete(phoneAccount) }

func (c PhoneConfig) validate() error {
	u, err := url.Parse(c.Server)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.RawQuery != "" || u.User != nil {
		return fmt.Errorf("ntfy server %q: want a URL like https://ntfy.sh", c.Server)
	}
	if u.Scheme == "http" && !loopback(u.Hostname()) {
		// Anyone on the network could read the pushes and tap them.
		return fmt.Errorf("ntfy server %q: use https (plain http is only accepted on this computer)", c.Server)
	}
	for _, t := range []string{c.Topic, c.Reply} {
		if !validTopic(t) {
			return fmt.Errorf("ntfy topic %q: want 1 to 64 letters, digits, - or _", t)
		}
	}
	if c.Topic == c.Reply {
		return errors.New("the push and reply topics must differ")
	}
	return nil
}

func loopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func validTopic(t string) bool {
	if t == "" || len(t) > 64 {
		return false
	}
	for _, r := range t {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
			return false
		}
	}
	return true
}

// NewTopic returns a random topic name with 128 bits of entropy.
func NewTopic() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return "opf-" + strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b[:]))
}

// SubscribeURL is the link that subscribes the ntfy app to the push topic:
// an ntfy:// deep link, which the Android app opens directly.
func (c PhoneConfig) SubscribeURL() string {
	u, _ := url.Parse(c.Server)
	q := "?display=Opfence"
	if u.Scheme == "http" {
		q += "&secure=false"
	}
	return "ntfy://" + u.Host + strings.TrimSuffix(u.Path, "/") + "/" + c.Topic + q
}

// WebURL is the push topic in ntfy's web app.
func (c PhoneConfig) WebURL() string { return strings.TrimSuffix(c.Server, "/") + "/" + c.Topic }

// Phone sends each pending request to the ntfy app as a push with action
// buttons (docs/ARCHITECTURE.md §8.5). A button makes the phone post a
// random token to the reply topic; each token stands for exactly one answer
// to one request and is forgotten when the request ends, so an answer
// cannot be moved to another request, turned from deny into approve, or
// replayed. A phone cannot type, so a confirm push offers Deny only.
type Phone struct {
	cfg    PhoneConfig
	client *http.Client
	logf   func(format string, args ...any)
	idle   time.Duration // reconnect after this long without a line
	grace  time.Duration // a request must wait this long before it is pushed

	sending chan struct{} // bounds publishes in flight

	mu     sync.Mutex
	tokens map[string]Answer // token -> the answer it gives
	bucket float64           // pushes allowed now, refilled over time
	filled time.Time
}

// Each request costs two ntfy messages (the push and its removal), and
// ntfy.sh allows 250 a day per address. phoneBurst pushes may go at once,
// then one per phoneRefill, so a flood of requests cannot use up the day's
// quota in minutes.
const (
	phoneBurst  = 10
	phoneRefill = 2 * time.Minute
)

// allow takes one push from the rate limit.
func (p *Phone) allow() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now()
	if p.filled.IsZero() {
		p.bucket = phoneBurst
	} else {
		p.bucket = min(phoneBurst, p.bucket+float64(now.Sub(p.filled))/float64(phoneRefill))
	}
	p.filled = now
	if p.bucket < 1 {
		return false
	}
	p.bucket--
	return true
}

// NewPhone returns the phone channel. logf receives delivery problems.
func NewPhone(cfg PhoneConfig, logf func(format string, args ...any)) *Phone {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	return &Phone{
		cfg: cfg,
		// No overall timeout: Listen holds one long-lived stream.
		client:  &http.Client{Transport: http.DefaultTransport},
		logf:    logf,
		idle:    2 * time.Minute,
		grace:   1500 * time.Millisecond,
		sending: make(chan struct{}, 4),
		tokens:  map[string]Answer{},
	}
}

// Name implements Channel.
func (*Phone) Name() string { return "phone" }

// phoneMessage is ntfy's JSON publish format.
type phoneMessage struct {
	Topic    string        `json:"topic"`
	Title    string        `json:"title,omitempty"`
	Message  string        `json:"message"`
	Priority int           `json:"priority,omitempty"`
	Tags     []string      `json:"tags,omitempty"`
	Actions  []phoneAction `json:"actions,omitempty"`
}

type phoneAction struct {
	Action  string            `json:"action"`
	Label   string            `json:"label"`
	URL     string            `json:"url"`
	Method  string            `json:"method,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
	Body    string            `json:"body,omitempty"`
	Clear   bool              `json:"clear,omitempty"`
}

// maxPhoneText keeps a push under ntfy's 4,096-byte message limit, past
// which it would arrive as an attachment.
const maxPhoneText = 3500

// Show implements Channel: it publishes one push, waits for the request to
// end, then removes the push from the phone.
func (p *Phone) Show(ctx context.Context, v View, b *Broker) {
	var issued []string
	issue := func(a Answer) string {
		t := newToken()
		a.ID, a.Channel = v.ID, "phone"
		p.mu.Lock()
		p.tokens[t] = a
		p.mu.Unlock()
		issued = append(issued, t)
		return t
	}
	defer func() {
		p.mu.Lock()
		for _, t := range issued {
			delete(p.tokens, t)
		}
		p.mu.Unlock()
	}()

	actions := []phoneAction{p.button("Deny", issue(Answer{Approve: false}))}
	if v.ConfirmText == "" {
		actions = append(actions, p.button("Approve", issue(Answer{Approve: true})))
		if v.Scopable {
			actions = append(actions, p.button("Approve 10 min", issue(Answer{Approve: true, Scope: ScopeOffer})))
		}
	}
	msg := phoneMessage{
		Topic:    p.cfg.Topic,
		Title:    phoneTitle(v),
		Message:  phoneText(v),
		Priority: 4,
		Tags:     []string{"warning"},
		Actions:  actions,
	}
	// Requests cancelled at once (an agent opening and dropping
	// connections) never reach the phone, so they cannot spend the ntfy
	// quota or bury real requests.
	select {
	case <-ctx.Done():
		return
	case <-time.After(p.grace):
	}
	if !p.allow() {
		p.logf("phone approvals: request %s not sent to your phone: more than %d requests in a short time", v.Hash, phoneBurst)
		return
	}
	select {
	case p.sending <- struct{}{}:
	case <-ctx.Done():
		return
	}
	// Not bound to ctx: the phone can answer before ntfy's reply to the
	// publish arrives, and the push must still be removed then.
	id, err := p.publish(context.Background(), msg)
	<-p.sending
	if err != nil {
		p.logf("phone approvals: could not send request %s: %v", v.Hash, err)
		return
	}
	<-ctx.Done() // answered anywhere, timed out or cancelled
	if err := p.remove(id); err != nil {
		p.logf("phone approvals: could not remove the push for request %s: %v", v.Hash, err)
	}
}

func (p *Phone) button(label, token string) phoneAction {
	a := phoneAction{Action: "http", Label: label, URL: p.topicURL(p.cfg.Reply), Method: http.MethodPost, Body: token, Clear: true}
	if p.cfg.Token != "" {
		a.Headers = map[string]string{"Authorization": "Bearer " + p.cfg.Token}
	}
	return a
}

func phoneTitle(v View) string {
	verb := "Approve"
	if v.ConfirmText != "" {
		verb = "Confirm"
	}
	t := fmt.Sprintf("%s: %s", verb, strings.Join(uniq(v.Classes), ", "))
	if v.Environment != "" {
		t += " in " + v.Environment
	}
	return t
}

func phoneText(v View) string {
	// The ending says what and where; it is written whole, and the cards
	// get what room is left.
	var tail strings.Builder
	if v.Resource != "" {
		fmt.Fprintf(&tail, "\nResource: %s", clip(v.Resource, 200))
	}
	fmt.Fprintf(&tail, "\n%s %s%s\nRequest %s", v.Method, v.Host, clip(v.Path, 300), v.Hash)
	if n := ViaNote(v.Via); n != "" {
		tail.WriteString("\n" + n)
	}
	if v.ConfirmText != "" {
		fmt.Fprintf(&tail, "\n\nThis needs confirming at your computer: type %s in the dialog or in opfence approve. You can deny it here.", clip(v.ConfirmText, 200))
	}
	room := maxPhoneText - tail.Len()
	var s strings.Builder
	for i, c := range v.Cards {
		c = clip(c, 300) + "\n"
		if i == maxDialogCards || s.Len()+len(c) > room-60 {
			fmt.Fprintf(&s, "+%d more (opfence approve lists them all)\n", len(v.Cards)-i)
			break
		}
		s.WriteString(c)
	}
	return s.String() + tail.String()
}

// clip shortens s to at most n bytes without splitting a character.
func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n] + "…"
}

// Listen reads answers from the reply topic until ctx ends, reconnecting
// after errors without missing answers posted in between.
func (p *Phone) Listen(ctx context.Context, b *Broker) {
	p.listen(ctx, nil, func(msg string) { p.answer(b, msg) })
}

// listen streams the reply topic, calling fn with each message, until ctx
// ends. ready, when not nil, is closed once the first connection is open.
func (p *Phone) listen(ctx context.Context, ready chan struct{}, fn func(string)) {
	since := fmt.Sprint(time.Now().Add(-time.Minute).Unix())
	backoff := time.Second
	for ctx.Err() == nil {
		last, err := p.stream(ctx, since, ready, fn)
		if last != "" {
			since, backoff = last, time.Second
		}
		if ctx.Err() != nil {
			return
		}
		p.logf("phone approvals: reading answers: %v (retrying)", err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, 30*time.Second)
	}
}

// phoneEvent is one line of ntfy's JSON stream.
type phoneEvent struct {
	ID      string `json:"id"`
	Event   string `json:"event"`
	Topic   string `json:"topic"`
	Message string `json:"message"`
}

// stream reads one connection's messages and returns the id of the last
// one, from which a reconnect resumes.
func (p *Phone) stream(ctx context.Context, since string, ready chan struct{}, fn func(string)) (last string, err error) {
	// ntfy sends a keepalive every 45 s; a connection silent for longer
	// than p.idle has died without telling us.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	idle := time.AfterFunc(p.idle, cancel)
	defer idle.Stop()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.topicURL(p.cfg.Reply)+"/json?since="+url.QueryEscape(since), nil)
	if err != nil {
		return "", err
	}
	p.auth(req)
	resp, err := p.client.Do(req)
	if err != nil {
		return "", p.netErr(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%s answered %s", p.cfg.Server, resp.Status)
	}
	if ready != nil {
		select {
		case <-ready:
		default:
			close(ready)
		}
	}
	r := bufio.NewReaderSize(resp.Body, 4096)
	for {
		line, err := readLine(r, maxPhoneLine)
		if err != nil {
			return last, err
		}
		idle.Reset(p.idle)
		var ev phoneEvent
		if line == nil || json.Unmarshal(line, &ev) != nil || ev.Event != "message" || ev.Topic != p.cfg.Reply {
			continue // over-long lines are skipped: answers are short
		}
		last = ev.ID
		fn(strings.TrimSpace(ev.Message))
	}
}

// maxPhoneLine is the longest stream line read; anyone who knows the reply
// topic can post longer ones, which are skipped rather than stopping the
// stream.
const maxPhoneLine = 16 << 10

// readLine returns the next line, or nil for a line longer than max (which
// it discards). io.EOF at the end becomes io.ErrUnexpectedEOF: the stream
// should never end.
func readLine(r *bufio.Reader, max int) ([]byte, error) {
	var line []byte
	tooLong := false
	for {
		frag, isPrefix, err := r.ReadLine()
		if err != nil {
			if err == io.EOF {
				err = io.ErrUnexpectedEOF
			}
			return nil, err
		}
		if !tooLong {
			if len(line)+len(frag) > max {
				tooLong, line = true, nil
			} else {
				line = append(line, frag...)
			}
		}
		if !isPrefix {
			if tooLong {
				return nil, nil
			}
			if line == nil {
				line = []byte{}
			}
			return line, nil
		}
	}
}

// answer applies the answer a token stands for. Unknown tokens (forged,
// replayed, or for a request that has ended) are ignored.
func (p *Phone) answer(b *Broker, token string) {
	p.mu.Lock()
	a, ok := p.tokens[token]
	if ok {
		// One answer per request: drop every token for it.
		for t, x := range p.tokens {
			if x.ID == a.ID {
				delete(p.tokens, t)
			}
		}
	}
	p.mu.Unlock()
	if !ok {
		return
	}
	if err := b.Answer(a); err != nil && !errors.Is(err, ErrUnknown) {
		p.logf("phone approvals: %v", err)
	}
}

// Test sends a push with one button and waits for it to be tapped, proving
// that the phone receives pushes and that its answers reach Opfence.
func (p *Phone) Test(ctx context.Context) error {
	token := newToken()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	got := make(chan struct{})
	var once sync.Once
	ready := make(chan struct{})
	go p.listen(ctx, ready, func(msg string) {
		if msg == token {
			once.Do(func() { close(got) })
		}
	})
	select {
	case <-ready:
	case <-time.After(15 * time.Second):
		return fmt.Errorf("could not read the reply topic on %s", p.cfg.Server)
	case <-ctx.Done():
		return ctx.Err()
	}
	id, err := p.publish(ctx, phoneMessage{
		Topic:    p.cfg.Topic,
		Title:    "Opfence phone approvals",
		Message:  "Tap the button to check that your answers reach Opfence.",
		Priority: 3,
		Actions:  []phoneAction{p.button("It works", token)},
	})
	if err != nil {
		return err
	}
	defer p.remove(id)
	select {
	case <-got:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// remove deletes a push from the phone. Servers older than ntfy 2.12
// cannot delete; the push then stays until dismissed.
func (p *Phone) remove(id string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return p.do(ctx, http.MethodDelete, p.topicURL(p.cfg.Topic)+"/"+url.PathEscape(id), nil)
}

// publish sends a push and returns its message id.
func (p *Phone) publish(ctx context.Context, m phoneMessage) (string, error) {
	// Without HTML escaping, < > & stay one byte each, so the body stays
	// under ntfy's JSON limit (twice its 4,096-byte message limit).
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(m); err != nil {
		return "", err
	}
	body := buf.Bytes()
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimSuffix(p.cfg.Server, "/")+"/", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	p.auth(req)
	resp, err := p.client.Do(req)
	if err != nil {
		return "", p.netErr(err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode != http.StatusOK {
		msg := fmt.Sprintf("%s answered %s", p.cfg.Server, resp.Status)
		if resp.StatusCode == http.StatusTooManyRequests {
			msg += " (the server's message quota is used up; phone approvals resume when it resets. ntfy.sh allows 250 messages a day per address; an ntfy account or your own server allows more)"
		}
		return "", errors.New(msg)
	}
	var r struct {
		ID string `json:"id"`
	}
	if json.Unmarshal(data, &r) != nil || r.ID == "" {
		return "", fmt.Errorf("%s did not return a message id", p.cfg.Server)
	}
	return r.ID, nil
}

func (p *Phone) do(ctx context.Context, method, u string, body io.Reader) error {
	req, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		return err
	}
	p.auth(req)
	resp, err := p.client.Do(req)
	if err != nil {
		return p.netErr(err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("%s answered %s", p.cfg.Server, resp.Status)
	}
	return nil
}

// netErr drops the URL from a network error: it holds a topic, which is a
// secret, and errors end up in opfence.log.
func (p *Phone) netErr(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return fmt.Errorf("%s %s: %w", ue.Op, p.cfg.Server, ue.Err)
	}
	return err
}

func (p *Phone) auth(r *http.Request) {
	if p.cfg.Token != "" {
		r.Header.Set("Authorization", "Bearer "+p.cfg.Token)
	}
}

func (p *Phone) topicURL(topic string) string {
	return strings.TrimSuffix(p.cfg.Server, "/") + "/" + topic
}

func newToken() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return "opf1" + base64.RawURLEncoding.EncodeToString(b[:])
}
