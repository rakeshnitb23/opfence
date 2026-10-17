// Package approve holds requests that need a human, shows them on every
// approval channel, and turns the first valid answer into a single-use
// approval bound to that request (docs/ARCHITECTURE.md §8.5).
package approve

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/rakeshnitb23/opfence/internal/classes"
	"github.com/rakeshnitb23/opfence/internal/engine"
	"github.com/rakeshnitb23/opfence/internal/proxy"
)

// MaxScope is the longest a scoped grant may last.
const MaxScope = time.Hour

// maxPending bounds how many requests may wait at once; more are denied, so
// an agent cannot bury the human in prompts.
const maxPending = 20

// View is what channels show about a pending request. It holds only decoded,
// sanitised fields, never bodies or credentials.
type View struct {
	ID          string    `json:"id"`
	Host        string    `json:"host"`
	Method      string    `json:"method"`
	Path        string    `json:"path"`
	Decision    string    `json:"decision"` // ask or confirm
	Cards       []string  `json:"cards"`
	Rules       []string  `json:"rules"`
	Classes     []string  `json:"classes"`
	Environment string    `json:"environment"`
	Resource    string    `json:"resource,omitempty"`
	Hash        string    `json:"hash"` // first 12 hex digits, to tell requests apart
	Via         string    `json:"via,omitempty"`
	ConfirmText string    `json:"confirm_text,omitempty"`
	Scopable    bool      `json:"scopable"` // a time-limited grant may be offered
	Expires     time.Time `json:"expires"`
}

// Answer is a human's answer to one pending request.
type Answer struct {
	ID      string        `json:"id"`
	Approve bool          `json:"approve"`
	Typed   string        `json:"typed,omitempty"` // for confirm: must equal ConfirmText
	Scope   time.Duration `json:"scope,omitempty"` // >0: also approve the same operation for this long
	Channel string        `json:"-"`
}

// Channel shows a pending request to a human and reports their answer with
// Broker.Answer. Show runs until the request is answered elsewhere (ctx is
// cancelled) or it gets an answer.
type Channel interface {
	Name() string
	Show(ctx context.Context, v View, b *Broker)
}

// Grant approves later requests for the same rules, resource, environment
// and host until it expires. Grants never cover confirm decisions or
// credential operations.
type Grant struct {
	Rules       []string
	Resource    string
	Environment string
	Host        string
	// Ops identifies every operation the approved request ran: rule,
	// environment, resource and top-level arguments (path parameters, a
	// repository's owner, a ref). A later request is covered only when it
	// runs the same set.
	Ops     []string
	Expires time.Time
}

// volatileArgs change on every request of the same kind (git object ids),
// so a grant does not compare them.
var volatileArgs = map[string]bool{"old": true, "new": true}

// opScope identifies one operation for grants.
func opScope(ev engine.Evaluation) string {
	rule := ""
	if ev.Rule != nil {
		rule = ev.Rule.ID
	}
	var args []string
	for k, v := range ev.Args {
		if s, ok := v.(string); ok && !volatileArgs[k] {
			args = append(args, k+"="+s)
		}
	}
	slices.Sort(args)
	b, _ := json.Marshal([]any{rule, ev.Environment, ev.Resource, args})
	return string(b)
}

type pending struct {
	view   View
	hash   [32]byte
	grant  Grant // what a scoped answer would grant
	result chan proxy.Approval
	once   sync.Once
}

// Broker implements proxy.Approver.
type Broker struct {
	timeout  time.Duration
	channels []Channel
	now      func() time.Time

	mu       sync.Mutex
	pending  map[string]*pending
	grants   []Grant
	watchers map[chan View]struct{}
}

// NewBroker returns a broker that denies requests nobody answers within
// timeout.
func NewBroker(timeout time.Duration, channels ...Channel) *Broker {
	return &Broker{
		timeout:  timeout,
		channels: channels,
		now:      time.Now,
		pending:  map[string]*pending{},
		watchers: map[chan View]struct{}{},
	}
}

// Approve implements proxy.Approver.
func (b *Broker) Approve(ctx context.Context, p proxy.Pending) proxy.Approval {
	res := p.Result
	v, g := b.describe(p)
	if v.Scopable && b.granted(g) {
		return proxy.Approval{Approved: true, Channel: "grant"}
	}
	if len(b.channels) == 0 && b.watcherCount() == 0 {
		return proxy.Approval{Reason: "Opfence needs a human to approve this, and no approval channel is running."}
	}
	item := &pending{view: v, hash: res.Hash, grant: g, result: make(chan proxy.Approval, 1)}
	b.mu.Lock()
	if len(b.pending) >= maxPending {
		b.mu.Unlock()
		return proxy.Approval{Reason: "Too many requests are already waiting for approval."}
	}
	b.pending[v.ID] = item
	for w := range b.watchers {
		select {
		case w <- v:
		default: // a slow watcher misses the push; it can still list
		}
	}
	b.mu.Unlock()
	defer func() {
		b.mu.Lock()
		delete(b.pending, v.ID)
		b.mu.Unlock()
	}()

	ctx, cancel := context.WithTimeout(ctx, b.timeout)
	defer cancel()
	for _, ch := range b.channels {
		go ch.Show(ctx, v, b)
	}
	select {
	case a := <-item.result:
		return a
	case <-ctx.Done():
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return proxy.Approval{Reason: fmt.Sprintf("Nobody approved this within %s, so Opfence denied it.", b.timeout)}
		}
		return proxy.Approval{Reason: "The request was cancelled while waiting for approval."}
	}
}

func (b *Broker) describe(p proxy.Pending) (View, Grant) {
	res := p.Result
	v := View{
		ID:       newID(),
		Host:     p.Host,
		Method:   p.Method,
		Path:     p.Path,
		Via:      p.Via,
		Decision: res.Decision.String(),
		Hash:     hex.EncodeToString(res.Hash[:6]),
		Expires:  b.now().Add(b.timeout),
	}
	scopable := res.Decision == classes.Ask
	// Strictest first, so the operation that needs approval leads the list
	// however many harmless ones the request carries.
	evs := slices.Clone(res.Evaluations)
	slices.SortStableFunc(evs, func(a, b engine.Evaluation) int { return int(b.Decision) - int(a.Decision) })
	for _, ev := range evs {
		v.Cards = append(v.Cards, ev.Card)
		v.Classes = append(v.Classes, string(ev.Class))
		if ev.Rule != nil && !slices.Contains(v.Rules, ev.Rule.ID) {
			v.Rules = append(v.Rules, ev.Rule.ID)
		}
		if ev.Decision == res.Decision {
			if v.Environment == "" {
				v.Environment = ev.Environment
			}
			if v.Resource == "" {
				v.Resource = ev.Resource
			}
		}
		if ev.Class == classes.Credential || ev.Rule == nil {
			scopable = false // unknown operations are never pre-approved either
		}
	}
	slices.Sort(v.Rules)
	if res.Decision == classes.Confirm {
		v.ConfirmText = v.Resource
		if v.ConfirmText == "" {
			v.ConfirmText = p.Host
		}
	}
	v.Scopable = scopable
	var ops []string
	for _, ev := range res.Evaluations {
		if sc := opScope(ev); !slices.Contains(ops, sc) {
			ops = append(ops, sc)
		}
	}
	slices.Sort(ops)
	return v, Grant{Rules: v.Rules, Resource: v.Resource, Environment: v.Environment, Host: p.Host, Ops: ops}
}

// ViaNote says where a request came from when that is not the agent's
// sandbox, or "" when it is (or the proxy runs on its own).
func ViaNote(via string) string {
	switch via {
	case "agent":
		return "From the agent itself or an MCP server, outside its sandbox."
	case "weak":
		return "Weak mode: this program is not sandboxed and could reach the API without Opfence."
	}
	return ""
}

func (b *Broker) granted(g Grant) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.now()
	b.grants = slices.DeleteFunc(b.grants, func(x Grant) bool { return !now.Before(x.Expires) })
	for _, x := range b.grants {
		if slices.Equal(x.Rules, g.Rules) && x.Resource == g.Resource && x.Environment == g.Environment && x.Host == g.Host && slices.Equal(x.Ops, g.Ops) {
			return true
		}
	}
	return false
}

// ErrUnknown is returned for an answer to a request that is not waiting
// (already answered, timed out, or never existed).
var ErrUnknown = errors.New("no request with that id is waiting")

// Answer applies a human's answer. A confirm request is approved only when
// the typed text matches exactly; a wrong text leaves it waiting.
func (b *Broker) Answer(a Answer) error {
	b.mu.Lock()
	item, ok := b.pending[a.ID]
	b.mu.Unlock()
	if !ok {
		return ErrUnknown
	}
	if !a.Approve {
		item.finish(proxy.Approval{Channel: a.Channel, Reason: "A human denied this request (" + a.Channel + ")."})
		return nil
	}
	if item.view.ConfirmText != "" && strings.TrimSpace(a.Typed) != item.view.ConfirmText {
		return fmt.Errorf("type %q exactly to approve", item.view.ConfirmText)
	}
	if a.Scope > 0 {
		if !item.view.Scopable {
			return errors.New("this request can only be approved once: it is a confirm, credential or unknown operation")
		}
		if a.Scope > MaxScope {
			return fmt.Errorf("a grant can last at most %s", MaxScope)
		}
		g := item.grant
		g.Expires = b.now().Add(a.Scope)
		b.mu.Lock()
		b.grants = append(b.grants, g)
		b.mu.Unlock()
	}
	item.finish(proxy.Approval{Approved: true, Channel: a.Channel})
	return nil
}

func (p *pending) finish(a proxy.Approval) {
	p.once.Do(func() { p.result <- a })
}

// List returns the requests waiting now, oldest first.
func (b *Broker) List() []View {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]View, 0, len(b.pending))
	for _, p := range b.pending {
		out = append(out, p.view)
	}
	slices.SortFunc(out, func(x, y View) int { return x.Expires.Compare(y.Expires) })
	return out
}

// Watch delivers each new pending request until cancel is called.
func (b *Broker) Watch() (<-chan View, func()) {
	ch := make(chan View, 16)
	b.mu.Lock()
	b.watchers[ch] = struct{}{}
	b.mu.Unlock()
	return ch, func() {
		b.mu.Lock()
		delete(b.watchers, ch)
		b.mu.Unlock()
	}
}

func (b *Broker) watcherCount() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.watchers)
}

func newID() string {
	var x [8]byte
	_, _ = rand.Read(x[:])
	return hex.EncodeToString(x[:])
}
