// Package engine ties the core together: it decodes a request into
// operations, matches each against the catalog, resolves its environment
// and decides what to do. It does no I/O.
package engine

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"unicode"

	"github.com/rakeshnitb23/opfence/internal/catalog"
	"github.com/rakeshnitb23/opfence/internal/classes"
	"github.com/rakeshnitb23/opfence/internal/decode"
	"github.com/rakeshnitb23/opfence/internal/policy"
	"github.com/rakeshnitb23/opfence/internal/request"
)

// Engine evaluates requests against a catalog and a policy.
type Engine struct {
	Catalog *catalog.Catalog
	Policy  *policy.Effective
	// IncludeDraft also applies draft rules (the fixture runner sets it;
	// otherwise the policy decides).
	IncludeDraft bool
}

// New returns an engine. A nil policy means defaults only.
func New(c *catalog.Catalog, p *policy.Effective) *Engine {
	if p == nil {
		p = policy.Resolve(nil, nil)
	}
	return &Engine{Catalog: c, Policy: p, IncludeDraft: p.IncludeDraft}
}

// Evaluation is the verdict on one operation.
type Evaluation struct {
	Op       decode.Operation
	Provider *catalog.Provider // nil for hosts not in the catalog
	Rule     *catalog.Rule     // nil when no rule matched
	Args     map[string]any    // operation args plus path parameters

	Class       classes.Class   // the class that produced Decision
	Classes     []classes.Class // every class the operation has (SQL can have several)
	ClassSource string

	Environment string
	EnvSource   string

	Decision       classes.Decision
	DecisionSource string

	Resource string // value of the rule's resource argument, if any
	Card     string // human description, from decoded arguments only
}

// Result is the verdict on a whole request.
type Result struct {
	Host        string
	Provider    *catalog.Provider // nil when the host is not in the catalog
	Evaluations []Evaluation
	Decision    classes.Decision // strictest over Evaluations
	// Hash identifies exactly what would run: provider, rules and
	// arguments of every operation. Approvals bind to it.
	Hash [32]byte
}

// UnknownHost reports whether the request's host is not in the catalog.
func (r Result) UnknownHost() bool { return r.Provider == nil }

// Evaluate decides a request.
func (e *Engine) Evaluate(r *request.Request) Result {
	p := e.Catalog.ProviderForHost(r.Host)
	res := Result{Host: r.Host, Provider: p}
	var ops []decode.Operation
	if p == nil {
		ops = decode.Decode(r, decode.Hints{})
	} else {
		ops = decode.Decode(r, p.Hints(r.Host))
	}
	for _, op := range ops {
		res.Evaluations = append(res.Evaluations, e.evaluate(p, r.Host, op))
	}
	res.finish()
	// Bind the hash to the exact body too, so a grant for one body can never
	// cover another sent to the same operation.
	bodyErr := ""
	if r.BodyErr != nil {
		bodyErr = r.BodyErr.Error()
	}
	res.Hash = sha256.Sum256(append(append(res.Hash[:], r.Body...), bodyErr...))
	return res
}

// EvaluateTool decides one MCP tool call made outside the proxy, such as a
// Claude Code tool call seen by the PreToolUse hook.
func (e *Engine) EvaluateTool(p *catalog.Provider, tool string, args map[string]any) Result {
	if args == nil {
		args = map[string]any{}
	}
	op := decode.Operation{Protocol: decode.MCP, MCPMethod: "tools/call", Tool: tool, Args: args}
	res := Result{Provider: p}
	res.Evaluations = []Evaluation{e.evaluate(p, "", op)}
	res.finish()
	return res
}

func (res *Result) finish() {
	ds := make([]classes.Decision, len(res.Evaluations))
	for i, ev := range res.Evaluations {
		ds[i] = ev.Decision
	}
	res.Decision = classes.Strictest(ds...)
	res.Hash = hashEvaluations(res.Host, res.Evaluations)
}

func (e *Engine) evaluate(p *catalog.Provider, host string, op decode.Operation) Evaluation {
	ev := Evaluation{Op: op, Provider: p, Args: map[string]any{}}
	for k, v := range op.Args {
		ev.Args[k] = v
	}

	switch {
	case p == nil:
		ev.Classes, ev.ClassSource = []classes.Class{classes.Unknown}, "host is not in the catalog"
	default:
		rule, params := p.Match(op, e.IncludeDraft)
		for k, v := range params {
			ev.Args[k] = v
		}
		if rule != nil {
			ev.Rule = rule
			ev.Classes, ev.ClassSource = rule.ClassesFor(op, ev.Args)
		} else {
			c, src := p.DefaultClass(op)
			ev.Classes, ev.ClassSource = []classes.Class{c}, src
		}
		if f := secretField(p, op); f != "" && !slices.Contains(ev.Classes, classes.Credential) {
			ev.Classes = append(ev.Classes, classes.Credential)
			ev.ClassSource += "; selects secret field " + f
		}
	}

	provID := ""
	if p != nil {
		provID = p.ID
	}
	ev.Environment, ev.EnvSource = e.Policy.Environment(provID, func(arg string) (string, bool) {
		v, ok := catalog.Lookup(ev.Args, arg)
		if !ok {
			return "", false
		}
		return catalog.Scalar(v)
	})

	ruleID := ""
	if ev.Rule != nil {
		ruleID = ev.Rule.ID
	}
	if len(ev.Classes) == 0 {
		ev.Classes = []classes.Class{classes.Unknown}
	}
	ev.Decision = -1
	for _, c := range ev.Classes {
		d, src := e.Policy.Decide(ruleID, c, ev.Environment)
		if d > ev.Decision {
			ev.Decision, ev.DecisionSource, ev.Class = d, src, c
		}
	}

	if ev.Rule != nil && ev.Rule.Resource != nil {
		if v, ok := catalog.Lookup(ev.Args, ev.Rule.Resource.Arg); ok {
			if s, ok := catalog.Scalar(v); ok {
				// The resource is shown in approval prompts and the hook's
				// reason, and comes from the request.
				ev.Resource = Sanitize(s, 200)
			}
		}
	}
	ev.Card = card(ev, host)
	return ev
}

// secretField returns the first field op selects that p lists as secret.
func secretField(p *catalog.Provider, op decode.Operation) string {
	if op.Protocol != decode.GraphQL {
		return ""
	}
	for _, f := range op.Selected {
		if slices.Contains(p.Defaults.GraphQLSecretFields, f) {
			return f
		}
	}
	return ""
}

var placeholderRe = regexp.MustCompile(`\{([^{}]*)\}`)

// card renders the approval text from the rule's template and the decoded
// arguments, never from anything the agent wrote about the request.
func card(ev Evaluation, host string) string {
	if ev.Rule != nil && ev.Rule.Card != "" {
		return placeholderRe.ReplaceAllStringFunc(ev.Rule.Card, func(m string) string {
			v, ok := catalog.Lookup(ev.Args, m[1:len(m)-1])
			if !ok {
				return "(none)"
			}
			s, ok := catalog.Scalar(v)
			if !ok {
				b, _ := json.Marshal(v)
				s = string(b)
			}
			return Sanitize(s, 80)
		})
	}
	op := ev.Op
	name := host
	if ev.Provider != nil {
		name = ev.Provider.Title
	}
	switch op.Protocol {
	case decode.GraphQL:
		return fmt.Sprintf("%s GraphQL %s %s", name, op.GraphQLType, Sanitize(op.Field, 80))
	case decode.MCP:
		if op.Tool != "" {
			if strings.HasSuffix(name, " MCP") {
				return fmt.Sprintf("%s tool %s", name, Sanitize(op.Tool, 80))
			}
			return fmt.Sprintf("%s MCP tool %s", name, Sanitize(op.Tool, 80))
		}
		return fmt.Sprintf("%s MCP %s", name, Sanitize(op.MCPMethod, 80))
	case decode.AWS:
		if op.Action != "" {
			return fmt.Sprintf("AWS %s %s", op.Service, Sanitize(op.Action, 80))
		}
		return fmt.Sprintf("AWS %s %s %s", op.Service, op.Method, Sanitize(op.Path, 120))
	}
	return fmt.Sprintf("%s %s %s", Sanitize(op.Method, 16), Sanitize(host, 80), Sanitize(op.Path, 120))
}

// Sanitize makes untrusted text safe to show on a card: control characters,
// bidirectional overrides and zero-width characters are replaced, and the
// text is cut to max runes.
func Sanitize(s string, max int) string {
	var b strings.Builder
	n := 0
	for _, r := range s {
		if n == max {
			b.WriteString("…")
			break
		}
		switch {
		case r == '\n' || r == '\r' || r == '\t':
			r = ' '
		case unicode.IsControl(r),
			r >= 0x202A && r <= 0x202E, r >= 0x2066 && r <= 0x2069,
			r >= 0x200B && r <= 0x200F, r == 0xFEFF, r == 0x2028, r == 0x2029:
			r = '�'
		}
		b.WriteRune(r)
		n++
	}
	return b.String()
}

// hashEvaluations hashes a canonical form of what the request would do.
// encoding/json sorts map keys, so equal requests hash equally.
func hashEvaluations(host string, evs []Evaluation) [32]byte {
	type canon struct {
		Provider, Rule, Protocol, Method, Path, Type, Field, Tool, MCPMethod, Service, Action string
		Args                                                                                  map[string]any
	}
	cs := make([]canon, len(evs))
	for i, ev := range evs {
		c := canon{Protocol: ev.Op.Protocol, Method: ev.Op.Method, Path: ev.Op.Path, Type: ev.Op.GraphQLType,
			Field: ev.Op.Field, Tool: ev.Op.Tool, MCPMethod: ev.Op.MCPMethod, Service: ev.Op.Service, Action: ev.Op.Action, Args: ev.Args}
		if ev.Provider != nil {
			c.Provider = ev.Provider.ID
		}
		if ev.Rule != nil {
			c.Rule = ev.Rule.ID
		}
		cs[i] = c
	}
	b, err := json.Marshal(struct {
		Host string
		Ops  []canon
	}{host, cs})
	if err != nil {
		// Args come from decoders and only hold JSON-compatible values;
		// should that ever fail, make the hash unique so no grant matches.
		b = []byte(fmt.Sprintf("unhashable %p", &evs))
	}
	return sha256.Sum256(b)
}
