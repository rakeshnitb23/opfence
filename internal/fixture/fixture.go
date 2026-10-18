// Package fixture replays every catalog rule's recorded requests and checks
// that each is classified the way the rule claims (`opfence test`).
package fixture

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/fs"
	"path"
	"strings"

	"github.com/rakeshnitb23/opfence/internal/catalog"
	"github.com/rakeshnitb23/opfence/internal/classes"
	"github.com/rakeshnitb23/opfence/internal/engine"
	"github.com/rakeshnitb23/opfence/internal/request"
)

// Outcome is the result of one rule test.
type Outcome struct {
	Rule    *catalog.Rule
	Fixture string // path within the catalog FS
	Pass    bool
	Problem string // why it failed
}

// Report is the result of a whole run.
type Report struct {
	Outcomes []Outcome
	Failed   int
}

// Run replays every test of every rule, draft rules included, using only
// the catalog (no user policy), so results do not depend on who runs them.
func Run(c *catalog.Catalog) Report {
	eng := engine.New(c, nil)
	eng.IncludeDraft = true
	var rep Report
	for _, r := range c.Rules() {
		for _, t := range r.Tests {
			o := runOne(eng, c, r, t)
			if !o.Pass {
				rep.Failed++
			}
			rep.Outcomes = append(rep.Outcomes, o)
		}
	}
	return rep
}

func runOne(eng *engine.Engine, c *catalog.Catalog, r *catalog.Rule, t catalog.Test) Outcome {
	file := path.Join(r.Provider.Dir, t.Fixture)
	o := Outcome{Rule: r, Fixture: file}
	fail := func(format string, args ...any) Outcome {
		o.Problem = fmt.Sprintf(format, args...)
		return o
	}
	data, err := fs.ReadFile(c.FS, file)
	if err != nil {
		return fail("%v", err)
	}
	var res engine.Result
	if strings.HasSuffix(file, ".json") {
		// A tool call as the agent hook sees it, for MCP servers that run
		// on the user's machine and have no host the proxy could route by.
		if r.Provider.MCP == nil {
			return fail("tool-call fixtures are for MCP providers")
		}
		call, err := ParseToolCall(data)
		if err != nil {
			return fail("%v", err)
		}
		res = eng.EvaluateTool(r.Provider, call.Tool, call.Arguments)
		return check(o, r, t, res)
	}
	req, _, err := request.ParseFixture(data)
	if err != nil {
		return fail("%v", err)
	}
	res = eng.Evaluate(req)
	if res.Provider != r.Provider {
		owner := "no provider"
		if res.Provider != nil {
			owner = "provider " + res.Provider.ID
		}
		return fail("fixture host %s belongs to %s, not %s", req.Host, owner, r.Provider.ID)
	}
	return check(o, r, t, res)
}

// ToolCall is a .json fixture: one MCP tool call with its arguments.
type ToolCall struct {
	Description string         `json:"description"`
	Tool        string         `json:"tool"`
	Arguments   map[string]any `json:"arguments"`
}

// ParseToolCall parses a tool-call fixture. Numbers stay json.Number, as
// they do in the hook.
func ParseToolCall(data []byte) (*ToolCall, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	dec.DisallowUnknownFields()
	var c ToolCall
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("tool-call fixture: %w", err)
	}
	if c.Tool == "" {
		return nil, fmt.Errorf("tool-call fixture has no tool")
	}
	if c.Arguments == nil {
		c.Arguments = map[string]any{}
	}
	return &c, nil
}

// check finds r's evaluation in res and compares it with t.
func check(o Outcome, r *catalog.Rule, t catalog.Test, res engine.Result) Outcome {
	fail := func(format string, args ...any) Outcome {
		o.Problem = fmt.Sprintf(format, args...)
		return o
	}
	var seen []string
	for _, ev := range res.Evaluations {
		if ev.Rule != r {
			switch {
			case ev.Rule != nil:
				seen = append(seen, "rule "+ev.Rule.ID)
			case ev.Op.Error != "":
				seen = append(seen, "decode error: "+ev.Op.Error)
			default:
				seen = append(seen, "unmatched "+describe(ev))
			}
			continue
		}
		if !hasClass(ev, t.Expect) {
			return fail("classified %s, want %s (%s)", joinClasses(ev), t.Expect, ev.ClassSource)
		}
		if t.Resource != "" && ev.Resource != t.Resource {
			return fail("resource %q, want %q", ev.Resource, t.Resource)
		}
		o.Pass = true
		return o
	}
	return fail("no operation matched %s; saw %s", r.ID, strings.Join(seen, ", "))
}

func hasClass(ev engine.Evaluation, want classes.Class) bool {
	for _, c := range ev.Classes {
		if c == want {
			return true
		}
	}
	return false
}

func joinClasses(ev engine.Evaluation) string {
	parts := make([]string, len(ev.Classes))
	for i, c := range ev.Classes {
		parts[i] = string(c)
	}
	return strings.Join(parts, "+")
}

func describe(ev engine.Evaluation) string {
	op := ev.Op
	switch {
	case op.Field != "":
		return op.GraphQLType + " " + op.Field
	case op.Tool != "":
		return "tool " + op.Tool
	case op.Action != "":
		return op.Service + ":" + op.Action
	}
	return op.Method + " " + op.Path
}
