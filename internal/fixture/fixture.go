// Package fixture replays every catalog rule's recorded requests and checks
// that each is classified the way the rule claims (`opfence test`).
package fixture

import (
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
	req, _, err := request.ParseFixture(data)
	if err != nil {
		return fail("%v", err)
	}
	res := eng.Evaluate(req)
	if res.Provider != r.Provider {
		owner := "no provider"
		if res.Provider != nil {
			owner = "provider " + res.Provider.ID
		}
		return fail("fixture host %s belongs to %s, not %s", req.Host, owner, r.Provider.ID)
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
