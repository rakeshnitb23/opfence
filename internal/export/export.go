// Package export compiles the catalog and a policy into configuration for
// other engines: OpenShell network policies, Claude Code settings and MCP
// tool annotations (docs/ARCHITECTURE.md §7).
//
// Exports are static: they cannot see a request's arguments. Wherever an
// exported rule would have to depend on arguments or on the environment, the
// exporter writes the stricter of the outcomes, so an export never allows
// something the engine would stop.
package export

import (
	"sort"

	"github.com/rakeshnitb23/opfence/internal/catalog"
	"github.com/rakeshnitb23/opfence/internal/classes"
	"github.com/rakeshnitb23/opfence/internal/policy"
)

// Ceiling is the strictest decision rule r can get in env, over every class
// its arguments could give it.
func Ceiling(p *policy.Effective, r *catalog.Rule, env string) classes.Decision {
	d := classes.Decision(-1)
	for _, c := range r.PossibleClasses() {
		if x, _ := p.Decide(r.ID, c, env); x > d {
			d = x
		}
	}
	return d
}

// Floor is the most lenient decision rule r can get, over every class and
// every environment. A static rule at the floor never contradicts the engine:
// whatever the arguments, the engine decides at least this strictly.
func Floor(p *policy.Effective, r *catalog.Rule) classes.Decision {
	d := classes.Deny + 1
	for _, env := range policy.Environments {
		for _, c := range r.PossibleClasses() {
			if x, _ := p.Decide(r.ID, c, env); x < d {
				d = x
			}
		}
	}
	return d
}

// DefaultDecision is the decision for an operation no rule matches but a
// provider default classifies as c.
func DefaultDecision(p *policy.Effective, c classes.Class, env string) classes.Decision {
	d, _ := p.Decide("", c, env)
	return d
}

// sortedRules returns a provider's rules sorted by id, skipping drafts unless
// the policy opts in to them.
func sortedRules(p *policy.Effective, prov *catalog.Provider) []*catalog.Rule {
	var out []*catalog.Rule
	for _, r := range prov.Rules {
		if r.Status == catalog.Draft && !p.IncludeDraft {
			continue
		}
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// MCPServerNames returns the names a provider's MCP server goes by: the
// catalog's common names plus the user's `servers:` aliases, sorted.
func MCPServerNames(p *policy.Effective, prov *catalog.Provider) []string {
	if prov.MCP == nil {
		return nil
	}
	seen := map[string]bool{}
	for _, n := range prov.MCP.Names {
		seen[n] = true
	}
	for name, id := range p.Servers {
		if id == prov.ID {
			seen[name] = true
		}
	}
	out := make([]string, 0, len(seen))
	for n := range seen {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}
