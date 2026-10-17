package export

import (
	"encoding/json"
	"slices"

	"github.com/rakeshnitb23/opfence/internal/catalog"
	"github.com/rakeshnitb23/opfence/internal/classes"
	"github.com/rakeshnitb23/opfence/internal/policy"
)

// Annotation is the MCP tool annotation overlay for one tool. The hint names
// are the MCP specification's tool annotations; the opfence fields say where
// they came from.
type Annotation struct {
	ReadOnlyHint    bool            `json:"readOnlyHint"`
	DestructiveHint bool            `json:"destructiveHint"`
	IdempotentHint  bool            `json:"idempotentHint"`
	OpfenceClasses  []classes.Class `json:"opfenceClasses"`
	Rule            string          `json:"rule"`
}

// MCPAnnotations writes {server: {tool: annotation}} for every MCP tool in
// the catalog, under each name the server goes by.
//
// readOnlyHint is true only when every class the tool can have is read;
// destructiveHint is true when any class it can have is delete or
// irreversible. idempotentHint is left false: the catalog does not record
// idempotency, and false is the cautious value.
func MCPAnnotations(c *catalog.Catalog, p *policy.Effective) ([]byte, error) {
	if p == nil {
		p = policy.Resolve(nil, nil)
	}
	out := map[string]map[string]Annotation{}
	for _, prov := range c.Providers {
		names := MCPServerNames(p, prov)
		if len(names) == 0 {
			continue
		}
		tools := map[string]Annotation{}
		for _, r := range sortedRules(p, prov) {
			if r.Match.MCP == nil {
				continue
			}
			cs := r.PossibleClasses()
			a := Annotation{ReadOnlyHint: true, OpfenceClasses: cs, Rule: r.ID}
			for _, cl := range cs {
				if cl != classes.Read {
					a.ReadOnlyHint = false
				}
				if cl == classes.Delete || cl == classes.Irreversible {
					a.DestructiveHint = true
				}
			}
			slices.Sort(a.OpfenceClasses)
			tools[r.Match.MCP.Tool] = a
		}
		for _, n := range names {
			out[n] = tools
		}
	}
	b, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}
