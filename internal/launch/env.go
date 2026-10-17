package launch

import (
	"sort"
	"strings"
	"time"

	"github.com/rakeshnitb23/opfence/internal/catalog"
	"github.com/rakeshnitb23/opfence/internal/secrets"
)

// EnvChange reports what happened to one environment variable.
type EnvChange struct {
	Var      string
	Provider string
	// Action is "placeholder" (a key Opfence already holds) or "session"
	// (a key held for this session only).
	Action string
}

// ProtectEnv replaces API keys in environ with placeholders, so the program
// never sees a real key. A stored secret's value, under any variable name,
// gets that secret's placeholder. Any other key for a catalog provider
// becomes a session secret: a placeholder made now and held in memory only,
// in group "env" (so AWS's key ID and secret key are paired),
// which the caller adds to the proxy's set; every variable holding that key
// gets the placeholder. Nothing is written to the keychain.
func ProtectEnv(environ []string, c *catalog.Catalog, stored []*secrets.Secret) (out []string, session []*secrets.Secret, changes []EnvChange, err error) {
	type known struct {
		s      *secrets.Secret
		action string
	}
	var swaps []known
	byValue := map[string]bool{}
	for _, s := range stored {
		if len(s.Value) >= secrets.MinLength && !byValue[s.Value] {
			swaps = append(swaps, known{s, "placeholder"})
			byValue[s.Value] = true
		}
	}
	for _, f := range secrets.ScanEnv(environ, c, secrets.NewSet(stored)) {
		switch {
		case f.Skip != "":
			// A placeholder, a reference or a short value: not a key.
		case !byValue[f.Value]:
			ph, perr := secrets.NewPlaceholder(f.Value, c.Provider(f.Provider).Detect.Prefixes)
			if perr != nil {
				return nil, nil, nil, perr
			}
			s := &secrets.Secret{Provider: f.Provider, Name: f.Where, Value: f.Value, Placeholder: ph, Sources: []string{"env " + f.Where}, Group: "env", Created: time.Now().UTC()}
			session = append(session, s)
			swaps = append(swaps, known{s, "session"})
			byValue[f.Value] = true
		}
	}
	// Longer values first, so a key that contains another is swapped whole.
	sort.SliceStable(swaps, func(i, j int) bool { return len(swaps[i].s.Value) > len(swaps[j].s.Value) })
	out = make([]string, 0, len(environ))
	for _, kv := range environ {
		key, value, ok := strings.Cut(kv, "=")
		if !ok || value == "" {
			out = append(out, kv)
			continue
		}
		var change *EnvChange
		for _, k := range swaps {
			if strings.Contains(value, k.s.Value) {
				value = strings.ReplaceAll(value, k.s.Value, k.s.Placeholder)
				if change == nil {
					change = &EnvChange{Var: key, Provider: k.s.Provider, Action: k.action}
				}
			}
		}
		if change != nil {
			changes = append(changes, *change)
		}
		out = append(out, key+"="+value)
	}
	sort.Slice(changes, func(i, j int) bool { return changes[i].Var < changes[j].Var })
	return out, session, changes, nil
}
