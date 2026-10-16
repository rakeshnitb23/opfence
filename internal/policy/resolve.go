package policy

import (
	"fmt"
	"path"
	"sort"
	"time"

	"github.com/rakeshnitb23/opfence/internal/classes"
)

// Effective is the merged result of the user's config and the repository's
// opfence.yaml. Build it with Resolve.
type Effective struct {
	user, repo *File
	// Warnings lists repository settings that were ignored because they
	// would loosen policy.
	Warnings []string

	DefaultEnvironment string
	IncludeDraft       bool
	Mode               string
	ApprovalTimeout    time.Duration
	ApprovalChannels   []string
	Servers            map[string]string
	// Passthrough is every host pattern the runner tunnels uninspected.
	Passthrough []string
}

// Resolve merges the user's config and the repository file; either may be
// nil. The repository may only tighten: see docs/ARCHITECTURE.md §5.3.
func Resolve(user, repo *File) *Effective {
	if user == nil {
		user = &File{Version: 1}
	}
	if repo == nil {
		repo = &File{Version: 1}
	}
	e := &Effective{user: user, repo: repo}
	if user.TrustRepo {
		// The user chose to treat the repository file as their own.
		merged := mergeTrusted(user, repo)
		e.user, e.repo = merged, &File{Version: 1}
		user, repo = merged, e.repo
	}
	for _, f := range repo.userOnlyFields() {
		e.Warnings = append(e.Warnings, fmt.Sprintf("%s: %s is only honoured in your user config; ignored", repo.Path, f))
	}

	e.DefaultEnvironment = Production
	if user.DefaultEnvironment != "" {
		e.DefaultEnvironment = user.DefaultEnvironment
	}
	if repo.DefaultEnvironment != "" {
		if envRank(repo.DefaultEnvironment) > envRank(e.DefaultEnvironment) {
			e.DefaultEnvironment = repo.DefaultEnvironment
		} else if repo.DefaultEnvironment != e.DefaultEnvironment {
			e.Warnings = append(e.Warnings, fmt.Sprintf("%s: default_environment %s would loosen policy; ignored", repo.Path, repo.DefaultEnvironment))
		}
	}

	e.IncludeDraft = user.IncludeDraft
	e.Servers = map[string]string{}
	for k, v := range user.Servers {
		e.Servers[k] = v
	}

	e.Mode = "strict"
	if user.Mode == "open" && repo.Mode != "strict" {
		e.Mode = "open"
	}
	if repo.Mode == "open" && user.Mode != "open" {
		e.Warnings = append(e.Warnings, fmt.Sprintf("%s: mode open would loosen policy; ignored", repo.Path))
	}

	defaults := user.PassthroughDefaults == nil || *user.PassthroughDefaults
	if repo.PassthroughDefaults != nil {
		if !*repo.PassthroughDefaults {
			defaults = false
		} else if !defaults {
			e.Warnings = append(e.Warnings, fmt.Sprintf("%s: passthrough_defaults true would loosen policy; ignored", repo.Path))
		}
	}
	if defaults {
		e.Passthrough = append(e.Passthrough, DefaultPassthrough...)
	}
	e.Passthrough = append(e.Passthrough, user.Passthrough...)

	e.ApprovalTimeout = 60 * time.Second
	if user.Approvals != nil && user.Approvals.Timeout != 0 {
		e.ApprovalTimeout = time.Duration(user.Approvals.Timeout)
	}
	if repo.Approvals != nil && repo.Approvals.Timeout != 0 && time.Duration(repo.Approvals.Timeout) < e.ApprovalTimeout {
		e.ApprovalTimeout = time.Duration(repo.Approvals.Timeout) // a shorter timeout denies sooner: tighter
	}
	e.ApprovalChannels = []string{"desktop", "cli"}
	if user.Approvals != nil && len(user.Approvals.Channels) > 0 {
		e.ApprovalChannels = user.Approvals.Channels
	}

	// Report repository decisions that try to loosen the defaults; they
	// can never take effect.
	for env, m := range repo.Decisions {
		for c, d := range m {
			if d < DefaultTable[env][c] {
				e.Warnings = append(e.Warnings, fmt.Sprintf("%s: decisions.%s.%s: %s would loosen policy; repository files can only tighten", repo.Path, env, c, d))
			}
		}
	}
	sort.Strings(e.Warnings)
	return e
}

func mergeTrusted(user, repo *File) *File {
	m := *user
	m.Environments = map[string]map[string]map[string][]string{}
	for _, f := range []*File{user, repo} {
		for env, provs := range f.Environments {
			if m.Environments[env] == nil {
				m.Environments[env] = map[string]map[string][]string{}
			}
			for prov, args := range provs {
				if m.Environments[env][prov] == nil {
					m.Environments[env][prov] = map[string][]string{}
				}
				for arg, vals := range args {
					m.Environments[env][prov][arg] = append(m.Environments[env][prov][arg], vals...)
				}
			}
		}
	}
	m.Decisions = map[string]map[classes.Class]classes.Decision{}
	for _, f := range []*File{repo, user} { // user wins
		for env, cs := range f.Decisions {
			if m.Decisions[env] == nil {
				m.Decisions[env] = map[classes.Class]classes.Decision{}
			}
			for c, d := range cs {
				m.Decisions[env][c] = d
			}
		}
	}
	m.Rules = append(append([]RuleOverride{}, user.Rules...), repo.Rules...) // first match wins: user first
	m.Passthrough = append(append([]string{}, user.Passthrough...), repo.Passthrough...)
	if m.PassthroughDefaults == nil {
		m.PassthroughDefaults = repo.PassthroughDefaults
	}
	if m.DefaultEnvironment == "" {
		m.DefaultEnvironment = repo.DefaultEnvironment
	}
	return &m
}

// Decide returns the decision for a class in an environment, for an
// operation matched by ruleID (empty when no rule matched), and a short
// explanation of where it came from.
func (e *Effective) Decide(ruleID string, c classes.Class, env string) (classes.Decision, string) {
	d, src := DefaultTable[env][c], "default for "+string(c)+" in "+env
	if od, ok := e.user.Decisions[env][c]; ok {
		d, src = od, userSrc(e.user)+" decisions."+env+"."+string(c)
	}
	if od, ok := ruleOverride(e.user, ruleID, env); ok {
		d, src = od, userSrc(e.user)+" rule override for "+ruleID
	}
	if od, ok := e.repo.Decisions[env][c]; ok && od > d {
		d, src = od, e.repo.Path+" decisions."+env+"."+string(c)
	}
	if od, ok := ruleOverride(e.repo, ruleID, env); ok && od > d {
		d, src = od, e.repo.Path+" rule override for "+ruleID
	}
	return d, src
}

func userSrc(f *File) string {
	if f.Path == "" {
		return "user config"
	}
	return f.Path
}

// ruleOverride returns the first override in f matching ruleID and env.
func ruleOverride(f *File, ruleID, env string) (classes.Decision, bool) {
	if ruleID == "" {
		return 0, false
	}
	for _, r := range f.Rules {
		if r.Environment != "" && r.Environment != env {
			continue
		}
		if ok, _ := path.Match(r.Rule, ruleID); ok {
			return r.Decision, true
		}
	}
	return 0, false
}

// CatalogWarnings checks the policy against the catalog: rule overrides that
// match no rule (usually a typo, which would otherwise do nothing silently),
// environment mappings and server aliases naming providers it does not have.
func (e *Effective) CatalogWarnings(ruleIDs, providerIDs []string) []string {
	providers := map[string]bool{}
	for _, id := range providerIDs {
		providers[id] = true
	}
	var out []string
	for _, f := range []*File{e.user, e.repo} {
		if f == nil {
			continue
		}
		src := userSrc(f)
		for _, o := range f.Rules {
			matched := false
			for _, id := range ruleIDs {
				if ok, _ := path.Match(o.Rule, id); ok {
					matched = true
					break
				}
			}
			if !matched {
				out = append(out, fmt.Sprintf("%s: rule %s matches no catalog rule", src, o.Rule))
			}
		}
		for env, provs := range f.Environments {
			for prov := range provs {
				if !providers[prov] {
					out = append(out, fmt.Sprintf("%s: environments.%s.%s: no catalog provider has that id", src, env, prov))
				}
			}
		}
		for name, prov := range f.Servers {
			if !providers[prov] {
				out = append(out, fmt.Sprintf("%s: servers.%s: no catalog provider has the id %s", src, name, prov))
			}
		}
	}
	sort.Strings(out)
	return out
}

// Environment resolves which environment an operation targets, from the
// provider's id mappings and the operation's arguments. lookup returns the
// scalar text of an argument path. It reports where the answer came from.
//
// Production is checked first, so an operation naming both a development
// and a production id is production. Repository mappings are honoured only
// when they make the result stricter than the user's mappings and the
// default would.
func (e *Effective) Environment(provider string, lookup func(arg string) (string, bool)) (string, string) {
	userEnv, userSrc := mapped(e.user, provider, lookup)
	repoEnv, repoSrc := mapped(e.repo, provider, lookup)
	env, src := e.DefaultEnvironment, "default; map ids in opfence.yaml to change"
	if userEnv != "" {
		env, src = userEnv, userSrc
	}
	if repoEnv != "" && envRank(repoEnv) > envRank(env) {
		env, src = repoEnv, repoSrc
	}
	return env, src
}

func mapped(f *File, provider string, lookup func(string) (string, bool)) (string, string) {
	for _, env := range Environments {
		args := f.Environments[env][provider]
		keys := make([]string, 0, len(args))
		for k := range args {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, arg := range keys {
			v, ok := lookup(arg)
			if !ok {
				continue
			}
			for _, want := range args[arg] {
				if v == want {
					where := "user config"
					if f.Path != "" {
						where = f.Path
					}
					return env, fmt.Sprintf("%s maps %s=%s", where, arg, v)
				}
			}
		}
	}
	return "", ""
}
