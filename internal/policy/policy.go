// Package policy decides what a risk class means in an environment.
//
// Two files feed it: the repository's opfence.yaml, which anyone with
// commit access (including the agent) can edit and which may therefore only
// tighten, and the user's config, which lives outside the sandbox's write
// paths and may also loosen. See docs/ARCHITECTURE.md §5.
package policy

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"regexp"
	"sort"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/rakeshnitb23/opfence/internal/classes"
)

// Environment names, from least to most strict.
const (
	Development = "development"
	Staging     = "staging"
	Production  = "production"
)

// Environments lists the environments from most to least strict, the order
// in which mappings are checked.
var Environments = []string{Production, Staging, Development}

func envRank(e string) int {
	switch e {
	case Development:
		return 0
	case Staging:
		return 1
	case Production:
		return 2
	}
	return -1
}

// DefaultTable is the decision for each class in each environment when no
// policy says otherwise (PLAN.md "Default decisions").
var DefaultTable = map[string]map[classes.Class]classes.Decision{
	Development: {
		classes.Read: classes.Allow, classes.Write: classes.Allow, classes.Delete: classes.Allow,
		classes.Irreversible: classes.Ask, classes.Money: classes.Ask, classes.Credential: classes.Ask,
		classes.Access: classes.Ask, classes.Unknown: classes.Ask,
	},
	Staging: {
		classes.Read: classes.Allow, classes.Write: classes.Allow, classes.Delete: classes.Ask,
		classes.Irreversible: classes.Ask, classes.Money: classes.Ask, classes.Credential: classes.Ask,
		classes.Access: classes.Ask, classes.Unknown: classes.Ask,
	},
	Production: {
		classes.Read: classes.Allow, classes.Write: classes.Ask, classes.Delete: classes.Ask,
		classes.Irreversible: classes.Confirm, classes.Money: classes.Ask, classes.Credential: classes.Deny,
		classes.Access: classes.Ask, classes.Unknown: classes.Ask,
	},
}

// File is one policy file as written.
type File struct {
	Version            int    `yaml:"version"`
	DefaultEnvironment string `yaml:"default_environment"`
	// Environments maps environment → provider → argument path → values.
	Environments map[string]map[string]map[string][]string `yaml:"environments"`
	// Decisions overrides the default table: environment → class → decision.
	Decisions map[string]map[classes.Class]classes.Decision `yaml:"decisions"`
	// Rules overrides decisions for catalog rules by id or glob.
	Rules     []RuleOverride `yaml:"rules"`
	Mode      string         `yaml:"mode"` // strict or open (runner)
	Approvals *Approvals     `yaml:"approvals"`
	// PassthroughDefaults turns the built-in DefaultPassthrough list off when
	// false. A repository may turn it off but not back on.
	PassthroughDefaults *bool `yaml:"passthrough_defaults"`

	// User config only.
	IncludeDraft bool              `yaml:"include_draft"` // use draft catalog rules
	TrustRepo    bool              `yaml:"trust_repo"`    // treat opfence.yaml as user config
	Servers      map[string]string `yaml:"servers"`       // MCP server name → catalog provider
	// Passthrough lists hosts the runner tunnels without inspecting, such
	// as an internal registry: exact names or *.suffix patterns.
	Passthrough []string `yaml:"passthrough"`

	Path string `yaml:"-"`
}

// RuleOverride sets the decision for matching rules.
type RuleOverride struct {
	Rule        string           `yaml:"rule"`        // id, or glob such as github.repo.*
	Environment string           `yaml:"environment"` // empty means every environment
	Decision    classes.Decision `yaml:"decision"`
}

// Approvals configures how the runner asks.
type Approvals struct {
	Timeout  Duration `yaml:"timeout"`
	Channels []string `yaml:"channels"`
}

// Duration is a time.Duration written as "60s" in YAML.
type Duration time.Duration

// UnmarshalYAML implements yaml.Unmarshaler.
func (d *Duration) UnmarshalYAML(n *yaml.Node) error {
	v, err := time.ParseDuration(n.Value)
	if err != nil {
		return fmt.Errorf("line %d: %v", n.Line, err)
	}
	*d = Duration(v)
	return nil
}

var (
	providerRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)
	argPathRe  = regexp.MustCompile(`^[A-Za-z_$][A-Za-z0-9_$-]*(\.[A-Za-z_$][A-Za-z0-9_$-]*)*$`)
	ruleGlobRe = regexp.MustCompile(`^[a-z0-9*][a-z0-9*.-]*$`)
	serverRe   = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
	hostPatRe  = regexp.MustCompile(`^(\*\.)?[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$`)
)

// DefaultPassthrough is what the runner tunnels without inspecting unless
// passthrough_defaults is false: package registries and source downloads,
// so installs work in strict mode. None of them is a catalog host. git over
// HTTPS to github.com is here too until git ref decoding lands (stage 10).
var DefaultPassthrough = []string{
	"codeload.github.com", "crates.io", "files.pythonhosted.org", "github.com",
	"index.crates.io", "index.rubygems.org", "objects.githubusercontent.com",
	"proxy.golang.org", "pypi.org", "raw.githubusercontent.com",
	"registry.npmjs.org", "registry.yarnpkg.com", "repo.maven.apache.org",
	"repo1.maven.org", "rubygems.org", "static.crates.io", "sum.golang.org",
}

// Parse reads and validates a policy file.
func Parse(data []byte, name string) (*File, error) {
	f := &File{Path: name}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(f); err != nil {
		if errors.Is(err, io.EOF) {
			return &File{Path: name, Version: 1}, nil
		}
		return nil, fmt.Errorf("%s: %s", name, strings.TrimPrefix(err.Error(), "yaml: "))
	}
	var problems []string
	add := func(format string, args ...any) { problems = append(problems, fmt.Sprintf(format, args...)) }
	if f.Version != 1 {
		add("version must be 1")
	}
	if f.DefaultEnvironment != "" && envRank(f.DefaultEnvironment) < 0 {
		add("default_environment %q must be development, staging or production", f.DefaultEnvironment)
	}
	for env, providers := range f.Environments {
		if envRank(env) < 0 {
			add("environments: %q must be development, staging or production", env)
		}
		for prov, args := range providers {
			if !providerRe.MatchString(prov) {
				add("environments.%s: %q is not a provider id", env, prov)
			}
			for arg, vals := range args {
				if !argPathRe.MatchString(arg) {
					add("environments.%s.%s: %q is not an argument path", env, prov, arg)
				}
				if len(vals) == 0 {
					add("environments.%s.%s.%s: list at least one value", env, prov, arg)
				}
			}
		}
	}
	for env, m := range f.Decisions {
		if envRank(env) < 0 {
			add("decisions: %q must be development, staging or production", env)
		}
		for c := range m {
			if !c.Valid() {
				add("decisions.%s: unknown class %q", env, c)
			}
		}
	}
	for i, r := range f.Rules {
		if !ruleGlobRe.MatchString(r.Rule) {
			add("rules[%d]: rule %q must be a rule id or a glob like github.repo.*", i, r.Rule)
		}
		if r.Environment != "" && envRank(r.Environment) < 0 {
			add("rules[%d]: environment %q must be development, staging or production", i, r.Environment)
		}
	}
	switch f.Mode {
	case "", "strict", "open":
	default:
		add("mode must be strict or open")
	}
	if f.Approvals != nil {
		if f.Approvals.Timeout != 0 && (time.Duration(f.Approvals.Timeout) < time.Second || time.Duration(f.Approvals.Timeout) > 10*time.Minute) {
			add("approvals.timeout must be between 1s and 10m")
		}
		for _, ch := range f.Approvals.Channels {
			switch ch {
			case "desktop", "cli", "ntfy":
			default:
				add("approvals.channels: unknown channel %q (want desktop, cli or ntfy)", ch)
			}
		}
	}
	for name, prov := range f.Servers {
		if !serverRe.MatchString(name) || !providerRe.MatchString(prov) {
			add("servers: %q: %q must map a server name to a provider id", name, prov)
		}
	}
	for _, h := range f.Passthrough {
		if !hostPatRe.MatchString(h) {
			add("passthrough: %q must be a lower-case host name or *.suffix, without a port", h)
		}
	}
	if len(problems) > 0 {
		sort.Strings(problems)
		return nil, fmt.Errorf("%s:\n  %s", name, strings.Join(problems, "\n  "))
	}
	return f, nil
}

// Load reads a policy file. A missing file is not an error: it returns nil.
func Load(name string) (*File, error) {
	data, err := os.ReadFile(name)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return Parse(data, name)
}

// UserConfigPath returns where the user's config lives: $OPFENCE_CONFIG,
// else $XDG_CONFIG_HOME/opfence/config.yaml, else ~/.config/opfence/config.yaml.
func UserConfigPath() string {
	if p := os.Getenv("OPFENCE_CONFIG"); p != "" {
		return p
	}
	if x := os.Getenv("XDG_CONFIG_HOME"); x != "" {
		return path.Join(x, "opfence", "config.yaml")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return path.Join(home, ".config", "opfence", "config.yaml")
}

// userOnlyFields lists settings a repository file may not set.
func (f *File) userOnlyFields() []string {
	var out []string
	if f.IncludeDraft {
		out = append(out, "include_draft")
	}
	if f.TrustRepo {
		out = append(out, "trust_repo")
	}
	if len(f.Servers) > 0 {
		out = append(out, "servers")
	}
	if len(f.Passthrough) > 0 {
		out = append(out, "passthrough")
	}
	return out
}
