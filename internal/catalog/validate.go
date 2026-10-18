package catalog

import (
	"io/fs"
	"net/url"
	"path"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/rakeshnitb23/opfence/internal/classes"
	"github.com/rakeshnitb23/opfence/internal/decode"
)

var (
	providerIDRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)
	ruleIDRe     = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*(\.[a-z0-9][a-z0-9-]*)+$`)
	hostRe       = regexp.MustCompile(`^(\*\.)?([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$`)
	graphqlName  = regexp.MustCompile(`^[_A-Za-z][_0-9A-Za-z]*$`)
	headerNameRe = regexp.MustCompile("^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
	envNameRe    = regexp.MustCompile(`^[A-Z_][A-Z0-9_]*$`)
	mcpNameRe    = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
	awsServiceRe = regexp.MustCompile(`^[a-z0-9-]+$`)
	awsActionRe  = regexp.MustCompile(`^[A-Z][A-Za-z0-9]*$`)
	cardParamRe  = regexp.MustCompile(`\{([^{}]*)\}`)
	gitRefRe     = regexp.MustCompile(`^refs/[A-Za-z0-9._/-]*\*?$`)
	argPathRe    = regexp.MustCompile(`^[A-Za-z_$][A-Za-z0-9_$-]*(\.[A-Za-z_$][A-Za-z0-9_$-]*)*$`)
)

var restMethods = map[string]bool{
	"GET": true, "HEAD": true, "POST": true, "PUT": true, "PATCH": true, "DELETE": true, "OPTIONS": true,
}

func (l *loader) validate(c *Catalog) {
	hostOwner := map[string]string{}
	mcpNameOwner := map[string]string{}
	referenced := map[string]bool{}

	for _, p := range c.Providers {
		l.validateProvider(p, hostOwner, mcpNameOwner)
		keys := map[string]*Rule{}
		var gitRules []*Rule
		for _, r := range p.Rules {
			l.validateRule(r)
			if g := r.Match.Git; g != nil && len(g.Refs) > 0 {
				for _, prev := range gitRules {
					if ref, ok := gitRefsOverlap(prev.Match.Git, g); ok {
						l.addf(r.File, r.Line, "rule %s and %s (%s:%d) can both match %s; ref patterns of one command must not overlap", r.ID, prev.ID, prev.File, prev.Line, ref)
					}
				}
				gitRules = append(gitRules, r)
			}
			for _, id := range append([]string{r.ID}, r.Aliases...) {
				if id == "" {
					continue
				}
				if prev, ok := c.rules[id]; ok {
					l.addf(r.File, r.Line, "rule id %q already used by %s:%d", id, prev.File, prev.Line)
					continue
				}
				c.rules[id] = r
			}
			if k := matchKey(r); k != "" {
				if prev, ok := keys[k]; ok {
					l.addf(r.File, r.Line, "rule %s matches the same operations as %s (%s:%d); merge them or use `when`", r.ID, prev.ID, prev.File, prev.Line)
				} else {
					keys[k] = r
				}
			}
			for _, t := range r.Tests {
				if t.Fixture != "" {
					referenced[path.Join(p.Dir, t.Fixture)] = true
				}
			}
		}
	}
	for h, owner := range hostOwner {
		if !strings.HasPrefix(h, "*.") {
			continue
		}
		for other, otherOwner := range hostOwner {
			if otherOwner != owner && strings.HasSuffix(other, h[1:]) {
				l.addf(path.Join(owner, ProviderFile), 0, "host %q overlaps %q claimed by provider %s", h, other, otherOwner)
			}
		}
	}
	for f := range l.fixtures {
		if !referenced[f] {
			l.addf(f, 0, "fixture is not referenced by any rule test")
		}
	}
}

func (l *loader) validateProvider(p *Provider, hostOwner, mcpNameOwner map[string]string) {
	file := path.Join(p.Dir, ProviderFile)
	if p.ID != p.Dir {
		l.addf(file, 0, "provider %q must match its folder name %q", p.ID, p.Dir)
	}
	if !providerIDRe.MatchString(p.ID) {
		l.addf(file, 0, "provider id %q must be lower-case letters, digits and dashes", p.ID)
	}
	if strings.TrimSpace(p.Title) == "" {
		l.addf(file, 0, "title is required")
	}
	if p.Docs != "" && !validHTTPSURL(p.Docs) {
		l.addf(file, 0, "docs must be an https URL")
	}
	if len(p.Hosts) == 0 && p.MCP == nil {
		l.addf(file, 0, "hosts is required (only local MCP servers may omit it)")
	}
	for _, h := range p.Hosts {
		if !hostRe.MatchString(h) {
			l.addf(file, 0, "host %q must be a lower-case DNS name, optionally starting with *.", h)
			continue
		}
		if prev, ok := hostOwner[h]; ok {
			l.addf(file, 0, "host %q is already claimed by provider %s", h, prev)
		} else {
			hostOwner[h] = p.ID
		}
	}
	for _, h := range p.Git {
		if !slices.Contains(p.Hosts, h) || strings.HasPrefix(h, "*.") {
			l.addf(file, 0, "git host %q must be one of the provider's hosts, without a wildcard", h)
		}
	}
	for _, g := range p.GraphQL {
		if !strings.HasPrefix(g, "/") {
			l.addf(file, 0, "graphql path %q must start with /", g)
		}
	}
	for i, a := range p.Auth {
		set := 0
		if a.Header != "" {
			set++
			if !headerNameRe.MatchString(a.Header) {
				l.addf(file, 0, "auth[%d]: bad header name %q", i, a.Header)
			}
		}
		if a.Query != "" {
			set++
		}
		if a.Basic != "" {
			set++
			if a.Basic != "username" && a.Basic != "password" {
				l.addf(file, 0, "auth[%d]: basic must be username or password", i)
			}
		}
		if set != 1 {
			l.addf(file, 0, "auth[%d]: set exactly one of header, query or basic", i)
		}
		if a.Scheme != "" && a.Header == "" {
			l.addf(file, 0, "auth[%d]: scheme is only valid with header", i)
		}
	}
	for _, e := range p.Detect.Env {
		if !envNameRe.MatchString(e) {
			l.addf(file, 0, "detect.env %q is not an environment variable name", e)
		}
	}
	for _, pre := range p.Detect.Prefixes {
		if len(pre) < 3 {
			l.addf(file, 0, "detect.prefixes %q is too short to identify a token", pre)
		}
	}
	for name, c := range map[string]classes.Class{"graphql_query": p.Defaults.GraphQLQuery, "rest_safe_methods": p.Defaults.RESTSafeMethods, "aws_read_actions": p.Defaults.AWSReadActions} {
		if c != "" && !c.Valid() {
			l.addf(file, 0, "defaults.%s: unknown class %q", name, c)
		}
	}
	if p.Defaults.GraphQLQuery != "" && len(p.GraphQL) == 0 {
		l.addf(file, 0, "defaults.graphql_query needs graphql paths")
	}
	if p.Defaults.AWSReadActions != "" && !p.SigV4 {
		l.addf(file, 0, "defaults.aws_read_actions needs sigv4: true")
	}
	if p.MCP != nil {
		if len(p.MCP.Names) == 0 {
			l.addf(file, 0, "mcp.names is required")
		}
		for _, n := range p.MCP.Names {
			if !mcpNameRe.MatchString(n) {
				l.addf(file, 0, "mcp name %q may only contain letters, digits, _ and -", n)
				continue
			}
			if prev, ok := mcpNameOwner[n]; ok {
				l.addf(file, 0, "mcp name %q is already claimed by provider %s", n, prev)
			} else {
				mcpNameOwner[n] = p.ID
			}
		}
	}
}

func (l *loader) validateRule(r *Rule) {
	p := r.Provider
	f, ln := r.File, r.Line
	if !ruleIDRe.MatchString(r.ID) {
		l.addf(f, ln, "rule id %q must look like provider.resource.verb (lower-case, dots between parts)", r.ID)
	} else if !strings.HasPrefix(r.ID, p.ID+".") {
		l.addf(f, ln, "rule id %q must start with its provider %q", r.ID, p.ID+".")
	}
	for _, a := range r.Aliases {
		if !ruleIDRe.MatchString(a) {
			l.addf(f, ln, "alias %q is not a valid rule id", a)
		}
	}

	l.validateMatch(r)

	if !r.Class.Valid() {
		l.addf(f, ln, "%s: unknown class %q", r.ID, r.Class)
	}
	for i := range r.When {
		w := &r.When[i]
		if !w.Class.Valid() {
			l.addf(f, ln, "%s: when[%d]: unknown class %q", r.ID, i, w.Class)
		}
		l.validateCondition(r, i, &w.If)
	}
	if r.Classify != nil {
		if r.Classify.SQL == "" {
			l.addf(f, ln, "%s: classify needs sql: <argument>", r.ID)
		} else if !argPathRe.MatchString(r.Classify.SQL) {
			l.addf(f, ln, "%s: classify.sql %q is not an argument path", r.ID, r.Classify.SQL)
		}
	}
	if r.Resource != nil {
		if !argPathRe.MatchString(r.Resource.Arg) {
			l.addf(f, ln, "%s: resource.arg %q is not an argument path", r.ID, r.Resource.Arg)
		}
		if r.Resource.Kind == "" {
			l.addf(f, ln, "%s: resource.kind is required", r.ID)
		}
	}

	if r.Card == "" && r.Class != classes.Read {
		l.addf(f, ln, "%s: card is required for operations that are not reads", r.ID)
	}
	if strings.Count(r.Card, "{") != strings.Count(r.Card, "}") {
		l.addf(f, ln, "%s: card has unbalanced braces", r.ID)
	}
	for _, m := range cardParamRe.FindAllStringSubmatch(r.Card, -1) {
		if !argPathRe.MatchString(m[1]) {
			l.addf(f, ln, "%s: card placeholder {%s} is not an argument path", r.ID, m[1])
		}
	}

	switch r.Status {
	case Verified, Community, Draft:
	case "":
		l.addf(f, ln, "%s: status is required (verified, community or draft)", r.ID)
	default:
		l.addf(f, ln, "%s: unknown status %q", r.ID, r.Status)
	}
	if r.Verified != "" {
		if _, err := time.Parse("2006-01-02", r.Verified); err != nil {
			l.addf(f, ln, "%s: verified must be a date like 2026-10-16", r.ID)
		}
	}
	for _, s := range r.Sources {
		if !validHTTPSURL(s) {
			l.addf(f, ln, "%s: source %q must be an https URL", r.ID, s)
		}
	}
	if r.Status == Verified {
		if len(r.Tests) == 0 {
			l.addf(f, ln, "%s: verified rules need at least one test", r.ID)
		}
		if len(r.Sources) == 0 {
			l.addf(f, ln, "%s: verified rules need at least one source", r.ID)
		}
		if r.Verified == "" {
			l.addf(f, ln, "%s: verified rules need a verified date", r.ID)
		}
	}
	if r.Match.CLI != nil && len(r.Tests) > 0 {
		l.addf(f, ln, "%s: cli rules cannot have request fixtures", r.ID)
	}
	for i, t := range r.Tests {
		l.validateTest(r, i, t)
	}
}

func (l *loader) validateMatch(r *Rule) {
	p, f, ln := r.Provider, r.File, r.Line
	m := &r.Match
	n := 0
	for _, set := range []bool{m.REST != nil, m.GraphQL != nil, m.MCP != nil, m.AWS != nil, m.Git != nil, m.CLI != nil} {
		if set {
			n++
		}
	}
	if n != 1 {
		l.addf(f, ln, "%s: match needs exactly one of rest, graphql, mcp, aws, git or cli", r.ID)
		return
	}
	switch {
	case m.REST != nil:
		if !restMethods[m.REST.Method] {
			l.addf(f, ln, "%s: rest.method %q must be an upper-case HTTP method", r.ID, m.REST.Method)
		}
		t, err := ParseTemplate(m.REST.Path)
		if err != nil {
			l.addf(f, ln, "%s: %v", r.ID, err)
		} else {
			m.REST.Template = t
		}
		if len(p.Hosts) == 0 {
			l.addf(f, ln, "%s: rest rules need provider hosts", r.ID)
		}
	case m.GraphQL != nil:
		switch m.GraphQL.Type {
		case "query", "mutation", "subscription":
		default:
			l.addf(f, ln, "%s: graphql.type must be query, mutation or subscription", r.ID)
		}
		if !graphqlName.MatchString(m.GraphQL.Field) {
			l.addf(f, ln, "%s: graphql.field %q is not a GraphQL name", r.ID, m.GraphQL.Field)
		}
		if len(p.GraphQL) == 0 {
			l.addf(f, ln, "%s: graphql rules need graphql paths in %s", r.ID, ProviderFile)
		}
	case m.MCP != nil:
		if !mcpNameRe.MatchString(m.MCP.Tool) {
			l.addf(f, ln, "%s: mcp.tool %q may only contain letters, digits, _ and -", r.ID, m.MCP.Tool)
		}
		if p.MCP == nil {
			l.addf(f, ln, "%s: mcp rules need an mcp block in %s", r.ID, ProviderFile)
		}
	case m.AWS != nil:
		if !awsServiceRe.MatchString(m.AWS.Service) {
			l.addf(f, ln, "%s: aws.service %q must be a lower-case signing name", r.ID, m.AWS.Service)
		}
		switch {
		case m.AWS.Action != "" && m.AWS.Method == "" && m.AWS.Path == "":
			if !awsActionRe.MatchString(m.AWS.Action) {
				l.addf(f, ln, "%s: aws.action %q must be an action name like DeleteBucket", r.ID, m.AWS.Action)
			}
		case m.AWS.Action == "" && m.AWS.Method != "" && m.AWS.Path != "":
			if !restMethods[m.AWS.Method] {
				l.addf(f, ln, "%s: aws.method %q must be an upper-case HTTP method", r.ID, m.AWS.Method)
			}
			t, err := ParseTemplate(m.AWS.Path)
			if err != nil {
				l.addf(f, ln, "%s: %v", r.ID, err)
			} else {
				m.AWS.Template = t
			}
		default:
			l.addf(f, ln, "%s: aws needs either action, or method and path", r.ID)
		}
		if !p.SigV4 {
			l.addf(f, ln, "%s: aws rules need sigv4: true in %s", r.ID, ProviderFile)
		}
	case m.Git != nil:
		cmds, ok := gitCommands[m.Git.Service]
		if !ok {
			l.addf(f, ln, "%s: git.service must be upload-pack, receive-pack or lfs", r.ID)
		} else if !slices.Contains(cmds, m.Git.Command) {
			l.addf(f, ln, "%s: git.command for %s must be one of %s", r.ID, m.Git.Service, strings.Join(cmds, ", "))
		}
		if len(m.Git.Refs) > 0 && !(m.Git.Service == decode.GitReceivePack && m.Git.Command != decode.GitListRefs) {
			l.addf(f, ln, "%s: git.refs only applies to receive-pack create, update and delete", r.ID)
		}
		for _, ref := range m.Git.Refs {
			if !gitRefRe.MatchString(ref) {
				l.addf(f, ln, "%s: git.refs %q must be a full ref name like refs/heads/main, with * only at the end", r.ID, ref)
			}
		}
		if len(p.Git) == 0 {
			l.addf(f, ln, "%s: git rules need git hosts in %s", r.ID, ProviderFile)
		}
	case m.CLI != nil:
		if strings.TrimSpace(m.CLI.Command) == "" || m.CLI.Command != strings.TrimSpace(m.CLI.Command) {
			l.addf(f, ln, "%s: cli.command must be a command without surrounding spaces", r.ID)
		}
	}
}

func (l *loader) validateCondition(r *Rule, i int, c *Condition) {
	f, ln := r.File, r.Line
	if !argPathRe.MatchString(c.Arg) {
		l.addf(f, ln, "%s: when[%d]: arg %q is not an argument path", r.ID, i, c.Arg)
	}
	n := 0
	if c.Equals != nil {
		n++
	}
	if c.In != nil {
		n++
		if len(c.In) == 0 {
			l.addf(f, ln, "%s: when[%d]: in must list at least one value", r.ID, i)
		}
	}
	if c.Present {
		n++
	}
	if c.Absent {
		n++
	}
	if c.Empty {
		n++
	}
	if c.Matches != "" {
		n++
		re, err := regexp.Compile(c.Matches)
		if err != nil {
			l.addf(f, ln, "%s: when[%d]: matches: %v", r.ID, i, err)
		}
		c.re = re
	}
	if n != 1 {
		l.addf(f, ln, "%s: when[%d]: set exactly one of equals, in, present, absent, empty or matches", r.ID, i)
	}
}

func (l *loader) validateTest(r *Rule, i int, t Test) {
	f, ln := r.File, r.Line
	if t.Fixture == "" {
		l.addf(f, ln, "%s: tests[%d]: fixture is required", r.ID, i)
	} else {
		clean := path.Clean(t.Fixture)
		if clean != t.Fixture || strings.HasPrefix(clean, "../") || clean == ".." || path.IsAbs(clean) || !strings.HasPrefix(clean, FixturesDir+"/") {
			l.addf(f, ln, "%s: tests[%d]: fixture %q must be a clean path under %s/", r.ID, i, t.Fixture, FixturesDir)
		} else if _, err := fs.Stat(l.fsys, path.Join(r.Provider.Dir, clean)); err != nil {
			l.addf(f, ln, "%s: tests[%d]: fixture %s not found", r.ID, i, t.Fixture)
		} else if strings.HasSuffix(clean, ".json") && r.Match.MCP == nil {
			l.addf(f, ln, "%s: tests[%d]: .json tool-call fixtures are for mcp rules", r.ID, i)
		} else if !strings.HasSuffix(clean, ".http") && !strings.HasSuffix(clean, ".json") {
			l.addf(f, ln, "%s: tests[%d]: fixture %s must be a .http request or a .json tool call", r.ID, i, t.Fixture)
		}
	}
	if !t.Expect.Valid() {
		l.addf(f, ln, "%s: tests[%d]: unknown expected class %q", r.ID, i, t.Expect)
	}
}

// matchKey identifies the set of operations a rule matches, for ambiguity
// checks within a provider. Rules with conditions still collide: conditions
// belong in one rule's `when` list.
func matchKey(r *Rule) string {
	m := r.Match
	switch {
	case m.REST != nil && m.REST.Template != nil:
		return "rest " + m.REST.Method + " " + m.REST.Template.Shape()
	case m.GraphQL != nil:
		return "graphql " + m.GraphQL.Type + " " + m.GraphQL.Field
	case m.MCP != nil:
		return "mcp " + m.MCP.Tool
	case m.AWS != nil && m.AWS.Template != nil:
		return "aws " + m.AWS.Service + " " + m.AWS.Method + " " + m.AWS.Template.Shape()
	case m.AWS != nil:
		return "aws " + m.AWS.Service + " " + m.AWS.Action
	case m.Git != nil && len(m.Git.Refs) == 0:
		return "git " + m.Git.Service + " " + m.Git.Command
	case m.CLI != nil:
		return "cli " + m.CLI.Command
	}
	return ""
}

// gitRefsOverlap reports a ref that two git rules for the same command
// could both match.
func gitRefsOverlap(a, b *GitMatch) (string, bool) {
	if a.Service != b.Service || a.Command != b.Command {
		return "", false
	}
	for _, x := range a.Refs {
		for _, y := range b.Refs {
			px, py := strings.TrimSuffix(x, "*"), strings.TrimSuffix(y, "*")
			switch {
			case x == y,
				strings.HasSuffix(x, "*") && strings.HasPrefix(py, px),
				strings.HasSuffix(y, "*") && strings.HasPrefix(px, py):
				return y, true
			}
		}
	}
	return "", false
}

// gitCommands lists each git service's commands.
var gitCommands = map[string][]string{
	decode.GitUploadPack:  {decode.GitFetch},
	decode.GitReceivePack: {decode.GitListRefs, decode.GitCreate, decode.GitUpdate, decode.GitDelete},
	decode.GitLFS:         {decode.LFSDownload, decode.LFSUpload, decode.LFSListLocks, decode.LFSLock, decode.LFSUnlock},
}

func validHTTPSURL(s string) bool {
	u, err := url.Parse(s)
	return err == nil && u.Scheme == "https" && u.Host != ""
}
