// Command sitegen writes Opfence's documentation site: the guides in docs/
// and the repository's top-level Markdown files, and a browsable catalog
// generated from catalog/. It is a module of its own, so the opfence binary
// does not depend on a Markdown renderer.
//
// From the repository root:
//
//	make site                       # writes _site/
//	cd tools/sitegen && go run . -repo ../.. -out ../../_site
package main

import (
	"bytes"
	"embed"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/rakeshnitb23/opfence/internal/catalog"
	"github.com/rakeshnitb23/opfence/internal/classes"
	"github.com/rakeshnitb23/opfence/internal/engine"
	"github.com/rakeshnitb23/opfence/internal/fixture"
	"github.com/rakeshnitb23/opfence/internal/policy"
	"github.com/rakeshnitb23/opfence/internal/request"
)

//go:embed assets
var assets embed.FS

//go:embed templates/*.html
var templateFS embed.FS

const repoURL = "https://github.com/rakeshnitb23/opfence"

// page is one Markdown file rendered as a page of the site.
type page struct {
	src, out, title, summary string
}

var pages = []page{
	{"docs/QUICKSTART.md", "quickstart.html", "Quick start", "From install to the first blocked call."},
	{"docs/ARCHITECTURE.md", "docs/architecture.html", "Architecture", "How Opfence decodes, classifies and decides a request."},
	{"docs/LIMITS.md", "docs/limits.html", "Limits", "What Opfence does not protect against."},
	{"SECURITY.md", "docs/security.html", "Security", "Reporting vulnerabilities."},
	{"CONTRIBUTING.md", "docs/contributing.html", "Contributing", "Adding a catalog rule."},
	{"docs/PLAN.md", "docs/plan.html", "Plan", "The problem, the threat model and the roadmap."},
	{"docs/BUILD_PLAN.md", "docs/progress.html", "Build progress", "What is built, stage by stage."},
}

func main() {
	repo := flag.String("repo", ".", "repository root")
	out := flag.String("out", "_site", "output folder")
	flag.Parse()
	if err := build(*repo, *out); err != nil {
		fmt.Fprintln(os.Stderr, "sitegen:", err)
		os.Exit(1)
	}
}

type site struct {
	repo, out string
	tmpl      *template.Template
	cat       *catalog.Catalog
	commit    string
	built     string
	links     map[string]string // repository path -> site path
}

func build(repo, out string) error {
	c, err := catalog.Load(os.DirFS(filepath.Join(repo, "catalog")))
	if err != nil {
		return fmt.Errorf("loading the catalog: %w", err)
	}
	tmpl, err := template.New("").Funcs(template.FuncMap{
		"classes": func(cs []classes.Class) string { return joinClasses(cs) },
	}).ParseFS(templateFS, "templates/*.html")
	if err != nil {
		return err
	}
	s := &site{repo: repo, out: out, tmpl: tmpl, cat: c, commit: gitCommit(repo), built: time.Now().UTC().Format("2 January 2006"),
		links: map[string]string{"README.md": "index.html", "catalog": "catalog/index.html"}}
	for _, p := range pages {
		s.links[p.src] = p.out
	}
	if err := os.RemoveAll(out); err != nil {
		return err
	}
	if err := s.copyAssets(); err != nil {
		return err
	}
	if err := s.home(); err != nil {
		return err
	}
	for _, p := range pages {
		if err := s.markdownPage(p); err != nil {
			return fmt.Errorf("%s: %w", p.src, err)
		}
	}
	if err := s.catalogPages(); err != nil {
		return err
	}
	// GitHub Pages serves the folder as it is.
	return os.WriteFile(filepath.Join(out, ".nojekyll"), nil, 0o644)
}

func gitCommit(repo string) string {
	b, err := exec.Command("git", "-C", repo, "rev-parse", "--short", "HEAD").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func (s *site) copyAssets() error {
	return fs.WalkDir(assets, "assets", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := assets.ReadFile(p)
		if err != nil {
			return err
		}
		return s.write(p, b)
	})
}

func (s *site) write(rel string, b []byte) error {
	full := filepath.Join(s.out, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		return err
	}
	return os.WriteFile(full, b, 0o644)
}

// base is the relative path from a page back to the site root, so the site
// works under any prefix (GitHub Pages serves it at /opfence/).
func base(out string) string {
	return strings.Repeat("../", strings.Count(out, "/"))
}

// view is what the layout template renders.
type view struct {
	Title, Description, Base, Class, Current string
	Body                                     template.HTML
	TOC                                      []tocEntry
	Mermaid                                  bool
	Commit, Built, RepoURL                   string
}

type tocEntry struct {
	ID, Text string
	Level    int
}

func (s *site) render(out string, v view) error {
	v.Base, v.Commit, v.Built, v.RepoURL = base(out), s.commit, s.built, repoURL
	if v.Current == "" {
		v.Current = out
	}
	var buf bytes.Buffer
	if err := s.tmpl.ExecuteTemplate(&buf, "layout.html", v); err != nil {
		return err
	}
	return s.write(out, buf.Bytes())
}

// ---- Home ----

type homeView struct {
	Providers, MCPServers, Rules, Fixtures int
	Base                                   string
	Featured                               []featured
}

type featured struct {
	Request, Provider, Rule, Class, Decision, Card string
}

func (s *site) home() error {
	hv := homeView{Base: ""}
	for _, p := range s.cat.Providers {
		hv.Providers++
		if p.MCP != nil {
			hv.MCPServers++
		}
		hv.Rules += len(p.Rules)
		for _, r := range p.Rules {
			hv.Fixtures += len(r.Tests)
		}
	}
	// Examples decided live from the rules' own fixtures, with the default
	// policy, so the home page cannot drift from the engine.
	for _, ex := range []struct {
		rule   string
		expect classes.Class
	}{
		{"railway.volume.delete", classes.Irreversible},
		{"supabase-mcp.database.execute-sql", classes.Read},
		{"supabase-mcp.database.execute-sql", classes.Irreversible},
		{"aws.rds.delete-db-instance", classes.Irreversible},
		{"stripe.refund.create", classes.Money},
		{"terraform-mcp.run.create", classes.Irreversible},
	} {
		f, err := s.example(ex.rule, ex.expect)
		if err != nil {
			return err
		}
		hv.Featured = append(hv.Featured, f)
	}
	var buf bytes.Buffer
	if err := s.tmpl.ExecuteTemplate(&buf, "home.html", hv); err != nil {
		return err
	}
	return s.render("index.html", view{Title: "Opfence", Description: "The open list of things your AI agent must never do without asking, and the tool that enforces it.",
		Class: "home", Body: template.HTML(buf.String())})
}

// example decides the first fixture of rule that expects class, as the
// proxy or the hook would with the default policy.
func (s *site) example(id string, want classes.Class) (featured, error) {
	r := s.cat.Rule(id)
	if r == nil {
		return featured{}, fmt.Errorf("example rule %s is not in the catalog", id)
	}
	eng := engine.New(s.cat, policy.Resolve(nil, nil))
	for _, t := range r.Tests {
		if t.Expect != want {
			continue
		}
		data, err := fs.ReadFile(s.cat.FS, path.Join(r.Provider.Dir, t.Fixture))
		if err != nil {
			return featured{}, err
		}
		var res engine.Result
		desc := ""
		if strings.HasSuffix(t.Fixture, ".json") {
			call, err := fixture.ParseToolCall(data)
			if err != nil {
				return featured{}, err
			}
			res = eng.EvaluateTool(r.Provider, call.Tool, call.Arguments)
			desc = call.Description
		} else {
			req, _, err := request.ParseFixture(data)
			if err != nil {
				return featured{}, err
			}
			res = eng.Evaluate(req)
			if m := descRe.FindSubmatch(data); m != nil {
				desc = string(m[1])
			}
		}
		for _, ev := range res.Evaluations {
			if ev.Rule == r {
				return featured{Request: desc, Provider: r.Provider.ID, Rule: r.ID, Class: string(ev.Class), Decision: strings.ToLower(ev.Decision.String()), Card: ev.Card}, nil
			}
		}
	}
	return featured{}, fmt.Errorf("example rule %s has no %s fixture", id, want)
}

var descRe = regexp.MustCompile(`(?m)^# description: (.+)$`)

// ---- Markdown pages ----

var mermaidRe = regexp.MustCompile(`(?s)<pre><code class="language-mermaid">(.*?)</code></pre>`)

func (s *site) markdownPage(p page) error {
	src, err := os.ReadFile(filepath.Join(s.repo, filepath.FromSlash(p.src)))
	if err != nil {
		return err
	}
	body, toc, err := renderMarkdown(src, p, s.links)
	if err != nil {
		return err
	}
	// The first heading is the page title, shown by the layout.
	mermaid := mermaidRe.MatchString(body)
	body = mermaidRe.ReplaceAllString(body, `<pre class="mermaid">$1</pre>`)
	return s.render(p.out, view{Title: p.title, Description: p.summary, Class: "doc", Body: template.HTML(body), TOC: toc, Mermaid: mermaid})
}

// ---- Catalog ----

type providerRow struct {
	ID, Title, Kind, Hosts string
	Rules                  int
	Classes                []classCount
}

type classCount struct {
	Class string
	N     int
	Pct   float64
}

var classOrder = []string{"read", "write", "delete", "irreversible", "money", "credential", "access", "unknown"}

type ruleRow struct {
	ID, Operation, Class, Card, Notes, Status, File, Resource string
	When                                                      []whenRow
	Classify                                                  string
	Sources                                                   []string
	Tests                                                     int
}

type whenRow struct{ Cond, Class string }

type providerView struct {
	P        *catalog.Provider
	Kind     string
	Hosts    string
	Groups   []ruleGroup
	Rules    int
	Classes  []classCount
	Auth     []string
	Detect   []string
	Defaults []string
	Schemas  []catalog.SchemaSource
	Shares   []string
}

type ruleGroup struct {
	Name  string
	Rules []ruleRow
}

// searchEntry is one rule in catalog/rules.json, which the catalog page
// searches in the browser.
type searchEntry struct {
	ID string   `json:"i"`
	P  string   `json:"p"`
	Op string   `json:"o"`
	C  []string `json:"c"`
	K  string   `json:"k"`
}

func (s *site) catalogPages() error {
	var rows []providerRow
	var index []searchEntry
	for _, p := range s.cat.Providers {
		pv := providerView{P: p, Kind: kind(p), Hosts: strings.Join(p.Hosts, ", "), Rules: len(p.Rules), Classes: classCounts(p.Rules), Schemas: p.Schemas,
			Shares: p.SecretsFrom}
		for _, a := range p.Auth {
			switch {
			case a.Header != "":
				pv.Auth = append(pv.Auth, a.Header+" header"+strings.TrimSpace(" "+a.Scheme))
			case a.Query != "":
				pv.Auth = append(pv.Auth, a.Query+" query parameter")
			case a.Basic != "":
				pv.Auth = append(pv.Auth, "HTTP Basic "+a.Basic)
			}
		}
		pv.Detect = append(pv.Detect, p.Detect.Env...)
		for _, pre := range p.Detect.Prefixes {
			pv.Detect = append(pv.Detect, pre+"…")
		}
		for name, c := range map[string]classes.Class{"GraphQL queries": p.Defaults.GraphQLQuery, "GET, HEAD and OPTIONS": p.Defaults.RESTSafeMethods,
			"AWS read actions": p.Defaults.AWSReadActions, "MCP tools no rule names": p.Defaults.MCPTools} {
			if c != "" {
				pv.Defaults = append(pv.Defaults, name+": "+string(c))
			}
		}
		sort.Strings(pv.Defaults)
		groups := map[string]*ruleGroup{}
		var order []string
		for _, r := range p.Rules {
			g := strings.TrimSuffix(path.Base(r.File), ".yaml")
			if groups[g] == nil {
				groups[g] = &ruleGroup{Name: g}
				order = append(order, g)
			}
			rr := ruleRow{ID: r.ID, Operation: operation(r), Class: string(r.Class), Card: r.Card, Notes: r.Notes, Status: string(r.Status),
				File: r.File, Sources: r.Sources, Tests: len(r.Tests)}
			if r.Resource != nil {
				rr.Resource = r.Resource.Arg + " (" + r.Resource.Kind + ")"
			}
			for _, w := range r.When {
				w := w
				rr.When = append(rr.When, whenRow{Cond: w.If.String(), Class: string(w.Class)})
			}
			if r.Classify != nil && r.Classify.Active() {
				rr.Classify = r.Classify.String()
			}
			groups[g].Rules = append(groups[g].Rules, rr)
			var cs []string
			for _, c := range r.PossibleClasses() {
				cs = append(cs, string(c))
			}
			index = append(index, searchEntry{ID: r.ID, P: p.ID, Op: rr.Operation, C: cs, K: r.Card})
		}
		for _, g := range order {
			pv.Groups = append(pv.Groups, *groups[g])
		}
		var buf bytes.Buffer
		if err := s.tmpl.ExecuteTemplate(&buf, "provider.html", pv); err != nil {
			return err
		}
		out := "catalog/" + p.ID + ".html"
		if err := s.render(out, view{Title: p.Title, Description: fmt.Sprintf("%d Opfence rules for %s.", len(p.Rules), p.Title), Class: "catalog",
			Current: "catalog/index.html", Body: template.HTML(buf.String())}); err != nil {
			return err
		}
		rows = append(rows, providerRow{ID: p.ID, Title: p.Title, Kind: pv.Kind, Hosts: pv.Hosts, Rules: len(p.Rules), Classes: pv.Classes})
	}
	b, err := json.Marshal(index)
	if err != nil {
		return err
	}
	if err := s.write("catalog/rules.json", b); err != nil {
		return err
	}
	total := 0
	for _, r := range rows {
		total += r.Rules
	}
	var buf bytes.Buffer
	if err := s.tmpl.ExecuteTemplate(&buf, "catalog.html", map[string]any{"Providers": rows, "Total": total, "Classes": classOrder}); err != nil {
		return err
	}
	return s.render("catalog/index.html", view{Title: "Catalog", Description: fmt.Sprintf("Every Opfence rule: %d across %d providers and MCP servers.", total, len(rows)),
		Class: "catalog", Body: template.HTML(buf.String())})
}

func kind(p *catalog.Provider) string {
	switch {
	case p.MCP != nil && len(p.Hosts) == 0:
		return "MCP server (local)"
	case p.MCP != nil:
		return "MCP server"
	case p.SigV4:
		return "AWS API"
	case len(p.GraphQL) > 0:
		return "REST and GraphQL API"
	}
	return "REST API"
}

func classCounts(rules []*catalog.Rule) []classCount {
	n := map[string]int{}
	for _, r := range rules {
		n[string(r.Class)]++
	}
	var out []classCount
	for _, c := range classOrder {
		if n[c] > 0 {
			out = append(out, classCount{Class: c, N: n[c], Pct: 100 * float64(n[c]) / float64(len(rules))})
		}
	}
	return out
}

// operation describes what a rule matches, the way explain prints it.
func operation(r *catalog.Rule) string {
	m := r.Match
	switch {
	case m.REST != nil:
		return m.REST.Method + " " + m.REST.Path
	case m.GraphQL != nil:
		return m.GraphQL.Type + " " + m.GraphQL.Field
	case m.MCP != nil:
		return "tool " + m.MCP.Tool
	case m.AWS != nil && m.AWS.Action != "":
		return m.AWS.Service + " " + m.AWS.Action
	case m.AWS != nil:
		return m.AWS.Service + " " + m.AWS.Method + " " + m.AWS.Path
	case m.Git != nil:
		s := "git " + m.Git.Service + " " + m.Git.Command
		if len(m.Git.Refs) > 0 {
			s += " " + strings.Join(m.Git.Refs, ", ")
		}
		return s
	case m.CLI != nil:
		return "command " + m.CLI.Command
	}
	return r.ID
}

func joinClasses(cs []classes.Class) string {
	var s []string
	for _, c := range cs {
		s = append(s, string(c))
	}
	return strings.Join(s, ", ")
}
