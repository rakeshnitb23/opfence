package main

import (
	"html"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var (
	idRe   = regexp.MustCompile(`\sid="([^"]*)"`)
	linkRe = regexp.MustCompile(`\s(?:href|src)="([^"]*)"`)
)

// TestBuild builds the whole site from this repository and checks that
// every page, asset and in-site link it writes resolves, anchors included.
func TestBuild(t *testing.T) {
	out := t.TempDir()
	if err := build("../..", out); err != nil {
		t.Fatal(err)
	}

	pages := map[string]string{} // site path -> HTML
	err := filepath.WalkDir(out, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".html") {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(out, p)
		pages[filepath.ToSlash(rel)] = string(b)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"index.html", "quickstart.html", "docs/architecture.html", "docs/limits.html", "catalog/index.html", "catalog/railway.html", "catalog/supabase-mcp.html"} {
		if pages[want] == "" {
			t.Errorf("%s was not written", want)
		}
	}
	for _, f := range []string{"assets/style.css", "assets/search.js", "assets/icon.svg", "assets/fonts/OFL.txt", "catalog/rules.json"} {
		if _, err := os.Stat(filepath.Join(out, f)); err != nil {
			t.Errorf("%s: %v", f, err)
		}
	}

	ids := map[string]map[string]bool{}
	for p, body := range pages {
		ids[p] = map[string]bool{}
		for _, m := range idRe.FindAllStringSubmatch(body, -1) {
			ids[p][html.UnescapeString(m[1])] = true
		}
	}
	checked := 0
	for p, body := range pages {
		for _, m := range linkRe.FindAllStringSubmatch(body, -1) {
			raw := html.UnescapeString(m[1])
			u, err := url.Parse(raw)
			if err != nil {
				t.Errorf("%s: bad link %q: %v", p, raw, err)
				continue
			}
			if u.Scheme != "" || u.Host != "" {
				continue
			}
			target := p
			if u.Path != "" {
				target = path.Clean(path.Join(path.Dir(p), u.Path))
			}
			if strings.HasPrefix(target, "../") {
				t.Errorf("%s: link %q leaves the site", p, raw)
				continue
			}
			if _, err := os.Stat(filepath.Join(out, filepath.FromSlash(target))); err != nil {
				t.Errorf("%s: link %q: no file %s", p, raw, target)
				continue
			}
			if u.Fragment != "" && strings.HasSuffix(target, ".html") && !ids[target][u.Fragment] {
				t.Errorf("%s: link %q: no anchor #%s in %s", p, raw, u.Fragment, target)
			}
			checked++
		}
	}
	if checked < 1000 {
		t.Errorf("only %d in-site links checked", checked)
	}

	// The hero is the call from the PocketOS incident, decided live.
	home := pages["index.html"]
	for _, want := range []string{"backboard.railway.com/graphql/v2", `class="dec d-confirm">confirm`, "<code>vol-pg-data</code>", `href="catalog/railway.html#railway.volume.delete"`} {
		if !strings.Contains(home, want) {
			t.Errorf("home page lacks %q", want)
		}
	}
	// Raw HTML in the docs is dropped, except empty anchors.
	if !ids["docs/plan.html"]["name-candidates"] {
		t.Error("docs/plan.html lost its name-candidates anchor")
	}
	if strings.Contains(pages["docs/plan.html"], "OPFENCE-ANCHOR") {
		t.Error("an anchor placeholder was left in docs/plan.html")
	}
}

func TestRenderMarkdownLinks(t *testing.T) {
	p := page{src: "docs/LIMITS.md", out: "docs/limits.html"}
	links := map[string]string{"docs/ARCHITECTURE.md": "docs/architecture.html", "README.md": "index.html"}
	src := "# Title\n\nSee [arch](ARCHITECTURE.md#4-catalog), [home](../README.md), [code](../internal/engine/engine.go), [web](https://example.com) and [here](#x).\n\n<script>alert(1)</script>\n\n<a id=\"ok-anchor\"></a>Text <a id=\"bad id\"></a>\n\n## Section two\n"
	body, toc, err := renderMarkdown([]byte(src), p, links)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`href="architecture.html#4-catalog"`,
		`href="../index.html"`,
		`href="` + repoURL + `/blob/main/internal/engine/engine.go"`,
		`href="https://example.com"`,
		`href="#x"`,
		`<a id="ok-anchor"></a>`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("rendered page lacks %s:\n%s", want, body)
		}
	}
	for _, bad := range []string{"<script", `id="bad id"`, "<h1"} {
		if strings.Contains(body, bad) {
			t.Errorf("rendered page contains %s:\n%s", bad, body)
		}
	}
	if len(toc) != 1 || toc[0].ID != "section-two" || toc[0].Level != 2 {
		t.Errorf("toc = %+v", toc)
	}
}

func TestHelpers(t *testing.T) {
	for n, want := range map[int]string{0: "0", 999: "999", 1000: "1,000", 6468: "6,468", 1234567: "1,234,567"} {
		if got := num(n); got != want {
			t.Errorf("num(%d) = %q, want %q", n, got, want)
		}
	}
	if got := clip("abcdef", 4); got != "abc…" {
		t.Errorf("clip = %q", got)
	}
	if got := linkHost("https://www.npmjs.com/package/x"); got != "npmjs.com" {
		t.Errorf("linkHost = %q", got)
	}
	if got := shownBody([]byte(`{"query":"mutation { a }","variables":{"x":1}}`)); got != "mutation { a }\nvariables {\"x\":1}" {
		t.Errorf("shownBody = %q", got)
	}
	if got := base("catalog/railway.html"); got != "../" {
		t.Errorf("base = %q", got)
	}
}

func TestRelative(t *testing.T) {
	for _, c := range []struct{ from, to, want string }{
		{"index.html", "quickstart.html", "quickstart.html"},
		{"index.html", "docs/limits.html", "docs/limits.html"},
		{"docs/limits.html", "docs/architecture.html", "architecture.html"},
		{"docs/limits.html", "index.html", "../index.html"},
		{"docs/limits.html", "catalog/index.html", "../catalog/index.html"},
		{"quickstart.html", "docs/plan.html", "docs/plan.html"},
	} {
		if got := relative(c.from, c.to); got != c.want {
			t.Errorf("relative(%q, %q) = %q, want %q", c.from, c.to, got, c.want)
		}
	}
}
