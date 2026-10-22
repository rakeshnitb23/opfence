package main

import (
	"bytes"
	"net/url"
	"path"
	"strings"

	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/ast"
	"github.com/yuin/goldmark/extension"
	"github.com/yuin/goldmark/parser"
	"github.com/yuin/goldmark/renderer/html"
	"github.com/yuin/goldmark/text"
	"github.com/yuin/goldmark/util"
)

// renderMarkdown renders a repository Markdown file as page p. Links to
// other repository files become links to their pages on the site, or to the
// file on GitHub when the site has no page for it. It also returns the
// page's h2 and h3 headings for a table of contents.
func renderMarkdown(src []byte, p page, links map[string]string) (string, []tocEntry, error) {
	var toc []tocEntry
	md := goldmark.New(
		goldmark.WithExtensions(extension.GFM),
		goldmark.WithParserOptions(
			parser.WithAutoHeadingID(),
			parser.WithASTTransformers(util.Prioritized(&linkRewriter{p: p, links: links, toc: &toc}, 100)),
		),
		// Raw HTML in the docs is not rendered: the site shows only what
		// Markdown produces.
		goldmark.WithRendererOptions(html.WithXHTML()),
	)
	var buf bytes.Buffer
	if err := md.Convert(src, &buf); err != nil {
		return "", nil, err
	}
	return buf.String(), toc, nil
}

type linkRewriter struct {
	p     page
	links map[string]string
	toc   *[]tocEntry
}

func (lr *linkRewriter) Transform(doc *ast.Document, reader text.Reader, _ parser.Context) {
	src := reader.Source()
	var title ast.Node
	_ = ast.Walk(doc, func(n ast.Node, entering bool) (ast.WalkStatus, error) {
		if !entering {
			return ast.WalkContinue, nil
		}
		switch x := n.(type) {
		case *ast.Heading:
			if x.Level == 1 && title == nil {
				title = x // the layout shows the title; drop the document's own
				return ast.WalkSkipChildren, nil
			}
			if x.Level == 2 || x.Level == 3 {
				id, _ := x.AttributeString("id")
				ids, _ := id.([]byte)
				*lr.toc = append(*lr.toc, tocEntry{ID: string(ids), Text: plainText(x, src), Level: x.Level})
			}
		case *ast.Link:
			x.Destination = []byte(lr.rewrite(string(x.Destination)))
		}
		return ast.WalkContinue, nil
	})
	if title != nil {
		title.Parent().RemoveChild(title.Parent(), title)
	}
}

// rewrite maps a link in the page's source file to the site.
func (lr *linkRewriter) rewrite(dest string) string {
	u, err := url.Parse(dest)
	if err != nil || u.Scheme != "" || u.Host != "" || strings.HasPrefix(dest, "#") || dest == "" {
		return dest
	}
	target := path.Clean(path.Join(path.Dir(lr.p.src), u.Path))
	frag := ""
	if u.Fragment != "" {
		frag = "#" + u.Fragment
	}
	if out, ok := lr.links[strings.TrimSuffix(target, "/")]; ok {
		return relative(lr.p.out, out) + frag
	}
	if strings.HasPrefix(target, "../") {
		return dest
	}
	return repoURL + "/blob/main/" + target + frag
}

// relative returns the link from page from to page to, both site paths.
func relative(from, to string) string {
	return base(from) + to
}

func plainText(n ast.Node, src []byte) string {
	var b strings.Builder
	_ = ast.Walk(n, func(c ast.Node, entering bool) (ast.WalkStatus, error) {
		if entering {
			if t, ok := c.(*ast.Text); ok {
				b.Write(t.Segment.Value(src))
			} else if s, ok := c.(*ast.String); ok {
				b.Write(s.Value)
			}
		}
		return ast.WalkContinue, nil
	})
	return b.String()
}
