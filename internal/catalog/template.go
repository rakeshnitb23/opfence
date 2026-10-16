package catalog

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// Template is a parsed REST path template such as
// /v9/projects/{idOrName} or /repos/{owner}/{repo}/contents/{path*}.
type Template struct {
	Raw      string
	Segments []Segment
}

// Segment is one path segment of a Template.
type Segment struct {
	Literal string // set for literal segments
	Param   string // set for {name} and {name*} segments
	Rest    bool   // {name*}: matches one or more remaining segments
}

var paramName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// ParseTemplate parses a REST path template.
func ParseTemplate(s string) (*Template, error) {
	if !strings.HasPrefix(s, "/") {
		return nil, fmt.Errorf("path template %q must start with /", s)
	}
	if strings.ContainsAny(s, "?#") {
		return nil, fmt.Errorf("path template %q must not contain a query or fragment", s)
	}
	t := &Template{Raw: s}
	if s == "/" {
		return t, nil
	}
	parts := strings.Split(s[1:], "/")
	seen := map[string]bool{}
	for i, p := range parts {
		if p == "" {
			return nil, fmt.Errorf("path template %q has an empty segment", s)
		}
		if p == "." || p == ".." {
			return nil, fmt.Errorf("path template %q has a dot segment", s)
		}
		if !strings.ContainsAny(p, "{}") {
			t.Segments = append(t.Segments, Segment{Literal: p})
			continue
		}
		if !strings.HasPrefix(p, "{") || !strings.HasSuffix(p, "}") || strings.Count(p, "{") != 1 || strings.Count(p, "}") != 1 {
			return nil, fmt.Errorf("path template %q: segment %q must be a literal or a whole {param}", s, p)
		}
		name := p[1 : len(p)-1]
		rest := strings.HasSuffix(name, "*")
		name = strings.TrimSuffix(name, "*")
		if !paramName.MatchString(name) {
			return nil, fmt.Errorf("path template %q: bad parameter name %q", s, name)
		}
		if seen[name] {
			return nil, fmt.Errorf("path template %q: parameter %q appears twice", s, name)
		}
		seen[name] = true
		if rest && i != len(parts)-1 {
			return nil, fmt.Errorf("path template %q: {%s*} must be the last segment", s, name)
		}
		t.Segments = append(t.Segments, Segment{Param: name, Rest: rest})
	}
	return t, nil
}

// Shape returns the template with parameter names erased, so templates that
// match exactly the same paths have the same shape.
func (t *Template) Shape() string {
	if len(t.Segments) == 0 {
		return "/"
	}
	var b strings.Builder
	for _, s := range t.Segments {
		b.WriteByte('/')
		switch {
		case s.Rest:
			b.WriteString("{*}")
		case s.Param != "":
			b.WriteString("{}")
		default:
			b.WriteString(s.Literal)
		}
	}
	return b.String()
}

// Specificity orders templates that match the same path: more literal
// segments first, then no trailing wildcard, then more segments.
func (t *Template) Specificity() (literals int, noRest bool, segments int) {
	noRest = true
	for _, s := range t.Segments {
		if s.Literal != "" {
			literals++
		}
		if s.Rest {
			noRest = false
		}
	}
	return literals, noRest, len(t.Segments)
}

// MoreSpecific reports whether t should win over u when both match a path.
func (t *Template) MoreSpecific(u *Template) bool {
	tl, tn, ts := t.Specificity()
	ul, un, us := u.Specificity()
	if tl != ul {
		return tl > ul
	}
	if tn != un {
		return tn
	}
	return ts > us
}

// Match matches a raw request path (not unescaped, without the query) and
// returns the captured parameters, unescaped.
//
// The path is normalised first, the same way most servers route it, so an
// agent cannot dodge a rule with "//", "/./", "/x/../" or a trailing slash.
// Percent-encoded slashes stay inside their segment. A path that cannot be
// normalised (".." above the root, bad escapes) never matches; callers treat
// that as unknown.
func (t *Template) Match(rawPath string) (map[string]string, bool) {
	segs, ok := NormalizePath(rawPath)
	if !ok {
		return nil, false
	}
	params := map[string]string{}
	for i, ts := range t.Segments {
		if i >= len(segs) {
			return nil, false
		}
		switch {
		case ts.Rest:
			vals := make([]string, 0, len(segs)-i)
			for _, s := range segs[i:] {
				v, err := url.PathUnescape(s)
				if err != nil {
					return nil, false
				}
				vals = append(vals, v)
			}
			params[ts.Param] = strings.Join(vals, "/")
			return params, true
		case ts.Param != "":
			v, err := url.PathUnescape(segs[i])
			if err != nil {
				return nil, false
			}
			params[ts.Param] = v
		default:
			v, err := url.PathUnescape(segs[i])
			if err != nil || v != ts.Literal {
				return nil, false
			}
		}
	}
	if len(segs) != len(t.Segments) {
		return nil, false
	}
	return params, true
}

// NormalizePath splits a raw path into segments after collapsing repeated
// slashes, dropping "." segments and a trailing slash, and resolving "..".
// It reports false for a path that escapes the root or is not absolute.
func NormalizePath(rawPath string) ([]string, bool) {
	if !strings.HasPrefix(rawPath, "/") {
		return nil, false
	}
	var out []string
	for _, s := range strings.Split(rawPath, "/") {
		// Unescape only to recognise dot segments; keep the raw form.
		dec, err := url.PathUnescape(s)
		if err != nil {
			return nil, false
		}
		switch dec {
		case "", ".":
			continue
		case "..":
			if len(out) == 0 {
				return nil, false
			}
			out = out[:len(out)-1]
			continue
		}
		out = append(out, s)
	}
	return out, true
}
