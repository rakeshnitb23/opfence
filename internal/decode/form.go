package decode

import (
	"fmt"
	"net/url"
	"slices"
	"strconv"
	"strings"
)

// maxFormDepth caps the bracket groups in one form key.
const maxFormDepth = 10

// formArgs turns a query string or form body into args, nesting bracket
// keys the way Stripe, Rails and PHP read them: metadata[plan]=pro becomes
// metadata.plan, expand[]=a&expand[]=b the list expand, and
// items[0][price]=x a list of objects, so conditions can name them with
// dotted paths. A key that is not of the form name[...][...] stays as it
// is, as does a list-append ([]) anywhere but at the end. A name used both
// for a value and for nested keys (a=1&a[b]=2) is an error: servers resolve
// it differently, so Opfence cannot know which reading runs.
func formArgs(v url.Values) (map[string]any, error) {
	root := &formNode{}
	keys := make([]string, 0, len(v))
	for k := range v {
		keys = append(keys, k)
	}
	slices.Sort(keys) // deterministic errors
	for _, k := range keys {
		path, ok := splitFormKey(k)
		n := root
		if !ok {
			path = []string{k}
		}
		for i, seg := range path {
			if seg == "" { // a trailing []: the values form a list
				n.list = true
				break
			}
			n = n.child(seg)
			if i == len(path)-1 {
				n.values = append(n.values, v[k]...)
			}
		}
		if path[len(path)-1] == "" {
			n.values = append(n.values, v[k]...)
		}
	}
	out, err := root.build("")
	if err != nil {
		return nil, err
	}
	m, _ := out.(map[string]any)
	if m == nil {
		m = map[string]any{}
	}
	return m, nil
}

type formNode struct {
	values   []string
	list     bool // values came from name[]=
	children map[string]*formNode
}

func (n *formNode) child(seg string) *formNode {
	if n.children == nil {
		n.children = map[string]*formNode{}
	}
	c := n.children[seg]
	if c == nil {
		c = &formNode{}
		n.children[seg] = c
	}
	return c
}

func (n *formNode) build(name string) (any, error) {
	if len(n.children) == 0 {
		if !n.list && len(n.values) == 1 {
			return n.values[0], nil
		}
		list := make([]any, len(n.values))
		for i, s := range n.values {
			list[i] = s
		}
		return list, nil
	}
	if len(n.values) > 0 {
		return nil, fmt.Errorf("form key %s has both a value and nested keys", name)
	}
	keys := make([]string, 0, len(n.children))
	numeric := true
	for k := range n.children {
		keys = append(keys, k)
		if _, err := strconv.ParseUint(k, 10, 31); err != nil {
			numeric = false
		}
	}
	if numeric && name != "" {
		// Indices keep their order, gaps closed, as servers read them.
		slices.SortFunc(keys, func(a, b string) int {
			x, _ := strconv.Atoi(a)
			y, _ := strconv.Atoi(b)
			return x - y
		})
		list := make([]any, 0, len(keys))
		for _, k := range keys {
			v, err := n.children[k].build(name + "[" + k + "]")
			if err != nil {
				return nil, err
			}
			list = append(list, v)
		}
		return list, nil
	}
	m := make(map[string]any, len(keys))
	for _, k := range keys {
		child := k
		if name != "" {
			child = name + "[" + k + "]"
		}
		v, err := n.children[k].build(child)
		if err != nil {
			return nil, err
		}
		m[k] = v
	}
	return m, nil
}

// splitFormKey splits name[a][b] into name, a, b. It reports false for a
// key that is not exactly that shape, or that puts [] before the end.
func splitFormKey(k string) ([]string, bool) {
	i := strings.IndexByte(k, '[')
	if i <= 0 || !strings.HasSuffix(k, "]") {
		return nil, false
	}
	path := []string{k[:i]}
	rest := k[i:]
	for rest != "" {
		if rest[0] != '[' {
			return nil, false
		}
		end := strings.IndexByte(rest, ']')
		seg := rest[1:end]
		if strings.ContainsAny(seg, "[") || (seg == "" && end != len(rest)-1) {
			return nil, false
		}
		path = append(path, seg)
		rest = rest[end+1:]
	}
	if len(path) > maxFormDepth+1 {
		return nil, false
	}
	return path, true
}
