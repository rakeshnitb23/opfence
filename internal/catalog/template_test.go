package catalog

import (
	"reflect"
	"testing"
)

func TestParseTemplateErrors(t *testing.T) {
	bad := []string{
		"", "v9/projects", "/v9//projects", "/v9/projects/", "/a/{id}.json", "/a/{id}/{id}",
		"/a/{rest*}/b", "/a/{1x}", "/a?b=c", "/a/./b", "/a/../b", "/a/{}", "/a/{x",
	}
	for _, s := range bad {
		if _, err := ParseTemplate(s); err == nil {
			t.Errorf("ParseTemplate(%q) succeeded", s)
		}
	}
}

func TestTemplateMatch(t *testing.T) {
	cases := []struct {
		tmpl, path string
		want       map[string]string
	}{
		{"/v9/projects/{idOrName}", "/v9/projects/web", map[string]string{"idOrName": "web"}},
		{"/v9/projects/{idOrName}", "/v9/projects/web/", map[string]string{"idOrName": "web"}},
		{"/v9/projects/{idOrName}", "//v9//projects/web", map[string]string{"idOrName": "web"}},
		{"/v9/projects/{idOrName}", "/v9/./projects/x/../web", map[string]string{"idOrName": "web"}},
		{"/v9/projects/{idOrName}", "/v9/%70rojects/my%20app", map[string]string{"idOrName": "my app"}},
		{"/v9/projects/{idOrName}", "/v9/projects/a%2Fb", map[string]string{"idOrName": "a/b"}},
		{"/v9/projects/{idOrName}", "/v9/projects", nil},
		{"/v9/projects/{idOrName}", "/v9/projects/web/env", nil},
		{"/v9/projects/{idOrName}", "/v10/projects/web", nil},
		{"/v9/projects/{idOrName}", "/../v9/projects/web", nil},
		{"/v9/projects/{idOrName}", "/v9/projects/%zz", nil},
		{"/repos/{owner}/{repo}/contents/{path*}", "/repos/o/r/contents/a/b/c.txt", map[string]string{"owner": "o", "repo": "r", "path": "a/b/c.txt"}},
		{"/repos/{owner}/{repo}/contents/{path*}", "/repos/o/r/contents", nil},
		{"/", "/", map[string]string{}},
		{"/", "//", map[string]string{}},
	}
	for _, c := range cases {
		tm, err := ParseTemplate(c.tmpl)
		if err != nil {
			t.Fatalf("ParseTemplate(%q): %v", c.tmpl, err)
		}
		got, ok := tm.Match(c.path)
		if c.want == nil {
			if ok {
				t.Errorf("%s matched %s: %v", c.tmpl, c.path, got)
			}
			continue
		}
		if !ok || !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s on %s = %v, %v; want %v", c.tmpl, c.path, got, ok, c.want)
		}
	}
}

func TestShapeAndSpecificity(t *testing.T) {
	a, _ := ParseTemplate("/v9/projects/{id}")
	b, _ := ParseTemplate("/v9/projects/{name}")
	if a.Shape() != b.Shape() {
		t.Errorf("shapes differ: %s vs %s", a.Shape(), b.Shape())
	}
	lit, _ := ParseTemplate("/v9/projects/search")
	rest, _ := ParseTemplate("/v9/{x*}")
	if !lit.MoreSpecific(a) || a.MoreSpecific(lit) {
		t.Error("literal segment should be more specific than a parameter")
	}
	if !a.MoreSpecific(rest) {
		t.Error("parameter template should beat a trailing wildcard")
	}
}
