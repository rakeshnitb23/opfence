package catalog

import (
	"testing"
	"testing/fstest"

	"github.com/rakeshnitb23/opfence/internal/decode"
)

func TestRESTSpecificity(t *testing.T) {
	m := fstest.MapFS{
		"gh/provider.yaml": {Data: []byte("provider: gh\ntitle: GH\nhosts: [api.gh.dev, \"*.gh.dev\"]\n")},
		"gh/r.yaml": {Data: []byte(`operations:
  - { id: gh.any.delete, match: { rest: { method: DELETE, path: "/repos/{rest*}" } }, class: delete, card: x, status: community }
  - { id: gh.repo.delete, match: { rest: { method: DELETE, path: "/repos/{owner}/{repo}" } }, class: irreversible, card: x, status: community }
  - { id: gh.ref.delete, match: { rest: { method: DELETE, path: "/repos/{owner}/{repo}/git/refs/{ref*}" } }, class: delete, card: x, status: community }
  - { id: gh.a.delete, match: { rest: { method: DELETE, path: "/a/{x}" } }, class: delete, card: x, status: community }
  - { id: gh.b.delete, match: { rest: { method: DELETE, path: "/{y}/b" } }, class: irreversible, card: x, status: community }
`)},
	}
	c, err := Load(m)
	if err != nil {
		t.Fatal(err)
	}
	p := c.ProviderForHost("api.gh.dev")
	if p == nil || c.ProviderForHost("uploads.gh.dev") != p || c.ProviderForHost("gh.dev") != nil {
		t.Fatal("host lookup")
	}
	cases := map[string]string{
		"/repos/o/r":                     "gh.repo.delete",
		"/repos/o/r/":                    "gh.repo.delete",
		"/repos/o/r/git/refs/heads/main": "gh.ref.delete",
		"/repos/o/r/collaborators/u":     "gh.any.delete",
		"/a/b":                           "gh.a.delete",
		"/z/b":                           "gh.b.delete",
	}
	for path, want := range cases {
		r, params := p.Match(decode.Operation{Protocol: decode.REST, Method: "DELETE", Path: path}, false)
		if r == nil || r.ID != want {
			t.Errorf("%s matched %v, want %s", path, r, want)
		}
		if want == "gh.ref.delete" && params["ref"] != "heads/main" {
			t.Errorf("params = %v", params)
		}
	}
	if r, _ := p.Match(decode.Operation{Protocol: decode.REST, Method: "GET", Path: "/repos/o/r"}, false); r != nil {
		t.Errorf("GET matched %s", r.ID)
	}
	if r, _ := p.Match(decode.Operation{Protocol: decode.REST, Method: "DELETE", Path: "/repos/o/r", Error: "x"}, false); r != nil {
		t.Error("failed operation matched a rule")
	}
}

func TestConditionEval(t *testing.T) {
	yes := "yes"
	args := map[string]any{"a": map[string]any{"b": "YES", "n": nil, "list": []any{"x"}}, "flag": true}
	cases := []struct {
		c    Condition
		want bool
	}{
		{Condition{Arg: "a.b", Equals: &yes}, true},
		{Condition{Arg: "a.b", In: []string{"no", "yes"}}, true},
		{Condition{Arg: "a.missing", Absent: true}, true},
		{Condition{Arg: "a.n", Absent: true}, true},
		{Condition{Arg: "a.n", Present: true}, false},
		{Condition{Arg: "a.list", Equals: &yes}, false},
		{Condition{Arg: "flag", In: []string{"TRUE"}}, true},
		{Condition{Arg: "a.b.c", Present: true}, false},
	}
	for i, c := range cases {
		if got := c.c.Eval(args); got != c.want {
			t.Errorf("case %d (%s): got %v", i, c.c.String(), got)
		}
	}
}
