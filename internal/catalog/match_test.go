package catalog

import (
	"strings"
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
	args := map[string]any{
		"a":       map[string]any{"b": "YES", "n": nil, "list": []any{"x"}},
		"flag":    true,
		"query":   map[string]any{"decrypt": []any{"false", "true"}},
		"updates": []any{map[string]any{"force": false}, map[string]any{"force": true}, "junk"},
		"nulls":   []any{nil},
	}
	tru := "true"
	cases := []struct {
		c    Condition
		want bool
	}{
		{Condition{Arg: "a.b", Equals: &yes}, true},
		{Condition{Arg: "a.b", In: []string{"no", "yes"}}, true},
		{Condition{Arg: "a.missing", Absent: true}, true},
		{Condition{Arg: "a.n", Absent: true}, false},
		{Condition{Arg: "a.n", Present: true}, true},
		{Condition{Arg: "a.list", Equals: &yes}, false},
		{Condition{Arg: "a.list", In: []string{"x"}}, true},
		{Condition{Arg: "query.decrypt", Equals: &tru}, true},
		{Condition{Arg: "updates.force", Equals: &tru}, true},
		{Condition{Arg: "updates.missing", Present: true}, false},
		{Condition{Arg: "nulls", Present: true}, true},
		{Condition{Arg: "nulls", Absent: true}, false},
		{Condition{Arg: "flag", In: []string{"TRUE"}}, true},
		{Condition{Arg: "a.b.c", Present: true}, false},
	}
	for i, c := range cases {
		if got := c.c.Eval(args); got != c.want {
			t.Errorf("case %d (%s): got %v", i, c.c.String(), got)
		}
	}
}

func TestLookupThroughLists(t *testing.T) {
	args := map[string]any{"input": map[string]any{"refUpdates": []any{
		map[string]any{"name": "a", "tags": []any{"x", "y"}},
		map[string]any{"name": "b", "tags": []any{"z"}},
		map[string]any{"other": 1},
	}}}
	v, ok := Lookup(args, "input.refUpdates.name")
	if !ok || len(v.([]any)) != 2 {
		t.Fatalf("names = %v, %v", v, ok)
	}
	v, ok = Lookup(args, "input.refUpdates.tags")
	if !ok || len(v.([]any)) != 3 {
		t.Fatalf("tags flattened = %v, %v", v, ok)
	}
	if _, ok := Lookup(args, "input.refUpdates.missing"); ok {
		t.Fatal("missing field found")
	}
}

func TestGitRefSpecificity(t *testing.T) {
	m := goodFS()
	m["acme/provider.yaml"] = &fstest.MapFile{Data: []byte(strings.Replace(goodProvider, "hosts: [api.acme.dev]", "hosts: [api.acme.dev]\ngit: [api.acme.dev]", 1))}
	m["acme/git.yaml"] = &fstest.MapFile{Data: []byte(`operations:
  - id: acme.git.update
    match: { git: { service: receive-pack, command: update } }
    class: write
    card: x
    status: community
  - id: acme.git.update-main
    match: { git: { service: receive-pack, command: update, refs: [refs/heads/main] } }
    class: delete
    card: x
    status: community
  - id: acme.git.update-release
    match: { git: { service: receive-pack, command: update, refs: ["refs/heads/release/*"] } }
    class: delete
    card: x
    status: community
`)}
	c, err := Load(m)
	if err != nil {
		t.Fatal(err)
	}
	p := c.Provider("acme")
	for ref, want := range map[string]string{
		"refs/heads/main":        "acme.git.update-main",
		"refs/heads/main2":       "acme.git.update",
		"refs/heads/release/1.0": "acme.git.update-release",
		"refs/heads/release":     "acme.git.update",
		"refs/tags/v1":           "acme.git.update",
	} {
		op := decode.Operation{Protocol: decode.Git, Service: decode.GitReceivePack, Action: decode.GitUpdate, Args: map[string]any{"ref": ref}}
		if r, _ := p.Match(op, false); r == nil || r.ID != want {
			t.Errorf("%s: got %v, want %s", ref, r, want)
		}
	}
	if !p.Hints("api.acme.dev").Git || p.Hints("other.acme.dev").Git {
		t.Error("git hint is per host")
	}
}
