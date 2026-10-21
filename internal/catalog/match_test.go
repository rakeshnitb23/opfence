package catalog

import (
	"slices"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/rakeshnitb23/opfence/internal/classes"
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

func TestClassifyClasses(t *testing.T) {
	R, W, D, I, U := classes.Read, classes.Write, classes.Delete, classes.Irreversible, classes.Unknown
	pg := &Classify{SQL: Strings{"q"}}
	for _, tc := range []struct {
		c    *Classify
		args map[string]any
		want []classes.Class
	}{
		{pg, map[string]any{"q": "select 1"}, []classes.Class{R}},
		{pg, map[string]any{"q": []any{"select 1", "drop table t"}}, []classes.Class{R, I}},
		// An unterminated quote in one statement cannot swallow the next.
		{pg, map[string]any{"q": []any{"select 'x", "drop table t"}}, []classes.Class{U, I}},
		{pg, map[string]any{"q": []any{"select 1", 7.0}}, nil},
		{pg, map[string]any{"q": []any{}}, nil},
		{pg, map[string]any{"q": map[string]any{"q": "select 1"}}, nil},
		{pg, map[string]any{"q": nil}, nil},
		{pg, map[string]any{}, nil},
		// Several arguments: whichever are present.
		{&Classify{SQL: Strings{"body.sql", "body.batch.sql"}, Dialect: Strings{"sqlite"}},
			map[string]any{"body": map[string]any{"sql": "select 1"}}, []classes.Class{R}},
		{&Classify{SQL: Strings{"body.sql", "body.batch.sql"}, Dialect: Strings{"sqlite"}},
			map[string]any{"body": map[string]any{"batch": []any{map[string]any{"sql": "select 1"}, map[string]any{"sql": "delete from t where id = 1"}}}},
			[]classes.Class{R, D}},
		{&Classify{SQL: Strings{"body.sql", "body.batch.sql"}, Dialect: Strings{"sqlite"}},
			map[string]any{"body": map[string]any{"sql": 7.0, "batch": []any{map[string]any{"sql": "select 1"}}}}, nil},
		// Dialects: each reads its own quoting.
		{&Classify{SQL: Strings{"q"}, Dialect: Strings{"sqlite"}}, map[string]any{"q": `select 'a\'; drop table t; -- '`}, []classes.Class{R, I}},
		{&Classify{SQL: Strings{"q"}, Dialect: Strings{"mysql"}}, map[string]any{"q": `select 'a\'; drop table t; -- '`}, []classes.Class{R}},
		// Several dialects: every reading counts.
		{&Classify{SQL: Strings{"q"}, Dialect: Strings{"mysql", "postgres"}}, map[string]any{"q": "insert into t values (1)"}, []classes.Class{W}},
		{&Classify{SQL: Strings{"q"}, Dialect: Strings{"mysql", "postgres"}}, map[string]any{"q": "insert into `t` values (1)"}, []classes.Class{W, U}},
		{&Classify{SQL: Strings{"q"}, Dialect: Strings{"mysql", "postgres"}}, map[string]any{"q": `select 'a\'; drop table t; -- '`}, []classes.Class{R, I}},
		// libSQL bodies.
		{&Classify{SQL: Strings{"body"}, Format: FormatLibSQL},
			map[string]any{"body": map[string]any{"requests": []any{map[string]any{"type": "execute", "stmt": map[string]any{"sql": "select 1"}}, map[string]any{"type": "close"}}}},
			[]classes.Class{R}},
		{&Classify{SQL: Strings{"body"}, Format: FormatLibSQL},
			map[string]any{"body": map[string]any{"requests": []any{map[string]any{"type": "close"}}}}, []classes.Class{R}},
		{&Classify{SQL: Strings{"body"}, Format: FormatLibSQL},
			map[string]any{"body": map[string]any{"statements": []any{"delete from t"}}}, []classes.Class{I}},
		{&Classify{SQL: Strings{"body"}, Format: FormatLibSQL},
			map[string]any{"body": map[string]any{"requests": []any{map[string]any{"type": "execute", "stmt": map[string]any{"sql_id": 1.0}}}}}, []classes.Class{U}},
		{&Classify{SQL: Strings{"body"}, Format: FormatLibSQL}, map[string]any{"body": "binary"}, nil},
		{&Classify{SQL: Strings{"body"}, Format: FormatLibSQL}, map[string]any{}, nil},
	} {
		if got := tc.c.classes(tc.args); !slices.Equal(got, tc.want) {
			t.Errorf("%s: classes(%v) = %v, want %v", tc.c, tc.args, got, tc.want)
		}
	}
}

// SQL Opfence cannot read gets the rule's own class too, so classifying never
// decides more loosely than the rule's fixed class would.
func TestClassifyUnknownKeepsRuleClass(t *testing.T) {
	R, I, U := classes.Read, classes.Irreversible, classes.Unknown
	r := &Rule{Class: I, Classify: &Classify{SQL: Strings{"sql"}, Dialect: Strings{"sqlite"}}}
	for _, tc := range []struct {
		sql  string
		want []classes.Class
	}{
		{"select 1", []classes.Class{R}},
		{"frobnicate", []classes.Class{U, I}},
		{"select 1; attach 'x.db' as x", []classes.Class{R, U, I}},
		{"drop table t; frobnicate", []classes.Class{U, I}},
	} {
		got, _ := r.ClassesFor(decode.Operation{}, map[string]any{"sql": tc.sql})
		if !slices.Equal(got, tc.want) {
			t.Errorf("ClassesFor(%q) = %v, want %v", tc.sql, got, tc.want)
		}
	}
	got, why := r.ClassesFor(decode.Operation{}, map[string]any{})
	if !slices.Equal(got, []classes.Class{I}) || !strings.Contains(why, "no SQL") {
		t.Errorf("no SQL: got %v (%s)", got, why)
	}
	// A rule whose own class is unknown adds nothing.
	r.Class = U
	if got, _ := r.ClassesFor(decode.Operation{}, map[string]any{"sql": "frobnicate"}); !slices.Equal(got, []classes.Class{U}) {
		t.Errorf("unknown rule: got %v", got)
	}
}

func TestConditionEmpty(t *testing.T) {
	c := Condition{Arg: "filter", Empty: true}
	for _, tc := range []struct {
		args map[string]any
		want bool
	}{
		{map[string]any{}, true},
		{map[string]any{"filter": nil}, true},
		{map[string]any{"filter": ""}, true},
		{map[string]any{"filter": map[string]any{}}, true},
		{map[string]any{"filter": []any{}}, true},
		{map[string]any{"filter": map[string]any{"a": 1.0}}, false},
		{map[string]any{"filter": "x"}, false},
		{map[string]any{"filter": false}, false},
	} {
		if got := c.Eval(tc.args); got != tc.want {
			t.Errorf("Eval(%v) = %v, want %v", tc.args, got, tc.want)
		}
	}
}

func TestPossibleClassesSQL(t *testing.T) {
	for _, tc := range []struct {
		c          *Classify
		credential bool
	}{
		{&Classify{SQL: Strings{"q"}}, true},
		{&Classify{SQL: Strings{"q"}, Dialect: Strings{"mysql"}}, true},
		{&Classify{SQL: Strings{"q"}, Dialect: Strings{"sqlite"}}, false},
		{&Classify{SQL: Strings{"body"}, Format: FormatLibSQL}, false},
		{&Classify{SQL: Strings{"q"}, Dialect: Strings{"sqlite", "mysql"}}, true},
	} {
		cs := (&Rule{Class: classes.Irreversible, Classify: tc.c}).PossibleClasses()
		for _, want := range []classes.Class{classes.Read, classes.Write, classes.Delete, classes.Irreversible, classes.Access, classes.Unknown} {
			if !slices.Contains(cs, want) {
				t.Errorf("%s: %v lacks %s", tc.c, cs, want)
			}
		}
		if got := slices.Contains(cs, classes.Credential); got != tc.credential {
			t.Errorf("%s: credential possible = %v, want %v", tc.c, got, tc.credential)
		}
	}
}

func TestHostMatches(t *testing.T) {
	for _, tc := range []struct {
		pattern, host string
		want          bool
	}{
		{"api.example.com", "api.example.com", true},
		{"api.example.com", "x.api.example.com", false},
		{"*.turso.io", "db-acme.turso.io", true},
		{"*.turso.io", "a.b.turso.io", true},
		{"*.turso.io", "turso.io", false},
		{"*.turso.io", "evilturso.io", false},
		{"api.*.neon.tech", "api.us-east-2.aws.neon.tech", true},
		{"api.*.neon.tech", "api.c-2.us-east-2.aws.neon.tech", true},
		{"api.*.neon.tech", "api.neon.tech", false},
		{"api.*.neon.tech", "ep-cool-darkness-123456.us-east-2.aws.neon.tech", false},
		{"api.*.neon.tech", "apiauth.us-east-2.aws.neon.tech", false},
		{"api.*.neon.tech", "xapi.us-east-2.aws.neon.tech", false},
		{"api.*.neon.tech", "api.us-east-2.aws.neon.tech.evil.com", false},
		{"api.*.neon.tech", "api.evilneon.tech", false},
	} {
		if got := HostMatches(tc.pattern, tc.host); got != tc.want {
			t.Errorf("HostMatches(%q, %q) = %v, want %v", tc.pattern, tc.host, got, tc.want)
		}
	}
}

// The SQL-over-HTTP hosts belong to their own providers, and a database's
// own hosts stay outside the catalog.
func TestProviderForSQLHosts(t *testing.T) {
	c, err := Embedded()
	if err != nil {
		t.Fatal(err)
	}
	for host, want := range map[string]string{
		"api.us-east-2.aws.neon.tech":                                "neon-sql",
		"api.c-2.us-east-2.aws.neon.tech":                            "neon-sql",
		"apiauth.eastus2.azure.neon.tech":                            "neon-sql",
		"console.neon.tech":                                          "neon",
		"ep-cool-darkness-123456.us-east-2.aws.neon.tech":            "",
		"ep-cool-darkness-123456-pooler.c-2.us-east-2.aws.neon.tech": "",
		"aws.connect.psdb.cloud":                                     "planetscale-sql",
		"aws-us-east-2.connect.psdb.cloud":                           "planetscale-sql",
		"api.planetscale.com":                                        "planetscale",
	} {
		got := ""
		if p := c.ProviderForHost(host); p != nil {
			got = p.ID
		}
		if got != want {
			t.Errorf("ProviderForHost(%q) = %q, want %q", host, got, want)
		}
	}
	if p := c.Provider("planetscale-sql"); !slices.Equal(p.DatabasePorts, []int{3306}) {
		t.Errorf("planetscale-sql database_ports = %v", p.DatabasePorts)
	}
}

func TestClassifyRedis(t *testing.T) {
	R, D, I, U := classes.Read, classes.Delete, classes.Irreversible, classes.Unknown
	r := &Rule{Class: I, Classify: &Classify{Redis: Strings{"commands"}}}
	for _, tc := range []struct {
		args map[string]any
		want []classes.Class
		src  string
	}{
		{map[string]any{"commands": []any{[]any{"GET", "k"}}}, []classes.Class{R}, "Redis commands in commands (redis)"},
		{map[string]any{"commands": []any{[]any{"GET", "k"}, []any{"DEL", "k"}}}, []classes.Class{R, D}, "Redis commands"},
		{map[string]any{"commands": []any{"DEL", "k"}}, []classes.Class{D}, "Redis commands"},
		{map[string]any{"commands": []any{[]any{"FLUSHALL"}}}, []classes.Class{I}, "Redis commands"},
		// Unknown commands keep the rule's class too.
		{map[string]any{"commands": []any{[]any{"EVAL", "return 1", "0"}}}, []classes.Class{U, I}, "Redis commands"},
		{map[string]any{"commands": []any{}}, []classes.Class{I}, "no Redis commands"},
		{map[string]any{"commands": "GET k"}, []classes.Class{I}, "no Redis commands"},
		{map[string]any{}, []classes.Class{I}, "no Redis commands"},
	} {
		got, src := r.ClassesFor(decode.Operation{}, tc.args)
		if !slices.Equal(got, tc.want) || !strings.Contains(src, tc.src) {
			t.Errorf("ClassesFor(%v) = %v (%s), want %v (%s)", tc.args, got, src, tc.want, tc.src)
		}
	}
	cs := r.PossibleClasses()
	for _, want := range []classes.Class{R, classes.Write, D, I, classes.Access, classes.Credential, U} {
		if !slices.Contains(cs, want) {
			t.Errorf("PossibleClasses %v lacks %s", cs, want)
		}
	}
}
