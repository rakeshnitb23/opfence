package decode

import (
	"reflect"
	"strings"
	"testing"

	"github.com/rakeshnitb23/opfence/internal/classes"
)

func TestClassifySQLite(t *testing.T) {
	R, W, D, I, A, U := classes.Read, classes.Write, classes.Delete, classes.Irreversible, classes.Access, classes.Unknown
	cases := []struct {
		sql  string
		want []classes.Class
	}{
		{"", []classes.Class{R}},
		{";;", []classes.Class{R}},
		{"select * from orders where id = ?1", []classes.Class{R}},
		{"SELECT 1; SELECT 2", []classes.Class{R}},
		{"values (1), (2)", []classes.Class{R}},
		{"with x as (select 1) select * from x", []classes.Class{R}},
		{"select * from t1 union all select * from t2", []classes.Class{R}},
		{"select count(*), lower(name), json_extract(data, '$.a') from users", []classes.Class{R}},
		{"select * from json_each('[1,2]')", []classes.Class{R}},
		{"select * from pragma_table_info('users')", []classes.Class{R}},
		{"select * from sqlite_master", []classes.Class{R}},
		{"explain query plan delete from t", []classes.Class{R}},
		{"explain drop table t", []classes.Class{R}},
		{"begin; commit", []classes.Class{R}},
		{"savepoint a; release a; rollback", []classes.Class{R}},
		{"insert into t (a) values (1)", []classes.Class{W}},
		{"insert into t values (1) on conflict (id) do update set a = excluded.a", []classes.Class{W}},
		{"insert or replace into t values (1)", []classes.Class{W, D}},
		{"replace into t values (1)", []classes.Class{W, D}},
		{"update or replace t set id = 1 where id = 2", []classes.Class{W, D}},
		{"update or replace t set id = 1", []classes.Class{I}},
		{"insert into t select * from u returning id", []classes.Class{W}},
		{"update t set a = 1 where id = 2", []classes.Class{W}},
		{"update t set a = 1", []classes.Class{I}},
		{"update or ignore t set a = 1 where 1", []classes.Class{I}},
		{"update t set a = u.a from u where t.id = u.id", []classes.Class{W}},
		{"delete from t where id = 1", []classes.Class{D}},
		{"delete from t", []classes.Class{I}},
		{"delete from t returning *", []classes.Class{I}},
		{"delete from t where true", []classes.Class{I}},
		{"delete from t where 1 = 1", []classes.Class{I}},
		{"delete from t where (1)", []classes.Class{I}},
		{"delete from t where id = 5 or 1", []classes.Class{I}},
		{"delete from t where id = 5 and 1", []classes.Class{D}},
		{"delete from t where ?", []classes.Class{I}},
		{"delete from t where :flag", []classes.Class{I}},
		{"delete from t where exists (select 1)", []classes.Class{I}},
		{"delete from t where id in (select id from u)", []classes.Class{D}},
		{"delete from t where id is not null", []classes.Class{I}},
		{"delete from t where id not null", []classes.Class{I}},
		{"delete from t where id notnull", []classes.Class{I}},
		{"delete from t where id is null", []classes.Class{D}},
		{"delete from t where id = id", []classes.Class{I}},
		{"delete from t where id is id", []classes.Class{I}},
		{"delete from t where t.id >= t.id", []classes.Class{I}},
		{"delete from t where random() < 2", []classes.Class{I}},
		{"delete from t where id between 1 and 10", []classes.Class{D}},
		{"delete from t where case when id > 1 then 1 else 0 end", []classes.Class{D}},
		{"delete from t limit 10", []classes.Class{I}},
		// A bare double-quoted name is a string when no column has that name.
		{`delete from t where "1"`, []classes.Class{I}},
		{`delete from t where "t"."id" = 5`, []classes.Class{D}},
		{`delete from "t" where id = 5`, []classes.Class{D}},
		// The schema table and raw pages.
		{"update sqlite_master set sql = 'x' where name = 't'", []classes.Class{I}},
		{"insert into sqlite_dbpage values (1, zeroblob(4096))", []classes.Class{I}},
		{"delete from main.sqlite_schema where name = 't'", []classes.Class{I}},
		// Schema.
		{"create table t (id integer primary key, name text not null)", []classes.Class{W}},
		{"create table if not exists t as select * from u", []classes.Class{W}},
		{"create index i on t (a)", []classes.Class{W}},
		{"create unique index if not exists i on t (a) where a is not null", []classes.Class{W}},
		{"create view v as select * from t", []classes.Class{W}},
		{"create view v as select load_extension('x')", []classes.Class{W, U}},
		{"create virtual table f using fts5(body)", []classes.Class{W}},
		{"create virtual table f using fsdir('/')", []classes.Class{U}},
		{"alter table t add column c int", []classes.Class{W}},
		{"alter table t rename to u", []classes.Class{W}},
		{"alter table t rename column a to b", []classes.Class{W}},
		{"alter table t drop column c", []classes.Class{W, I}},
		{"drop table t", []classes.Class{I}},
		{"drop table if exists t", []classes.Class{I}},
		{"drop view v", []classes.Class{I}},
		{"drop index i", []classes.Class{I}},
		{"drop trigger g", []classes.Class{I}},
		{"analyze", []classes.Class{W}},
		{"reindex t", []classes.Class{W}},
		{"vacuum", []classes.Class{W}},
		{"vacuum into '/tmp/copy.db'", []classes.Class{U}},
		{"attach database 'other.db' as o", []classes.Class{U}},
		{"detach o", []classes.Class{R}},
		// Triggers run their body later.
		{"create trigger g after insert on t begin delete from u; end", []classes.Class{W, I}},
		{"create trigger g after insert on t begin delete from u where id = new.id; end", []classes.Class{W, D}},
		{"create trigger g before delete on t begin select raise(abort, 'no'); end", []classes.Class{W, R}},
		{"create trigger g after insert on t when load_extension('x') begin select 1; end", []classes.Class{W, R, U}},
		// Pragmas.
		{"pragma table_info(users)", []classes.Class{R}},
		{"pragma main.index_list('users')", []classes.Class{R}},
		{"pragma foreign_key_check", []classes.Class{R}},
		{"pragma integrity_check(10)", []classes.Class{R}},
		{"pragma user_version", []classes.Class{R}},
		{"pragma user_version = 3", []classes.Class{W}},
		{"pragma journal_mode = wal", []classes.Class{W}},
		{"pragma defer_foreign_keys = on", []classes.Class{W}},
		{"pragma foreign_keys = off", []classes.Class{A}},
		{"pragma foreign_keys(0)", []classes.Class{A}},
		{"pragma ignore_check_constraints = 1", []classes.Class{A}},
		{"pragma writable_schema = on", []classes.Class{I}},
		{"pragma schema_version = 7", []classes.Class{I}},
		{"pragma writable_schema", []classes.Class{R}},
		{"pragma optimize", []classes.Class{W}},
		{"pragma wal_checkpoint(truncate)", []classes.Class{W}},
		{"pragma table_info = t", []classes.Class{U}},
		{"pragma frobnicate", []classes.Class{U}},
		// Functions that reach outside the database, anywhere.
		{"select load_extension('evil')", []classes.Class{R, U}},
		{"select (select load_extension('evil'))", []classes.Class{R, U}},
		{"insert into t values (writefile('/tmp/x', 'y'))", []classes.Class{W, U}},
		{"select * from fsdir('/etc')", []classes.Class{R, U}},
		{"select fts3_tokenizer('simple', x'00')", []classes.Class{R, U}},
		{"update t set a = readfile('/etc/passwd') where id = 1", []classes.Class{W, U}},
		// Statement boundaries, comments and quoting, as SQLite reads them.
		{"select 1; drop table t", []classes.Class{R, I}},
		{"select 1 -- ; drop table t", []classes.Class{R}},
		{"select 1 /* ; drop table t */", []classes.Class{R}},
		// SQLite does not nest comments: the first */ ends this one.
		{"/* /* */ drop table t; -- */ select 1", []classes.Class{I}},
		{"select 1 /* unterminated comments run to the end", []classes.Class{R}},
		{"select '; drop table t'", []classes.Class{R}},
		// No backslash escapes: the string ends at the second quote.
		{`select 'a\'; drop table t; -- '`, []classes.Class{R, I}},
		{`select "a"; drop table "t"`, []classes.Class{R, I}},
		{"select [a;b] from t; drop table t", []classes.Class{R, I}},
		{"select `a` from t", []classes.Class{R}},
		{"select $a::b(x) from t", []classes.Class{R}},
		{"select x'00ff'", []classes.Class{R}},
		// SQLite stops at a NUL, so the WHERE after one never runs.
		{"delete from t\x00 where id = 1", []classes.Class{I}},
		{"select 1\x00; drop table t", []classes.Class{R}},
		// Non-ASCII spaces are identifier characters to SQLite.
		{"delete from t where id = 1", []classes.Class{U}},
		{"select 1 as a ; drop table t", []classes.Class{R, I}},
		// Unparsable input.
		{"select 'unterminated", []classes.Class{U}},
		{"delete from t where", []classes.Class{U}},
		{"frobnicate everything", []classes.Class{U}},
		{"select 1; frobnicate", []classes.Class{U}},
		{"select $1", []classes.Class{R}}, // SQLite accepts $1 as a parameter
		{"drop table t cascade", []classes.Class{U}},
		{"truncate t", []classes.Class{U}},
	}
	for _, c := range cases {
		if got := ClassifySQLite(c.sql); !reflect.DeepEqual(got, c.want) {
			t.Errorf("ClassifySQLite(%q) = %v, want %v", c.sql, got, c.want)
		}
	}
}

func TestClassifySQLiteTooLong(t *testing.T) {
	sql := "select " + strings.Repeat("(", maxSQL) + "1"
	if got := ClassifySQLite(sql); !reflect.DeepEqual(got, []classes.Class{classes.Unknown}) {
		t.Fatalf("got %v, want [unknown]", got)
	}
	deep := "select " + strings.Repeat("(", 5000) + "1" + strings.Repeat(")", 5000)
	if got := ClassifySQLite(deep); !reflect.DeepEqual(got, []classes.Class{classes.Unknown}) {
		t.Fatalf("deep nesting: got %v, want [unknown]", got)
	}
}

func FuzzClassifySQLite(f *testing.F) {
	for _, s := range []string{"select 1", "delete from t where id = 1", "create trigger g after insert on t begin delete from u; end",
		"pragma foreign_keys = off", "/* /* */ drop table t; -- */", "select $a::b(c)", "select 1\x00; drop table t"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		got := ClassifySQLite(s)
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
