package decode

import (
	"reflect"
	"strings"
	"testing"

	"github.com/rakeshnitb23/opfence/internal/classes"
)

func TestClassifyMySQL(t *testing.T) {
	R, W, D, I, A, U, C := classes.Read, classes.Write, classes.Delete, classes.Irreversible, classes.Access, classes.Unknown, classes.Credential
	cases := []struct {
		sql  string
		want []classes.Class
	}{
		{"", []classes.Class{R}},
		{"/* only a comment */", []classes.Class{R}},
		{"select * from users where id = ?", []classes.Class{R}},
		{"SELECT `id`, `name` FROM `users` WHERE `email` = 'a@b.c' LIMIT 10", []classes.Class{R}},
		{"select 1; select 2", []classes.Class{R}},
		{"select * from t1 union select * from t2", []classes.Class{R}},
		{"with x as (select 1) select * from x", []classes.Class{R}},
		{"select * from t for update", []classes.Class{R}},
		{"select sleep(1), now(), count(*) from t", []classes.Class{R}},
		{"select id into @x from t limit 1", []classes.Class{R}},
		{"show tables", []classes.Class{R}},
		{"show create table t", []classes.Class{R}},
		{"describe t", []classes.Class{R}},
		{"explain select * from t", []classes.Class{R}},
		{"explain delete from t", []classes.Class{R}},
		{"explain analyze delete from t", []classes.Class{I}},
		{"explain analyze select * from t", []classes.Class{R}},
		{"use shop", []classes.Class{R}},
		{"begin; commit", []classes.Class{R}},
		{"start transaction; rollback", []classes.Class{R}},
		{"savepoint a; release savepoint a", []classes.Class{R}},
		{"set autocommit = 0", []classes.Class{R}},
		{"set @x = 1", []classes.Class{R}},
		{"set session transaction isolation level read committed", []classes.Class{R}},
		{"insert into t (a) values (1)", []classes.Class{W}},
		{"insert into t values (1) on duplicate key update a = values(a)", []classes.Class{W}},
		{"insert ignore into t values (1)", []classes.Class{W}},
		{"replace into t values (1)", []classes.Class{W, D}},
		{"insert into t select * from u", []classes.Class{W}},
		{"update t set a = 1 where id = 2", []classes.Class{W}},
		{"update t set a = 1", []classes.Class{I}},
		{"update t set a = 1 limit 10", []classes.Class{I}},
		{"update t set a = 1 where 1 = 1", []classes.Class{I}},
		{"update t set a = 1 where true", []classes.Class{I}},
		{"update t join u on t.id = u.id set t.a = u.a where u.b = 1", []classes.Class{W}},
		{"update t join u on t.id = u.id set t.a = u.a", []classes.Class{I}},
		{"delete from t where id = 1", []classes.Class{D}},
		{"delete from t", []classes.Class{I}},
		{"delete from t where id = 5 or true", []classes.Class{I}},
		{"delete from t where id = 5 or 1", []classes.Class{I}},
		{"delete from t where id = 5 xor true", []classes.Class{I}},
		{"delete from t where id = 5 and true", []classes.Class{D}},
		{"delete from t where ?", []classes.Class{I}},
		{"delete from t where :v1", []classes.Class{I}},
		{"delete from t where @x", []classes.Class{I}},
		{"delete from t where exists (select 1)", []classes.Class{I}},
		{"delete from t where id in (select id from u)", []classes.Class{D}},
		{"delete from t where id is not null", []classes.Class{I}},
		{"delete from t where id is null", []classes.Class{D}},
		{"delete from t where id = id", []classes.Class{I}},
		{"delete from t where `t`.`id` >= `t`.`id`", []classes.Class{I}},
		{"delete from t where rand() < 2", []classes.Class{I}},
		{`delete from t where "1"`, []classes.Class{I}}, // a string, not a column
		{"delete t from t join u on t.id = u.id where u.gone = 1", []classes.Class{D}},
		{"delete from t order by id limit 1000", []classes.Class{I}},
		// Schema.
		{"create table t (id bigint unsigned not null auto_increment primary key, name varchar(255))", []classes.Class{W}},
		{"create table if not exists t like u", []classes.Class{W}},
		{"create table t as select * from u", []classes.Class{W}},
		{"create index i on t (a)", []classes.Class{W}},
		{"create or replace view v as select * from t", []classes.Class{W}},
		{"create database shop", []classes.Class{W}},
		{"alter table t add column c int", []classes.Class{W}},
		{"alter table t modify column c bigint", []classes.Class{W}},
		{"alter table t drop index i", []classes.Class{W}},
		{"alter table t drop primary key", []classes.Class{W}},
		{"alter table t drop column c", []classes.Class{W, I}},
		{"alter table t add column d int, drop column c", []classes.Class{W, I}},
		{"alter table t engine = innodb", []classes.Class{W}},
		{"alter table t engine = blackhole", []classes.Class{W, I}},
		{"alter table t discard tablespace", []classes.Class{W, I}},
		{"alter table t import tablespace", []classes.Class{W}},
		{"alter table t drop partition p1", []classes.Class{W, I}},
		{"alter table t truncate partition p1", []classes.Class{W, I}},
		{"alter table t add partition (partition p9 values less than (900))", []classes.Class{W}},
		{"rename table t to u", []classes.Class{W}},
		{"drop table t", []classes.Class{I}},
		{"drop table if exists t, u", []classes.Class{I}},
		{"drop view v", []classes.Class{I}},
		{"drop database shop", []classes.Class{I}},
		{"truncate table t", []classes.Class{I}},
		{"truncate t", []classes.Class{I}},
		{"analyze table t", []classes.Class{W}},
		{"lock tables t write; unlock tables", []classes.Class{W, R}},
		{"purge binary logs to 'mysql-bin.000010'", []classes.Class{I}},
		// What the server does outside the tables.
		{"select * from t into outfile '/tmp/t.csv'", []classes.Class{U}},
		{"select * from t into dumpfile '/tmp/t'", []classes.Class{U}},
		{"select load_file('/etc/passwd')", []classes.Class{R, U}},
		{"select get_lock('x', 10)", []classes.Class{R, U}},
		{"select release_all_locks()", []classes.Class{R, U}},
		{"select is_free_lock('x')", []classes.Class{R}},
		{"update t set a = sys_exec('id') where id = 1", []classes.Class{W, U}},
		{"load data infile '/tmp/t.csv' into table t", []classes.Class{U}},
		{"call cleanup()", []classes.Class{U}},
		{"do sleep(1)", []classes.Class{U}},
		{"kill 5", []classes.Class{U}},
		{"flush privileges", []classes.Class{U}},
		{"optimize table t", []classes.Class{U}},
		{"set global read_only = 1", []classes.Class{U}},
		{"set persist max_connections = 10", []classes.Class{U}},
		{"prepare s from 'delete from t'", []classes.Class{I}},
		{"prepare s from 'select 1'", []classes.Class{R}},
		{"prepare s from @q", []classes.Class{U}},
		{"execute s", []classes.Class{U}},
		{"deallocate prepare s", []classes.Class{R}},
		// Settings that change how later SQL is read, or switch off checks.
		{"set sql_mode = 'NO_BACKSLASH_ESCAPES'", []classes.Class{U}},
		{"set @@session.sql_mode = ''", []classes.Class{U}},
		{"set names gbk", []classes.Class{U}},
		{"set character set gbk", []classes.Class{U}},
		{"set character_set_client = gbk", []classes.Class{U}},
		{"set foreign_key_checks = 0", []classes.Class{R, A}},
		{"set sql_log_bin = 0", []classes.Class{R, A}},
		// Privilege tables.
		{"select user, authentication_string from mysql.user", []classes.Class{R, C}},
		{"update mysql.user set authentication_string = '' where user = 'root'", []classes.Class{W, C, A}},
		{"insert into mysql.db values ('%', 'shop', 'evil')", []classes.Class{W, A}},
		{"select * from mysql.db", []classes.Class{R}},
		// Comments, quoting and statement boundaries, as MySQL reads them.
		{"select 1 -- ; drop table t", []classes.Class{R}},
		{"select 1 # ; drop table t", []classes.Class{R}},
		{"select 1 --x", []classes.Class{R}}, // 1 - -x: "--" needs a space to start a comment
		{"select 1 /* ; drop table t */", []classes.Class{R}},
		{"select '; drop table t'", []classes.Class{R}},
		{`select 'a\'; drop table t; -- '`, []classes.Class{R}}, // backslash escapes the quote
		{`select "a\"; drop table t; -- "`, []classes.Class{R}},
		{"select `; drop table t` from t", []classes.Class{R}},
		{"select 1; drop table t", []classes.Class{R, I}},
		{"select 1 /*! ; drop table t */", []classes.Class{R, I}},
		{"delete from t /*! where id = 1 */", []classes.Class{D}},
		// A versioned comment runs only on servers of at least its version.
		{"delete from t /*!50700 where id = 1 */", []classes.Class{I, D}},
		{"delete from t where id = 1 /*!99999 or true */", []classes.Class{D, I}},
		{"delete from t where id = 5 /*!80000 or true */ /*!90000 and id = 6 */", []classes.Class{D, I}},
		{"select 1 /*!80000 ; drop table t */", []classes.Class{R, I}},
		{"select '/*!80000'", []classes.Class{R}},
		// Unparsable input, and what Vitess does not parse.
		{"select 'unterminated", []classes.Class{U}},
		{"delete from t where", []classes.Class{U}},
		{"frobnicate everything", []classes.Class{U}},
		{"select 1; frobnicate", []classes.Class{U}},
		{"grant all on *.* to 'u'@'%'", []classes.Class{U}},
		{"create user u identified by 'p'", []classes.Class{U}},
		{"set role admin", []classes.Class{U}},
		{"select $$x$$ from t", []classes.Class{R}}, // an identifier: MySQL allows $ in names
		{"delete from t\x00 where id = 1", []classes.Class{U}},
	}
	for _, c := range cases {
		if got := ClassifyMySQL(c.sql); !reflect.DeepEqual(got, c.want) {
			t.Errorf("ClassifyMySQL(%q) = %v, want %v", c.sql, got, c.want)
		}
	}
}

func TestClassifyMySQLManyVersions(t *testing.T) {
	var b strings.Builder
	b.WriteString("select 1")
	for i := range maxMySQLVersions {
		b.WriteString(" /*!5" + string(rune('0'+i/10)) + string(rune('0'+i%10)) + "00 + 1 */")
	}
	if got := ClassifyMySQL(b.String()); !reflect.DeepEqual(got, []classes.Class{classes.Unknown}) {
		t.Fatalf("got %v, want [unknown]", got)
	}
}

func TestClassifyMySQLTooLong(t *testing.T) {
	sql := "select " + strings.Repeat("(", maxSQL) + "1"
	if got := ClassifyMySQL(sql); !reflect.DeepEqual(got, []classes.Class{classes.Unknown}) {
		t.Fatalf("got %v, want [unknown]", got)
	}
}

func FuzzClassifyMySQL(f *testing.F) {
	for _, s := range []string{"select 1", "delete from t where id = 1", "alter table t drop column c",
		"select 1 /*!80000 ; drop table t */", "prepare s from 'delete from t'", "set names gbk", "select 'a\\'; -- '"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		got := ClassifyMySQL(s)
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
