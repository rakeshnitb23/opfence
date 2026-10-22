package decode

import (
	"slices"
	"strings"
	"testing"
)

func TestSummarizeSQL(t *testing.T) {
	cases := []struct {
		dialect, sql string
		want         []string
	}{
		// Postgres
		{"postgres", "select id, email from auth.users limit 10", []string{"SELECT from auth.users"}},
		{"postgres", "select 1", []string{"SELECT"}},
		{"postgres", "delete from orders", []string{"DELETE from orders (every row)"}},
		{"postgres", "delete from orders where id = 5", []string{"DELETE from orders"}},
		{"postgres", "DELETE FROM orders WHERE id IS NOT NULL", []string{"DELETE from orders (every row)"}},
		{"postgres", "delete from users where exists (select 1 from admins a where a.id = 7)", []string{"DELETE from users (every row)"}},
		{"postgres", "update accounts set plan = 'free'", []string{"UPDATE accounts (every row)"}},
		{"postgres", "update accounts set plan = 'free' where id = $1", []string{"UPDATE accounts"}},
		{"postgres", "insert into public.events (kind) values ('x')", []string{"INSERT into public.events"}},
		{"postgres", "truncate a, b, c, d, e", []string{"TRUNCATE a, b, c and 2 more"}},
		{"postgres", "drop table if exists users, sessions cascade", []string{"DROP TABLE users, sessions"}},
		{"postgres", "drop schema app", []string{"DROP SCHEMA app"}},
		{"postgres", "select * from a join b on a.id = b.id, (select * from c) s", []string{"SELECT from a, b, c"}},
		{"postgres", "select * from a union select * from b", []string{"SELECT from a, b"}},
		{"postgres", "select 1; drop table users", []string{"SELECT", "DROP TABLE users"}},
		// What runs under a SELECT is named, however the statement starts.
		{"postgres", "with d as (delete from users returning *) select count(*) from d", []string{"SELECT from d, which also runs DELETE from users (every row)"}},
		{"postgres", "select pg_terminate_backend(pid) from pg_stat_activity", []string{"SELECT from pg_stat_activity, which also calls pg_terminate_backend"}},
		{"postgres", "select * from vault.decrypted_secrets", []string{"SELECT from vault.decrypted_secrets"}},
		{"postgres", "create function f() returns void language sql as $$ delete from users $$; select f()", []string{"CREATE FUNCTION", "SELECT, which also calls f"}},
		// A comment is never shown; the statement is.
		{"postgres", "/* read only, safe */ delete from orders", []string{"DELETE from orders (every row)"}},
		// Names that are not plain are quoted, so they read as names.
		{"postgres", `delete from "only reads this"`, []string{`DELETE from "only reads this" (every row)`}},
		{"postgres", `delete from "a""b"`, []string{`DELETE from "a""b" (every row)`}},
		{"postgres", "explain delete from orders", []string{"EXPLAIN DELETE from orders (every row)"}},
		{"postgres", "explain analyze delete from orders", []string{"EXPLAIN ANALYZE, which runs DELETE from orders (every row)"}},
		{"postgres", "create table t (id int)", []string{"CREATE TABLE t"}},
		{"postgres", "alter table t drop column x", []string{"ALTER TABLE t"}},
		{"postgres", "grant select on accounts to anon", []string{"GRANT on accounts"}},
		{"postgres", "create extension pgcrypto", []string{"CREATE EXTENSION"}},
		{"postgres", "begin", []string{"BEGIN"}},
		{"postgres", "delete from", nil},

		// MySQL
		{"mysql", "SELECT * FROM shop.orders o JOIN customers c ON o.c = c.id", []string{"SELECT from shop.orders, customers"}},
		{"mysql", "DELETE FROM orders", []string{"DELETE from orders (every row)"}},
		{"mysql", "DELETE FROM orders WHERE id = 1", []string{"DELETE from orders"}},
		{"mysql", "UPDATE users SET admin = 1 WHERE name LIKE '%'", []string{"UPDATE users (every row)"}},
		{"mysql", "REPLACE INTO t VALUES (1)", []string{"REPLACE into t"}},
		{"mysql", "DROP TABLE a, b", []string{"DROP TABLE a, b"}},
		{"mysql", "DROP DATABASE shop", []string{"DROP DATABASE shop"}},
		{"mysql", "TRUNCATE TABLE logs", []string{"TRUNCATE logs"}},
		{"mysql", "DELETE t1 FROM t1 JOIN t2 ON t1.id = t2.id WHERE t2.x = 1", []string{"DELETE from t1"}},
		// Each reading of a versioned comment is listed.
		{"mysql", "SELECT 1 /*!80000 ; DROP TABLE users */", []string{"SELECT", "DROP TABLE users"}},
		{"mysql", "SELECT 1 FROM", nil},

		// SQLite
		{"sqlite", "SELECT * FROM main.notes", []string{"SELECT from main.notes"}},
		{"sqlite", "DELETE FROM notes", []string{"DELETE from notes (every row)"}},
		{"sqlite", "DELETE FROM notes WHERE id = 3", []string{"DELETE from notes"}},
		{"sqlite", "DELETE FROM notes WHERE body GLOB '*'", []string{"DELETE from notes (every row)"}},
		{"sqlite", "UPDATE notes SET body = ''", []string{"UPDATE notes (every row)"}},
		{"sqlite", "INSERT OR REPLACE INTO notes VALUES (1, 'x')", []string{"REPLACE into notes"}},
		{"sqlite", "DROP TABLE IF EXISTS notes", []string{"DROP TABLE notes"}},
		{"sqlite", "SELECT * FROM a UNION SELECT * FROM b", []string{"SELECT from a, b"}},
		{"sqlite", "EXPLAIN DELETE FROM notes", []string{"EXPLAIN DELETE from notes (every row)"}},
		// SQLite stops at a NUL, and so does the summary.
		{"sqlite", "DELETE FROM notes\x00 WHERE id = 1", []string{"DELETE from notes (every row)"}},
		{"sqlite", "VACUUM", []string{"VACUUM"}},
		{"sqlite", "SELECT FROM", nil},

		{"oracle", "select 1", nil},
	}
	for _, c := range cases {
		got := SummarizeSQL(c.dialect, c.sql)
		if !slices.Equal(got, c.want) {
			t.Errorf("%s %q:\n got  %q\n want %q", c.dialect, c.sql, got, c.want)
		}
	}
}

// A summary says "every row" exactly when the classifier makes an UPDATE or
// DELETE irreversible for its WHERE, in every dialect.
func TestSummaryAgreesWithClass(t *testing.T) {
	wheres := []string{"", "WHERE id = 1", "WHERE id = id", "WHERE id IS NOT NULL", "WHERE 1 = 1", "WHERE id = 1 OR TRUE",
		"WHERE id IN (1, 2)", "WHERE id IN (id)", "WHERE name LIKE '%'", "WHERE name LIKE 'a%'", "WHERE EXISTS (SELECT 1 FROM b WHERE b.x = 1)",
		"WHERE EXISTS (SELECT 1 FROM b WHERE b.x = t.id)", "WHERE NOT id IS NULL", "WHERE (id IS NOT NULL)"}
	for _, d := range []string{"postgres", "mysql", "sqlite"} {
		for _, w := range wheres {
			for _, verb := range []string{"DELETE FROM t ", "UPDATE t SET x = 1 "} {
				sql := verb + w
				var cls []string
				for _, c := range ClassifySQLDialect(d, sql) {
					cls = append(cls, string(c))
				}
				sum := SummarizeSQL(d, sql)
				if len(sum) != 1 {
					t.Errorf("%s %q: summary %q", d, sql, sum)
					continue
				}
				every := strings.Contains(sum[0], "(every row)")
				irreversible := slices.Contains(cls, "irreversible")
				if every != irreversible {
					t.Errorf("%s %q: summary %q but classes %v", d, sql, sum[0], cls)
				}
			}
		}
	}
}

func TestSQLVerb(t *testing.T) {
	for in, want := range map[string]string{
		"CreateExtensionStmt": "CREATE EXTENSION", "ALTER_ROLE_SET": "ALTER ROLE SET", "DROP DATABASE": "DROP DATABASE",
		"VacuumStatement": "VACUUM", "": "SQL statement", "DDL": "DDL",
	} {
		if got := sqlVerb(in); got != want {
			t.Errorf("sqlVerb(%q) = %q, want %q", in, got, want)
		}
	}
}

func FuzzSummarizeSQL(f *testing.F) {
	for _, s := range []string{"select 1", "delete from t", "with d as (delete from t returning *) select 1", `drop table "x"`, "explain analyze update t set a = 1"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, sql string) {
		for _, d := range []string{"postgres", "mysql", "sqlite"} {
			for _, s := range SummarizeSQL(d, sql) {
				if s == "" {
					t.Fatalf("%s %q: empty summary", d, sql)
				}
			}
		}
	})
}
