package decode

import (
	"slices"
	"strings"
	"testing"

	"github.com/rakeshnitb23/opfence/internal/classes"
)

func TestClassifyGoogleSQL(t *testing.T) {
	cases := []struct {
		sql  string
		want []classes.Class
	}{
		// Queries.
		{"SELECT * FROM `acme-prod.sales.orders` WHERE id = 1", []classes.Class{classes.Read}},
		{"SELECT name FROM acme-prod.sales.orders LIMIT 10", []classes.Class{classes.Read}},
		{"WITH a AS (SELECT 1 AS x) SELECT * FROM a", []classes.Class{classes.Read}},
		{"(SELECT 1) UNION ALL (SELECT 2)", []classes.Class{classes.Read}},
		{"SELECT a, ROW_NUMBER() OVER (PARTITION BY b) AS rn FROM t QUALIFY rn = 1", []classes.Class{classes.Read}},
		{"SELECT * FROM `proj.ds.events_*` WHERE _TABLE_SUFFIX = '20260101'", []classes.Class{classes.Read}},
		{"SELECT * FROM t FOR SYSTEM_TIME AS OF TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 1 HOUR)", []classes.Class{classes.Read}},
		{"FROM t |> WHERE x > 1 |> SELECT x", []classes.Class{classes.Read}},
		{"#standardSQL\nSELECT 1", []classes.Class{classes.Read}},
		{"SELECT [x] FROM [proj:ds.t]", []classes.Class{classes.Read}}, // legacy SQL reads
		{"SELECT SAFE.SUBSTR(s, 1, 2), NET.HOST(u), ML.PREDICT(MODEL ds.m, (SELECT 1)) FROM t", []classes.Class{classes.Read}},
		{"SELECT * FROM ds.my_tvf(1)", []classes.Class{classes.Read}},
		{"SELECT '; DELETE FROM t WHERE true; '", []classes.Class{classes.Read}},
		{"SELECT \"; DROP TABLE t\" -- ; DROP TABLE u", []classes.Class{classes.Read}},
		{"SELECT 1 /* ; DROP TABLE t; */", []classes.Class{classes.Read}},
		{"SELECT '''a ' ; DROP TABLE t; ' b'''", []classes.Class{classes.Read}},
		{`SELECT 'it\'s; DROP TABLE t'`, []classes.Class{classes.Read}},
		{`SELECT r'\'; DROP TABLE t; '`, []classes.Class{classes.Read}},
		{"SELECT `a;b` FROM t", []classes.Class{classes.Read}},
		{"SELECT @x, @@dataset_id, ? FROM t", []classes.Class{classes.Read}},
		// Calls that change what a query is.
		{"SELECT * FROM EXTERNAL_QUERY('conn', 'DELETE FROM users')", []classes.Class{classes.Read, classes.Unknown}},
		{"SELECT ds.remote_fn(x) FROM t", []classes.Class{classes.Read, classes.Unknown}},
		{"SELECT `proj.ds.fn`(x) FROM t", []classes.Class{classes.Read, classes.Unknown}},
		{"SELECT ML.GENERATE_TEXT(MODEL ds.gemini, (SELECT 'hi' AS prompt))", []classes.Class{classes.Read, classes.Money}},
		{"SELECT AI.GENERATE('hello', connection_id => 'us.c')", []classes.Class{classes.Read, classes.Money}},
		{"SELECT AEAD.DECRYPT_STRING(k, c, '') FROM t", []classes.Class{classes.Read, classes.Credential}},
		{"SELECT DETERMINISTIC_DECRYPT_STRING(k, c, '') FROM t", []classes.Class{classes.Read, classes.Credential}},
		// Writes and deletes.
		{"INSERT INTO ds.t (id) VALUES (1)", []classes.Class{classes.Write}},
		{"INSERT ds.t (id) SELECT id FROM ds.u", []classes.Class{classes.Write}},
		{"INSERT OR UPDATE INTO t (id) VALUES (1)", []classes.Class{classes.Write}},
		{"UPDATE ds.t SET x = 1 WHERE id = 5", []classes.Class{classes.Write}},
		{"UPDATE ds.t SET x = 1 WHERE true", []classes.Class{classes.Irreversible}},
		{"UPDATE ds.t SET x = 1", []classes.Class{classes.Irreversible}},
		{"DELETE FROM `acme-prod.sales.orders` WHERE created < '2020-01-01'", []classes.Class{classes.Delete}},
		{"DELETE sales.orders WHERE id = @id", []classes.Class{classes.Delete}},
		{"DELETE FROM t WHERE TRUE", []classes.Class{classes.Irreversible}},
		{"DELETE FROM t WHERE 1 = 1", []classes.Class{classes.Irreversible}},
		{"DELETE FROM t WHERE @everything", []classes.Class{classes.Irreversible}},
		{"DELETE FROM t WHERE id = 5 OR TRUE", []classes.Class{classes.Irreversible}},
		{"DELETE FROM t WHERE id = 5 AND TRUE", []classes.Class{classes.Delete}},
		{"DELETE FROM t WHERE id IS NOT NULL", []classes.Class{classes.Irreversible}},
		{"DELETE FROM t WHERE NOT id IS NULL", []classes.Class{classes.Irreversible}},
		{"DELETE FROM t WHERE id IS DISTINCT FROM NULL", []classes.Class{classes.Irreversible}},
		{"DELETE FROM t WHERE id = id", []classes.Class{classes.Irreversible}},
		{"DELETE FROM t WHERE LOWER(name) = lower(name)", []classes.Class{classes.Irreversible}},
		{"DELETE FROM t WHERE id IN (id, 1)", []classes.Class{classes.Irreversible}},
		{"DELETE FROM t WHERE id IN (1, 2)", []classes.Class{classes.Delete}},
		{"DELETE FROM t WHERE id NOT IN (1, 2)", []classes.Class{classes.Delete}},
		{"DELETE FROM t WHERE name LIKE '%'", []classes.Class{classes.Irreversible}},
		{"DELETE FROM t WHERE name LIKE 'a%'", []classes.Class{classes.Delete}},
		{"DELETE FROM t WHERE name LIKE ANY ('a%', '%%')", []classes.Class{classes.Irreversible}},
		{"DELETE FROM t WHERE REGEXP_CONTAINS(name, r'.*')", []classes.Class{classes.Irreversible}},
		{"DELETE FROM t WHERE REGEXP_CONTAINS(name, r'^a')", []classes.Class{classes.Delete}},
		{"DELETE FROM t WHERE EXISTS (SELECT 1 FROM u WHERE u.id = 1)", []classes.Class{classes.Irreversible}},
		{"DELETE FROM t WHERE id IN (SELECT id FROM u)", []classes.Class{classes.Delete}},
		{"DELETE FROM t WHERE ((id = 5))", []classes.Class{classes.Delete}},
		{"DELETE FROM t WHERE (id IS NOT NULL)", []classes.Class{classes.Irreversible}},
		{"DELETE FROM t WHERE created BETWEEN '2020-01-01' AND '2021-01-01'", []classes.Class{classes.Delete}},
		{"DELETE FROM t WHERE CURRENT_DATE() > DATE '2000-01-01'", []classes.Class{classes.Irreversible}},
		{"DELETE FROM t WHERE DATE(created) < '2020-01-01'", []classes.Class{classes.Delete}},
		{"DELETE FROM t WHERE CASE WHEN TRUE AND TRUE THEN TRUE END", []classes.Class{classes.Irreversible}},
		{"DELETE FROM t WHERE id = 1 THEN RETURN id", []classes.Class{classes.Delete}},
		{"DELETE FROM t", []classes.Class{classes.Irreversible}},
		{"MERGE ds.t T USING ds.s S ON T.id = S.id WHEN MATCHED THEN UPDATE SET x = S.x WHEN NOT MATCHED THEN INSERT ROW", []classes.Class{classes.Write}},
		{"MERGE ds.t T USING ds.s S ON T.id = S.id WHEN MATCHED THEN DELETE", []classes.Class{classes.Irreversible}},
		{"MERGE ds.t T USING ds.s S ON FALSE WHEN NOT MATCHED BY SOURCE THEN UPDATE SET x = 0", []classes.Class{classes.Irreversible}},
		{"TRUNCATE TABLE ds.t", []classes.Class{classes.Irreversible}},
		// DDL.
		{"DROP TABLE ds.t", []classes.Class{classes.Irreversible}},
		{"DROP TABLE IF EXISTS ds.t", []classes.Class{classes.Irreversible}},
		{"DROP SCHEMA sales CASCADE", []classes.Class{classes.Irreversible}},
		{"DROP ROW ACCESS POLICY p ON ds.t", []classes.Class{classes.Access}},
		{"DROP ALL ROW ACCESS POLICIES ON ds.t", []classes.Class{classes.Access}},
		{"UNDROP SCHEMA sales", []classes.Class{classes.Write}},
		{"CREATE TABLE ds.t (id INT64)", []classes.Class{classes.Write}},
		{"CREATE TABLE IF NOT EXISTS ds.t AS SELECT * FROM ds.u", []classes.Class{classes.Write}},
		{"CREATE OR REPLACE TABLE ds.t AS SELECT 1 AS x", []classes.Class{classes.Irreversible}},
		{"CREATE OR REPLACE TEMP TABLE t AS SELECT 1 AS x", []classes.Class{classes.Write}},
		{"CREATE OR REPLACE EXTERNAL TABLE ds.t OPTIONS (uris = ['gs://b/*'])", []classes.Class{classes.Write}},
		{"CREATE OR REPLACE VIEW ds.v AS SELECT ds.fn(x) FROM t", []classes.Class{classes.Write}},
		{"CREATE OR REPLACE FUNCTION ds.f(x INT64) AS (x + 1)", []classes.Class{classes.Write}},
		{"CREATE TEMP FUNCTION f(x INT64) AS (x * 2); SELECT f(3)", []classes.Class{classes.Write, classes.Read}},
		{"CREATE ROW ACCESS POLICY p ON ds.t GRANT TO ('user:a@b.com') FILTER USING (region = 'us')", []classes.Class{classes.Access}},
		{"CREATE CAPACITY `proj.region-us.c1` OPTIONS (slot_count = 100, plan = 'ANNUAL')", []classes.Class{classes.Money}},
		{"CREATE RESERVATION `proj.region-us.r1` OPTIONS (slot_capacity = 100)", []classes.Class{classes.Money}},
		{"CREATE ROLE analyst", []classes.Class{classes.Access}},
		{"CREATE MATERIALIZED VIEW ds.mv AS SELECT ML.GENERATE_TEXT(MODEL ds.m, (SELECT 'x' AS prompt))", []classes.Class{classes.Write, classes.Money}},
		{"ALTER TABLE ds.t ADD COLUMN x STRING", []classes.Class{classes.Write}},
		{"ALTER TABLE ds.t DROP COLUMN x", []classes.Class{classes.Irreversible}},
		{"ALTER TABLE ds.t DROP COLUMN IF EXISTS x", []classes.Class{classes.Irreversible}},
		{"ALTER TABLE ds.t ALTER COLUMN x DROP NOT NULL", []classes.Class{classes.Write}},
		{"ALTER TABLE ds.t DROP PRIMARY KEY", []classes.Class{classes.Write}},
		{"ALTER TABLE ds.t SET OPTIONS (description = 'x')", []classes.Class{classes.Write}},
		{"ALTER TABLE ds.t SET OPTIONS (expiration_timestamp = TIMESTAMP '2026-11-01')", []classes.Class{classes.Irreversible}},
		{"ALTER SCHEMA ds SET OPTIONS (max_time_travel_hours = 48)", []classes.Class{classes.Irreversible}},
		{"ALTER SCHEMA ds SET OPTIONS (default_table_expiration_days = 1)", []classes.Class{classes.Irreversible}},
		{"ALTER DATABASE db SET OPTIONS (version_retention_period = '1h')", []classes.Class{classes.Irreversible}},
		{"ALTER TABLE t ADD ROW DELETION POLICY (OLDER_THAN(ts, INTERVAL 1 DAY))", []classes.Class{classes.Irreversible}},
		{"ALTER TABLE t DROP ROW DELETION POLICY", []classes.Class{classes.Write}},
		{"ALTER RESERVATION `proj.region-us.r1` SET OPTIONS (slot_capacity = 500)", []classes.Class{classes.Money}},
		{"GRANT `roles/bigquery.dataViewer` ON SCHEMA sales TO 'user:a@b.com'", []classes.Class{classes.Access}},
		{"REVOKE SELECT ON TABLE t FROM ROLE analyst", []classes.Class{classes.Access}},
		{"EXPORT DATA OPTIONS (uri = 'gs://b/*.csv', format = 'CSV') AS SELECT * FROM t", []classes.Class{classes.Access}},
		{"LOAD DATA INTO ds.t FROM FILES (uris = ['gs://b/x.csv'])", []classes.Class{classes.Write}},
		{"LOAD DATA OVERWRITE ds.t FROM FILES (uris = ['gs://b/x.csv'])", []classes.Class{classes.Irreversible}},
		// Scripts.
		{"DECLARE x INT64 DEFAULT 1; SELECT x", []classes.Class{classes.Read}},
		{"SET @@dataset_id = 'ds'; SELECT 1", []classes.Class{classes.Read}},
		{"BEGIN TRANSACTION; DELETE FROM t WHERE id = 1; COMMIT TRANSACTION", []classes.Class{classes.Read, classes.Delete}},
		{"ASSERT (SELECT COUNT(*) FROM t) > 0", []classes.Class{classes.Read}},
		{"SELECT 1; DELETE FROM t WHERE true", []classes.Class{classes.Read, classes.Irreversible}},
		{"BEGIN DELETE FROM t WHERE true; END", []classes.Class{classes.Unknown}},
		{"IF TRUE THEN DELETE FROM t WHERE true; END IF", []classes.Class{classes.Unknown}},
		{"EXECUTE IMMEDIATE 'DELETE FROM t WHERE true'", []classes.Class{classes.Unknown}},
		{"CALL ds.proc()", []classes.Class{classes.Unknown}},
		{"LOOP SELECT 1; END LOOP", []classes.Class{classes.Unknown}},
		// What does not lex or is not known.
		{"SELECT 'unterminated", []classes.Class{classes.Unknown}},
		{"SELECT 1 /* unterminated", []classes.Class{classes.Unknown}},
		{"SELECT 'a\nb'", []classes.Class{classes.Unknown}},
		{"SELECT $1", []classes.Class{classes.Unknown}},
		{"SELECT `unterminated", []classes.Class{classes.Unknown}},
		{"SELECT ``", []classes.Class{classes.Unknown}},
		{"SELECT r'ends in backslash\\'", []classes.Class{classes.Unknown}},
		{"VACUUM t", []classes.Class{classes.Unknown}},
		{"CREATE", []classes.Class{classes.Unknown}},
		{"", []classes.Class{classes.Read}},
	}
	for _, tc := range cases {
		got := ClassifyGoogleSQL(tc.sql)
		if !slices.Equal(got, tc.want) {
			t.Errorf("%q: %v, want %v", tc.sql, got, tc.want)
		}
	}
}

// Comments end where BigQuery ends them: block comments do not nest, and #
// and -- run to the end of the line, so a statement after a comment is
// read.
func TestGoogleSQLComments(t *testing.T) {
	for _, sql := range []string{
		"/* /* */ DELETE FROM t WHERE true -- */ ",
		"# comment\nDELETE FROM t WHERE true",
		"-- comment\nDELETE FROM t WHERE true",
		"SELECT 1; /* x */ DELETE FROM t WHERE true",
	} {
		if got := ClassifyGoogleSQL(sql); !slices.Contains(got, classes.Irreversible) {
			t.Errorf("%q: %v", sql, got)
		}
	}
}

func TestSummarizeGoogleSQL(t *testing.T) {
	cases := map[string][]string{
		"DELETE FROM `acme-prod.sales.orders` WHERE true":                 {`DELETE from "acme-prod".sales.orders (every row)`},
		"DELETE acme-prod.sales.orders WHERE id = 1":                      {`DELETE from "acme-prod".sales.orders`},
		"SELECT * FROM ds.a JOIN ds.b ON a.id = b.id":                     {"SELECT from ds.a, ds.b"},
		"UPDATE ds.t SET x = 1 WHERE 1 = 1":                               {"UPDATE ds.t (every row)"},
		"INSERT INTO ds.t (id) VALUES (1); TRUNCATE TABLE x":              {"INSERT into ds.t", "TRUNCATE TABLE x"},
		"DROP SCHEMA IF EXISTS sales CASCADE":                             {"DROP SCHEMA sales"},
		"CREATE OR REPLACE TABLE ds.t AS SELECT 1":                        {"CREATE OR REPLACE TABLE ds.t"},
		"SELECT ds.fn(x) FROM t":                                          {"SELECT from t, which also calls ds.fn"},
		"SELECT * FROM `my table`":                                        {`SELECT from "my table"`},
		"MERGE INTO ds.t USING s ON t.id = s.id WHEN MATCHED THEN DELETE": {"MERGE into ds.t"},
	}
	for sql, want := range cases {
		if got := SummarizeSQL("googlesql", sql); !slices.Equal(got, want) {
			t.Errorf("%q: %q, want %q", sql, got, want)
		}
	}
	if got := SummarizeSQL("googlesql", "SELECT 'x"); got != nil {
		t.Errorf("unlexable SQL summarized: %q", got)
	}
}

func FuzzGoogleSQL(f *testing.F) {
	for _, s := range []string{"SELECT 1", "DELETE FROM t WHERE id = 1", "SELECT '''a''' ; DROP TABLE t", "/* x */ UPDATE t SET a = 1 WHERE a = a",
		"MERGE t USING s ON TRUE WHEN MATCHED THEN DELETE", "SELECT r'\\''", "BEGIN; END"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, sql string) {
		cls := ClassifyGoogleSQL(sql)
		if len(cls) == 0 {
			t.Fatal("no class")
		}
		// Every statement Opfence reads gets a summary, and a DELETE or
		// UPDATE says (every row) only when it is irreversible.
		if sum := SummarizeSQL("googlesql", sql); sum != nil {
			for _, line := range sum {
				if strings.Contains(line, "(every row)") && !slices.Contains(cls, classes.Irreversible) {
					t.Fatalf("%q: %q but %v", sql, line, cls)
				}
			}
		}
	})
}
