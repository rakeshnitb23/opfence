package engine

import (
	"os"
	"strings"
	"testing"

	"github.com/rakeshnitb23/opfence/internal/catalog"
	"github.com/rakeshnitb23/opfence/internal/policy"
	"github.com/rakeshnitb23/opfence/internal/request"
)

// Cards of rules that read SQL say what the SQL does, from its parse.
func TestSQLSummaryInCards(t *testing.T) {
	c, err := catalog.Embedded()
	if err != nil {
		t.Fatal(err)
	}
	e := New(c, policy.Resolve(nil, nil))
	cases := []struct {
		prov, tool string
		args       map[string]any
		card       string
	}{
		{"supabase-mcp", "execute_sql", map[string]any{"project_id": "p1", "query": "select * from auth.users"},
			"Run SQL on project p1: SELECT from auth.users"},
		{"supabase-mcp", "execute_sql", map[string]any{"project_id": "p1", "query": "/* tidy up old rows */ delete from orders"},
			"Run SQL on project p1: DELETE from orders (every row)"},
		{"supabase-mcp", "execute_sql", map[string]any{"project_id": "p1", "query": "with d as (delete from users returning id) select count(*) from d"},
			"Run SQL on project p1: SELECT from d, which also runs DELETE from users (every row)"},
		// A table name cannot pass for words of the summary.
		{"supabase-mcp", "execute_sql", map[string]any{"project_id": "p1", "query": "delete from \"cache\nreads only\""},
			`Run SQL on project p1: DELETE from "cache reads only" (every row)`},
		// More than three statements are counted.
		{"supabase-mcp", "execute_sql", map[string]any{"project_id": "p1", "query": "select 1; select 2; select 3; drop table a; drop table b"},
			"Run SQL on project p1: SELECT; SELECT; SELECT; and 2 more statements"},
		{"supabase-mcp", "execute_sql", map[string]any{"project_id": "p1", "query": "delete from where"},
			"Run SQL on project p1: SQL Opfence cannot read"},
		// A list of statements, SQLite, and SQL that is MySQL or Postgres.
		{"neon-mcp", "run_sql_transaction", map[string]any{"project_id": "p1", "branch_id": "b1", "sql_statements": []any{"update t set a = 1 where id = 2", "truncate logs"}},
			"Run a SQL transaction on branch b1 of project p1: UPDATE t; TRUNCATE logs"},
		{"cloudflare-mcp", "d1_database_query", map[string]any{"database_id": "d1", "sql": "DELETE FROM notes WHERE body GLOB '*'"},
			"Run SQL on D1 database d1: DELETE from notes (every row)"},
		{"planetscale-mcp", "planetscale_execute_write_query", map[string]any{"database": "shop", "branch": "main", "query": "DELETE FROM `orders`"},
			"Run SQL that changes data on branch main of database shop: DELETE from orders (every row)"},
		// No SQL argument, and Redis commands, keep the card as it was.
		{"supabase-mcp", "execute_sql", map[string]any{"project_id": "p1"},
			"Run SQL on project p1"},
		{"upstash-mcp", "redis_database_run_redis_commands", map[string]any{"database_id": "u1", "database_rest_url": "https://x", "commands": []any{[]any{"FLUSHALL"}}},
			`Run Redis commands [["FLUSHALL"]] on Upstash database u1 https://x`},
	}
	for _, tc := range cases {
		p := c.Provider(tc.prov)
		if p == nil {
			t.Fatalf("no provider %s", tc.prov)
		}
		res := e.EvaluateTool(p, tc.tool, tc.args)
		if got := res.Evaluations[0].Card; got != tc.card {
			t.Errorf("%s %s:\n got  %q\n want %q", tc.prov, tc.tool, got, tc.card)
		}
	}
}

// The summary is added only when the class came from the SQL. DynamoDB's
// PartiQL is read by the Postgres parser, which nests block comments where
// PartiQL does not, so a statement with one is unknown by a when condition
// and its Postgres reading must not reach the card.
func TestSQLSummaryOnlyFromSQLClass(t *testing.T) {
	c, err := catalog.Embedded()
	if err != nil {
		t.Fatal(err)
	}
	e := New(c, policy.Resolve(nil, nil))
	for _, f := range []struct{ file, card string }{
		{"dynamodb-execute-statement.http", "Run a PartiQL statement: SELECT from orders"},
		{"dynamodb-execute-statement-delete.http", "Run a PartiQL statement: DELETE from orders"},
		{"dynamodb-execute-statement-comment.http", "Run a PartiQL statement"},
	} {
		data, err := os.ReadFile("../../catalog/aws/fixtures/" + f.file)
		if err != nil {
			t.Fatal(err)
		}
		req, _, err := request.ParseFixture(data)
		if err != nil {
			t.Fatal(err)
		}
		if got := e.Evaluate(req).Evaluations[0].Card; got != f.card {
			t.Errorf("%s: card %q, want %q", f.file, got, f.card)
		}
	}
}

// libSQL bodies sent over HTTP are summarised statement by statement.
func TestSQLSummaryLibSQL(t *testing.T) {
	c, err := catalog.Embedded()
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile("../../catalog/turso/fixtures/sql-pipeline-batch.http")
	if err != nil {
		t.Fatal(err)
	}
	req, _, err := request.ParseFixture(data)
	if err != nil {
		t.Fatal(err)
	}
	res := New(c, policy.Resolve(nil, nil)).Evaluate(req)
	card := res.Evaluations[0].Card
	if !strings.HasSuffix(card, ": SELECT from sessions; DELETE from sessions") {
		t.Errorf("card %q", card)
	}
}

func TestSQLSummaryText(t *testing.T) {
	long := strings.Repeat("x", 400)
	if got := sqlSummaryText([]string{long}); len([]rune(got)) != 301 || !strings.HasSuffix(got, "…") {
		t.Errorf("not cut at 300: %d runes", len([]rune(got)))
	}
	if got := sqlSummaryText([]string{"a\x1b[31m"}); strings.ContainsRune(got, 0x1b) {
		t.Errorf("control character kept: %q", got)
	}
}
