package decode

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/multigres/multigres/go/common/parser"
	"github.com/multigres/multigres/go/common/parser/ast"
	sqlite "github.com/rqlite/sql"
	"vitess.io/vitess/go/vt/sqlparser"

	"github.com/rakeshnitb23/opfence/internal/classes"
)

// SummarizeSQL describes what SQL does, one short phrase per statement, for
// approval cards: "DELETE from orders (every row)", "SELECT from
// auth.users", "DROP TABLE users". It reads the statements with the same
// parser and the same WHERE analysis as the classifier, so a summary never
// says a statement limits its rows when its class says it does not, and it
// never shows the SQL's own text: a comment such as /* read only */ cannot
// reach the card. Identifiers are shown as names, quoted when they are not
// plain. It returns nil when the SQL does not parse in the dialect.
func SummarizeSQL(dialect, sql string) []string {
	if len(sql) > maxSQL {
		return nil
	}
	switch dialect {
	case "", "postgres":
		return summarizePostgres(sql)
	case "mysql":
		return summarizeMySQL(sql)
	case "sqlite":
		return summarizeSQLite(sql)
	case "googlesql":
		return summarizeGoogleSQL(sql)
	}
	return nil
}

// sqlSummary describes one statement.
type sqlSummary struct {
	verb    string   // SELECT, DELETE, DROP TABLE
	prep    string   // from, into: put before the names
	names   []string // the tables or objects it acts on, shown as names
	allRows bool     // an UPDATE or DELETE whose WHERE limits no rows
	also    []string // statements it runs inside it (data-changing CTEs)
	calls   []string // functions it calls that change something
}

// maxSummaryNames bounds the names one statement lists.
const maxSummaryNames = 3

func (s sqlSummary) String() string {
	var b strings.Builder
	b.WriteString(s.verb)
	if names := sqlNameList(s.names); names != "" {
		if s.prep != "" {
			b.WriteString(" " + s.prep)
		}
		b.WriteString(" " + names)
	}
	if s.allRows {
		b.WriteString(" (every row)")
	}
	var extra []string
	if len(s.also) > 0 {
		extra = append(extra, "runs "+strings.Join(s.also, " and "))
	}
	if calls := sqlNameList(s.calls); calls != "" {
		extra = append(extra, "calls "+calls)
	}
	if len(extra) > 0 {
		b.WriteString(", which also " + strings.Join(extra, " and "))
	}
	return b.String()
}

// sqlNameList lists names once each, at most maxSummaryNames of them.
func sqlNameList(names []string) string {
	var out []string
	seen := map[string]bool{}
	for _, n := range names {
		if n == "" || seen[strings.ToLower(n)] {
			continue
		}
		seen[strings.ToLower(n)] = true
		out = append(out, n)
	}
	if len(out) > maxSummaryNames {
		return fmt.Sprintf("%s and %d more", strings.Join(out[:maxSummaryNames], ", "), len(out)-maxSummaryNames)
	}
	return strings.Join(out, ", ")
}

var plainSQLName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_$]{0,62}$`)

// sqlName shows a possibly qualified name: plain parts as they are, others
// double-quoted (and cut), so a table named "only reads this" reads as a
// name, not as words of the summary.
func sqlName(parts ...string) string {
	var out []string
	for _, p := range parts {
		if p == "" {
			continue
		}
		if plainSQLName.MatchString(p) {
			out = append(out, p)
			continue
		}
		if r := []rune(p); len(r) > 40 {
			p = string(r[:39]) + "…"
		}
		out = append(out, `"`+strings.ReplaceAll(p, `"`, `""`)+`"`)
	}
	return strings.Join(out, ".")
}

// sqlVerb turns a parser's statement type name into words: "CreateExtensionStmt"
// and "CREATE_EXTENSION" both become "CREATE EXTENSION".
func sqlVerb(t string) string {
	t = strings.TrimSuffix(t, "Stmt")
	t = strings.TrimSuffix(t, "Statement")
	var b strings.Builder
	for i, r := range t {
		switch {
		case r == '_' || r == ' ':
			b.WriteByte(' ')
			continue
		case i > 0 && r >= 'A' && r <= 'Z' && t[i-1] >= 'a' && t[i-1] <= 'z':
			b.WriteByte(' ')
		}
		b.WriteRune(r)
	}
	v := strings.ToUpper(strings.Join(strings.Fields(b.String()), " "))
	if v == "" {
		return "SQL statement"
	}
	return v
}

// ---- Postgres ----

func summarizePostgres(sql string) (out []string) {
	defer func() {
		if recover() != nil {
			out = nil
		}
	}()
	stmts, err := parser.ParseSQL(sql)
	if err != nil {
		return nil
	}
	// Functions the batch creates run what their bodies do, which the
	// classifier counts; calls to them are named.
	batch := map[string]bool{}
	for _, st := range stmts {
		if f, ok := st.(*ast.CreateFunctionStmt); ok {
			if parts := nameParts(f.FuncName); len(parts) > 0 {
				batch[parts[len(parts)-1]] = true
			}
		}
	}
	for _, st := range stmts {
		out = append(out, pgSummary(st, true, batch).String())
	}
	return out
}

// pgSummary describes a statement. With runs set, it also lists what runs
// inside it; EXPLAIN without ANALYZE runs nothing. batch names the
// functions the same batch creates.
func pgSummary(n ast.Node, runs bool, batch map[string]bool) sqlSummary {
	var s sqlSummary
	switch st := n.(type) {
	case *ast.RawStmt:
		return pgSummary(st.Stmt, runs, batch)
	case *ast.SelectStmt:
		if st.IntoClause != nil && st.IntoClause.Rel != nil {
			s = sqlSummary{verb: "SELECT INTO", names: []string{pgRelName(st.IntoClause.Rel)}}
		} else {
			s = sqlSummary{verb: "SELECT", prep: "from", names: pgSelectTables(st, 0)}
		}
	case *ast.InsertStmt:
		s = sqlSummary{verb: "INSERT", prep: "into", names: []string{pgRelName(st.Relation)}}
	case *ast.UpdateStmt:
		s = sqlSummary{verb: "UPDATE", names: []string{pgRelName(st.Relation)}, allRows: !effectiveWhere(st.WhereClause, st.Relation)}
	case *ast.DeleteStmt:
		s = sqlSummary{verb: "DELETE", prep: "from", names: []string{pgRelName(st.Relation)}, allRows: !effectiveWhere(st.WhereClause, st.Relation)}
	case *ast.MergeStmt:
		s = sqlSummary{verb: "MERGE", prep: "into", names: []string{pgRelName(st.Relation)}}
	case *ast.TruncateStmt:
		s = sqlSummary{verb: "TRUNCATE", names: pgRelNames(st.Relations)}
	case *ast.DropStmt:
		s = sqlSummary{verb: "DROP " + st.RemoveType.String(), names: pgDropNames(st.Objects)}
	case *ast.CreateStmt:
		s = sqlSummary{verb: "CREATE TABLE", names: []string{pgRelName(st.Relation)}}
	case *ast.AlterTableStmt:
		s = sqlSummary{verb: "ALTER " + st.Objtype.String(), names: []string{pgRelName(st.Relation)}}
	case *ast.IndexStmt:
		s = sqlSummary{verb: "CREATE INDEX", prep: "on", names: []string{pgRelName(st.Relation)}}
	case *ast.ViewStmt:
		s = sqlSummary{verb: "CREATE VIEW", names: []string{pgRelName(st.View)}}
	case *ast.GrantStmt:
		s.verb = "REVOKE"
		if st.IsGrant {
			s.verb = "GRANT"
		}
		s.prep, s.names = "on", pgRelNames(st.Objects)
	case *ast.ExplainStmt:
		analyze := explainAnalyze(st.Options)
		inner := pgSummary(st.Query, runs && analyze, batch)
		inner.verb = "EXPLAIN " + inner.verb
		if analyze {
			inner.verb = "EXPLAIN ANALYZE, which runs " + strings.TrimPrefix(inner.verb, "EXPLAIN ")
		}
		return inner
	case ast.Stmt:
		s.verb = sqlVerb(st.StatementType())
	default:
		s.verb = "SQL statement"
	}
	if runs {
		s.also, s.calls = pgInside(n, batch)
	}
	return s
}

// pgInside finds what runs inside a statement beyond the statement itself:
// data-changing CTEs at any depth, functions the classifier counts as
// changing something, and functions the batch creates.
func pgInside(n ast.Node, batch map[string]bool) (also, calls []string) {
	ast.Rewrite(n, func(cur *ast.Cursor) bool {
		switch x := cur.Node().(type) {
		case *ast.CommonTableExpr:
			switch x.Ctequery.(type) {
			case *ast.InsertStmt, *ast.UpdateStmt, *ast.DeleteStmt, *ast.MergeStmt:
				also = append(also, pgSummary(x.Ctequery, true, batch).String())
				return false // its own summary lists what runs inside it
			}
		case *ast.FuncCall:
			parts := nameParts(x.Funcname)
			c, known := sqlFunctionClass(parts)
			if (known && c != classes.Read) || (len(parts) > 0 && batch[parts[len(parts)-1]]) {
				calls = append(calls, sqlName(parts...))
			}
		}
		return true
	}, nil)
	return also, calls
}

func pgRelName(r *ast.RangeVar) string {
	if r == nil {
		return ""
	}
	return sqlName(r.SchemaName, r.RelName)
}

func pgRelNames(l *ast.NodeList) []string {
	if l == nil {
		return nil
	}
	var out []string
	for _, n := range l.Items {
		if r, ok := n.(*ast.RangeVar); ok {
			out = append(out, pgRelName(r))
		}
	}
	return out
}

// pgDropNames reads DROP's objects: each is a list of name parts.
func pgDropNames(l *ast.NodeList) []string {
	if l == nil {
		return nil
	}
	var out []string
	for _, n := range l.Items {
		switch o := n.(type) {
		case *ast.NodeList:
			var parts []string
			for _, p := range o.Items {
				if s, ok := p.(*ast.String); ok {
					parts = append(parts, s.SVal)
				}
			}
			out = append(out, sqlName(parts...))
		case *ast.String:
			out = append(out, sqlName(o.SVal))
		}
	}
	return out
}

// pgSelectTables lists the tables a query reads in its FROM clauses,
// through joins, subqueries in FROM and set operations.
func pgSelectTables(st *ast.SelectStmt, depth int) []string {
	if st == nil || depth > 8 {
		return nil
	}
	var out []string
	if st.Larg != nil || st.Rarg != nil {
		out = append(out, pgSelectTables(st.Larg, depth+1)...)
		return append(out, pgSelectTables(st.Rarg, depth+1)...)
	}
	if st.FromClause == nil {
		return nil
	}
	for _, n := range st.FromClause.Items {
		out = append(out, pgFromTables(n, depth+1)...)
	}
	return out
}

func pgFromTables(n ast.Node, depth int) []string {
	if depth > 8 {
		return nil
	}
	switch f := n.(type) {
	case *ast.RangeVar:
		return []string{pgRelName(f)}
	case *ast.JoinExpr:
		return append(pgFromTables(f.Larg, depth+1), pgFromTables(f.Rarg, depth+1)...)
	case *ast.RangeSubselect:
		if q, ok := f.Subquery.(*ast.SelectStmt); ok {
			return pgSelectTables(q, depth+1)
		}
	}
	return nil
}

// ---- MySQL ----

func summarizeMySQL(sql string) (out []string) {
	versions := mysqlVersions(sql)
	if versions == nil {
		return nil
	}
	defer func() {
		if recover() != nil {
			out = nil
		}
	}()
	// Versioned comments can make one text several statements; every
	// reading that differs is listed.
	seen := map[string]bool{}
	for _, v := range versions {
		p, err := sqlparser.New(sqlparser.Options{MySQLServerVersion: v})
		if err != nil {
			return nil
		}
		stmts, err := p.ParseMultiple(sql)
		if err != nil {
			return nil
		}
		for _, st := range stmts {
			if _, ok := st.(*sqlparser.CommentOnly); ok {
				continue
			}
			s := mysqlSummary(st).String()
			if !seen[s] {
				seen[s] = true
				out = append(out, s)
			}
		}
	}
	return out
}

func mysqlSummary(n sqlparser.Statement) sqlSummary {
	switch st := n.(type) {
	case *sqlparser.Select:
		return sqlSummary{verb: "SELECT", prep: "from", names: mysqlTableNames(st.From)}
	case *sqlparser.Union:
		s := sqlSummary{verb: "SELECT", prep: "from"}
		_ = sqlparser.Walk(func(node sqlparser.SQLNode) (bool, error) {
			if sel, ok := node.(*sqlparser.Select); ok {
				s.names = append(s.names, mysqlTableNames(sel.From)...)
			}
			return true, nil
		}, st)
		return s
	case *sqlparser.Insert:
		verb := "INSERT"
		if st.Action == sqlparser.ReplaceAct {
			verb = "REPLACE"
		}
		return sqlSummary{verb: verb, prep: "into", names: mysqlTableNames([]sqlparser.TableExpr{st.Table})}
	case *sqlparser.Update:
		return sqlSummary{verb: "UPDATE", names: mysqlTableNames(st.TableExprs), allRows: !mysqlLimits(st.Where, mysqlOuterNames(st.TableExprs))}
	case *sqlparser.Delete:
		names := mysqlNames(st.Targets)
		if len(names) == 0 {
			names = mysqlTableNames(st.TableExprs)
		}
		return sqlSummary{verb: "DELETE", prep: "from", names: names, allRows: !mysqlLimits(st.Where, mysqlOuterNames(st.TableExprs))}
	case *sqlparser.DropTable:
		return sqlSummary{verb: "DROP TABLE", names: mysqlNames(st.FromTables)}
	case *sqlparser.DropView:
		return sqlSummary{verb: "DROP VIEW", names: mysqlNames(st.FromTables)}
	case *sqlparser.DropDatabase:
		return sqlSummary{verb: "DROP DATABASE", names: []string{sqlName(st.DBName.String())}}
	case *sqlparser.TruncateTable:
		return sqlSummary{verb: "TRUNCATE", names: mysqlNames(sqlparser.TableNames{st.Table})}
	case *sqlparser.AlterTable:
		return sqlSummary{verb: "ALTER TABLE", names: mysqlNames(sqlparser.TableNames{st.Table})}
	case *sqlparser.CreateTable:
		return sqlSummary{verb: "CREATE TABLE", names: mysqlNames(sqlparser.TableNames{st.Table})}
	case *sqlparser.ExplainStmt:
		inner := mysqlSummary(st.Statement)
		if st.Type == sqlparser.AnalyzeType {
			inner.verb = "EXPLAIN ANALYZE, which runs " + inner.verb
		} else {
			inner.verb = "EXPLAIN " + inner.verb
		}
		return inner
	}
	return sqlSummary{verb: sqlVerb(sqlparser.ASTToStatementType(n).String())}
}

func mysqlNames(t sqlparser.TableNames) []string {
	var out []string
	for _, n := range t {
		out = append(out, sqlName(n.Qualifier.String(), n.Name.String()))
	}
	return out
}

// mysqlTableNames lists the tables in FROM-style table expressions, through
// joins and parentheses; derived tables add the tables they read.
func mysqlTableNames(exprs []sqlparser.TableExpr) []string {
	var out []string
	for _, e := range exprs {
		switch t := e.(type) {
		case *sqlparser.AliasedTableExpr:
			switch x := t.Expr.(type) {
			case sqlparser.TableName:
				if x.Qualifier.IsEmpty() && strings.EqualFold(x.Name.String(), "dual") {
					continue // the parser's stand-in for no table: SELECT 1
				}
				out = append(out, mysqlNames(sqlparser.TableNames{x})...)
			case *sqlparser.DerivedTable:
				if sel, ok := x.Select.(*sqlparser.Select); ok {
					out = append(out, mysqlTableNames(sel.From)...)
				}
			}
		case *sqlparser.JoinTableExpr:
			out = append(out, mysqlTableNames([]sqlparser.TableExpr{t.LeftExpr, t.RightExpr})...)
		case *sqlparser.ParenTableExpr:
			out = append(out, mysqlTableNames(t.Exprs)...)
		}
	}
	return out
}

// ---- SQLite ----

func summarizeSQLite(sql string) (out []string) {
	defer func() {
		if recover() != nil {
			out = nil
		}
	}()
	stmts, err := sqlite.NewParser(strings.NewReader(sqliteText(sql))).ParseStatements()
	if err != nil {
		return nil
	}
	for _, st := range stmts {
		out = append(out, sqliteSummary(st).String())
	}
	return out
}

func sqliteSummary(n sqlite.Statement) sqlSummary {
	switch st := n.(type) {
	case *sqlite.SelectStatement:
		s := sqlSummary{verb: "SELECT", prep: "from"}
		for sel := st; sel != nil; sel = sel.Compound {
			s.names = append(s.names, sqliteSourceTables(sel.Source, 0)...)
		}
		return s
	case *sqlite.InsertStatement:
		verb := "INSERT"
		if st.Replace.IsValid() || st.InsertOrReplace.IsValid() {
			verb = "REPLACE"
		}
		return sqlSummary{verb: verb, prep: "into", names: []string{sqliteName(st.Schema, st.Table)}}
	case *sqlite.UpdateStatement:
		s := sqlSummary{verb: "UPDATE", allRows: !sqliteLimits(st.WhereExpr, sqliteTableNames(st.Table))}
		if st.Table != nil {
			s.names = []string{sqliteName(st.Table.Schema, st.Table.Name)}
		}
		return s
	case *sqlite.DeleteStatement:
		s := sqlSummary{verb: "DELETE", prep: "from", allRows: !sqliteLimits(st.WhereExpr, sqliteTableNames(st.Table))}
		if st.Table != nil {
			s.names = []string{sqliteName(st.Table.Schema, st.Table.Name)}
		}
		return s
	case *sqlite.DropTableStatement:
		return sqlSummary{verb: "DROP TABLE", names: []string{sqliteName(st.Schema, st.Name)}}
	case *sqlite.DropViewStatement:
		return sqlSummary{verb: "DROP VIEW", names: []string{sqliteName(st.Schema, st.Name)}}
	case *sqlite.DropIndexStatement:
		return sqlSummary{verb: "DROP INDEX", names: []string{sqliteName(st.Schema, st.Name)}}
	case *sqlite.DropTriggerStatement:
		return sqlSummary{verb: "DROP TRIGGER", names: []string{sqliteName(st.Schema, st.Name)}}
	case *sqlite.ExplainStatement:
		inner := sqliteSummary(st.Stmt)
		inner.verb = "EXPLAIN " + inner.verb // SQLite's EXPLAIN never runs it
		return inner
	}
	return sqlSummary{verb: sqlVerb(fmt.Sprintf("%T", n)[len("*sql."):])}
}

func sqliteName(schema, name *sqlite.Ident) string {
	var parts []string
	if schema != nil {
		parts = append(parts, schema.Name)
	}
	if name != nil {
		parts = append(parts, name.Name)
	}
	return sqlName(parts...)
}

func sqliteSourceTables(src sqlite.Source, depth int) []string {
	if depth > 8 {
		return nil
	}
	switch t := src.(type) {
	case *sqlite.QualifiedTableName:
		return []string{sqliteName(t.Schema, t.Name)}
	case *sqlite.JoinClause:
		return append(sqliteSourceTables(t.X, depth+1), sqliteSourceTables(t.Y, depth+1)...)
	case *sqlite.ParenSource:
		return sqliteSourceTables(t.X, depth+1)
	case *sqlite.SelectStatement:
		var out []string
		for sel := t; sel != nil; sel = sel.Compound {
			out = append(out, sqliteSourceTables(sel.Source, depth+1)...)
		}
		return out
	}
	return nil
}
