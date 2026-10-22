package decode

import (
	"fmt"
	"regexp"
	"slices"
	"strings"

	"vitess.io/vitess/go/vt/sqlparser"

	"github.com/rakeshnitb23/opfence/internal/classes"
)

// ClassifyMySQL classifies MySQL SQL text, as PlanetScale's Vitess databases
// run it, by the same table as ClassifySQL (docs/ARCHITECTURE.md §3.4). It
// parses with Vitess' own parser, the one vtgate parses every query with.
// SQL that does not parse, DDL Vitess only parses in part (vtgate passes it
// on to MySQL as text), and every statement type not listed below are
// unknown.
//
// A versioned comment, /*!80000 DELETE ... */, runs only on servers of at
// least that version. The SQL is parsed once for each range of versions its
// comments mark out, and every reading counts.
func ClassifyMySQL(sql string) (out []classes.Class) {
	unknown := []classes.Class{classes.Unknown}
	if len(sql) > maxSQL {
		return unknown
	}
	versions := mysqlVersions(sql)
	if versions == nil {
		return unknown
	}
	defer func() {
		if recover() != nil {
			out = unknown
		}
	}()
	seen := map[classes.Class]bool{}
	add := func(cs ...classes.Class) {
		for _, c := range cs {
			if !seen[c] {
				seen[c] = true
				out = append(out, c)
			}
		}
	}
	for _, v := range versions {
		p, err := sqlparser.New(sqlparser.Options{MySQLServerVersion: v})
		if err != nil {
			return unknown
		}
		stmts, err := p.ParseMultiple(sql)
		if err != nil {
			return unknown
		}
		for _, st := range stmts {
			add(mysqlStatement(st)...)
			add(mysqlInside(st)...)
		}
	}
	if len(out) == 0 {
		return []classes.Class{classes.Read}
	}
	return out
}

// mysqlVersionComment finds the five-digit version of a versioned comment.
// It may also match inside a string or another comment; parsing at a version
// that changes nothing only costs time.
var mysqlVersionComment = regexp.MustCompile(`/\*!([0-9]{5})`)

// maxMySQLVersions bounds how many times one text is parsed.
const maxMySQLVersions = 16

// mysqlVersions returns the server versions to parse at: one below every
// versioned comment, and each comment's own version, which is the lowest
// that runs it. It returns nil when there are too many to try.
func mysqlVersions(sql string) []string {
	var marks []string
	for _, m := range mysqlVersionComment.FindAllStringSubmatch(sql, -1) {
		if !slices.Contains(marks, m[1]) {
			marks = append(marks, m[1])
		}
	}
	if len(marks) >= maxMySQLVersions {
		return nil
	}
	slices.Sort(marks)
	out := []string{"0.0.0"}
	for _, m := range marks {
		// Mmmpp, as Vitess compares them: 80040 is 8.0.40.
		out = append(out, fmt.Sprintf("%d.%d.%d", int(m[0]-'0'), atoi2(m[1:3]), atoi2(m[3:5])))
	}
	return out
}

func atoi2(s string) int { return int(s[0]-'0')*10 + int(s[1]-'0') }

// mysqlStatement classifies what a statement itself does. Function calls and
// tables anywhere inside it are added by mysqlInside.
func mysqlStatement(n sqlparser.Statement) []classes.Class {
	switch st := n.(type) {
	case nil, *sqlparser.CommentOnly:
		return nil
	case *sqlparser.Select:
		return mysqlInto(st.Into)
	case *sqlparser.Union:
		return mysqlInto(st.Into)
	case *sqlparser.ValuesStatement, *sqlparser.Show, *sqlparser.ExplainTab, *sqlparser.Use,
		*sqlparser.Begin, *sqlparser.Commit, *sqlparser.Rollback, *sqlparser.SRollback,
		*sqlparser.Savepoint, *sqlparser.Release, *sqlparser.UnlockTables, *sqlparser.DeallocateStmt,
		*sqlparser.ShowMigrationLogs, *sqlparser.ShowThrottledApps, *sqlparser.ShowThrottlerStatus,
		*sqlparser.Stream, *sqlparser.VStream:
		return one(classes.Read)
	case *sqlparser.ExplainStmt:
		if st.Type == sqlparser.AnalyzeType {
			return mysqlStatement(st.Statement) // EXPLAIN ANALYZE runs the statement
		}
		return one(classes.Read)
	case *sqlparser.VExplainStmt:
		return mysqlStatement(st.Statement) // VEXPLAIN QUERIES and ALL run it
	case *sqlparser.Set:
		return mysqlSet(st)

	case *sqlparser.Insert:
		if st.Action == sqlparser.ReplaceAct {
			// REPLACE deletes every row the new one conflicts with on any
			// unique key, not only the row it replaces.
			return []classes.Class{classes.Write, classes.Delete}
		}
		return one(classes.Write) // ON DUPLICATE KEY UPDATE updates, like an upsert
	case *sqlparser.Update:
		if mysqlLimits(st.Where, mysqlOuterNames(st.TableExprs)) {
			return one(classes.Write)
		}
		return one(classes.Irreversible)
	case *sqlparser.Delete:
		if mysqlLimits(st.Where, mysqlOuterNames(st.TableExprs)) {
			return one(classes.Delete)
		}
		return one(classes.Irreversible)

	case *sqlparser.DropTable, *sqlparser.DropView, *sqlparser.DropDatabase, *sqlparser.TruncateTable,
		*sqlparser.DropProcedure, *sqlparser.PurgeBinaryLogs:
		return one(classes.Irreversible)
	case *sqlparser.AlterTable:
		return mysqlAlterTable(st)
	case *sqlparser.CreateTable, *sqlparser.CreateView, *sqlparser.AlterView, *sqlparser.RenameTable,
		*sqlparser.CreateDatabase, *sqlparser.AlterDatabase, *sqlparser.CreateProcedure,
		*sqlparser.Analyze, *sqlparser.LockTables:
		return one(classes.Write)

	case *sqlparser.PrepareStmt:
		// It runs later, through EXECUTE; classify what it would run.
		if l, ok := st.Statement.(*sqlparser.Literal); ok && l.Type == sqlparser.StrVal {
			return ClassifyMySQL(l.Val)
		}
		return one(classes.Unknown) // prepared from a variable
	}
	// LOAD DATA, CALL, EXECUTE, DO, REPAIR, OPTIMIZE, FLUSH, KILL, Vitess'
	// ALTER VSCHEMA and migration commands, and anything else.
	return one(classes.Unknown)
}

// mysqlInto classifies a query's INTO clause: a file on the server is
// unknown, variables are a read.
func mysqlInto(into *sqlparser.SelectInto) []classes.Class {
	if into != nil && into.Type != sqlparser.IntoVariables {
		return one(classes.Unknown)
	}
	return one(classes.Read)
}

// mysqlSet classifies SET: server-wide settings are unknown, and so are the
// settings that change how the server reads later SQL (sql_mode can turn
// backslash escapes off, and a character set can turn a backslash into part
// of a character). Settings that switch off checks or logging are access.
func mysqlSet(st *sqlparser.Set) []classes.Class {
	out := one(classes.Read)
	for _, e := range st.Exprs {
		if e == nil || e.Var == nil {
			return one(classes.Unknown)
		}
		switch e.Var.Scope {
		case sqlparser.GlobalScope, sqlparser.PersistSysScope, sqlparser.PersistOnlySysScope, sqlparser.VitessMetadataScope:
			return one(classes.Unknown)
		case sqlparser.VariableScope, sqlparser.NextTxScope:
			continue
		}
		switch name := e.Var.Name.Lowered(); {
		case name == "sql_mode", name == "names", name == "charset", strings.HasPrefix(name, "character_set_"),
			strings.HasPrefix(name, "collation_"):
			return one(classes.Unknown)
		case name == "sql_log_bin", name == "foreign_key_checks":
			out = append(out, classes.Access)
		}
	}
	return out
}

func mysqlAlterTable(st *sqlparser.AlterTable) []classes.Class {
	out := one(classes.Write)
	for _, o := range st.AlterOptions {
		switch x := o.(type) {
		case *sqlparser.DropColumn:
			out = append(out, classes.Irreversible)
		case *sqlparser.TablespaceOperation:
			if !x.Import {
				out = append(out, classes.Irreversible) // DISCARD TABLESPACE
			}
		case sqlparser.TableOptions:
			for _, t := range x {
				if t != nil && strings.EqualFold(t.Name, "engine") && strings.EqualFold(t.String, "blackhole") {
					out = append(out, classes.Irreversible) // BLACKHOLE keeps no rows
				}
			}
		}
	}
	if st.PartitionSpec != nil {
		switch st.PartitionSpec.Action {
		case sqlparser.DropAction, sqlparser.TruncateAction, sqlparser.DiscardAction:
			out = append(out, classes.Irreversible)
		}
	}
	return out
}

// mysqlInside finds what a statement's parts can do beyond the statement
// itself: functions with side effects, and the tables that hold password
// hashes and privileges.
func mysqlInside(st sqlparser.Statement) []classes.Class {
	var out []classes.Class
	writes := false
	switch st.(type) {
	case *sqlparser.Select, *sqlparser.Union, *sqlparser.ValuesStatement, *sqlparser.Show,
		*sqlparser.ExplainStmt, *sqlparser.ExplainTab:
	default:
		writes = true
	}
	table := func(t sqlparser.TableName) {
		if !strings.EqualFold(t.Qualifier.String(), "mysql") {
			return
		}
		name := strings.ToLower(t.Name.String())
		if name == "user" || name == "global_priv" {
			out = append(out, classes.Credential) // password hashes
		}
		if writes && mysqlPrivilegeTables[name] {
			out = append(out, classes.Access)
		}
	}
	_ = sqlparser.Walk(func(n sqlparser.SQLNode) (bool, error) {
		switch x := n.(type) {
		case *sqlparser.FuncExpr:
			if mysqlDangerousFuncs[x.Name.Lowered()] {
				out = append(out, classes.Unknown)
			}
		case *sqlparser.LockingFunc:
			if x.Type == sqlparser.GetLock || x.Type == sqlparser.ReleaseLock || x.Type == sqlparser.ReleaseAllLocks {
				out = append(out, classes.Unknown)
			}
		case sqlparser.TableName:
			table(x)
		case *sqlparser.TableName:
			if x != nil {
				table(*x)
			}
		}
		return true, nil
	}, st)
	return out
}

// Tables in the mysql schema that grant privileges.
var mysqlPrivilegeTables = map[string]bool{
	"user": true, "db": true, "tables_priv": true, "columns_priv": true, "procs_priv": true,
	"proxies_priv": true, "global_grants": true, "role_edges": true, "default_roles": true, "global_priv": true,
}

// Functions whose side effects a query can hide: reading server files and
// common shell-running UDFs. GET_LOCK and RELEASE_LOCK, which Vitess parses
// as their own node, are caught in mysqlInside.
var mysqlDangerousFuncs = map[string]bool{
	"load_file": true, "sys_exec": true, "sys_eval": true,
}

// mysqlLimits reports whether a WHERE clause limits the rows an UPDATE or
// DELETE of the outer tables touches, by the rules effectiveWhere applies
// to Postgres.
func mysqlLimits(w *sqlparser.Where, outer map[string]bool) bool {
	if w == nil {
		return false
	}
	return mysqlExprLimits(w.Expr, outer)
}

func mysqlExprLimits(e sqlparser.Expr, outer map[string]bool) bool {
	switch n := e.(type) {
	case nil:
		return false
	case *sqlparser.OrExpr:
		return mysqlExprLimits(n.Left, outer) && mysqlExprLimits(n.Right, outer)
	case *sqlparser.XorExpr:
		return mysqlExprLimits(n.Left, outer) && mysqlExprLimits(n.Right, outer)
	case *sqlparser.AndExpr:
		return mysqlExprLimits(n.Left, outer) || mysqlExprLimits(n.Right, outer)
	case *sqlparser.NotExpr:
		switch x := n.Expr.(type) {
		case *sqlparser.IsExpr:
			if x.Right == sqlparser.IsNullOp {
				return false // NOT id IS NULL
			}
		case *sqlparser.ComparisonExpr:
			if x.Operator == sqlparser.NullSafeEqualOp && (mysqlNull(x.Left) || mysqlNull(x.Right)) {
				return false // NOT id <=> NULL
			}
		}
	case *sqlparser.IsExpr:
		if n.Right == sqlparser.IsNotNullOp {
			return false // id IS NOT NULL
		}
	case *sqlparser.ComparisonExpr:
		switch n.Operator {
		case sqlparser.InOp:
			if t, ok := n.Right.(sqlparser.ValTuple); ok {
				for _, v := range t {
					if sqlparser.String(v) == sqlparser.String(n.Left) {
						return false // id IN (id, 7)
					}
				}
			}
		case sqlparser.NotInOp:
		case sqlparser.LikeOp:
			if s, ok := mysqlString(n.Right); ok && n.Escape == nil && likeMatchesAll(s) {
				return false // x LIKE '%'
			}
		case sqlparser.RegexpOp:
			if s, ok := mysqlString(n.Right); ok && regexMatchesAll(s) {
				return false // x REGEXP ''
			}
		default:
			if sqlparser.String(n.Left) == sqlparser.String(n.Right) {
				return false // id = id, id >= id
			}
		}
	}
	return mysqlReadsOuter(e, outer)
}

func mysqlNull(e sqlparser.Expr) bool {
	_, ok := e.(*sqlparser.NullVal)
	return ok
}

func mysqlString(e sqlparser.Expr) (string, bool) {
	l, ok := e.(*sqlparser.Literal)
	if !ok || l.Type != sqlparser.StrVal {
		return "", false
	}
	return l.Val, true
}

// mysqlOuterNames returns the names and aliases of the tables a statement
// changes, which a subquery's columns may refer to.
func mysqlOuterNames(exprs []sqlparser.TableExpr) map[string]bool {
	names := map[string]bool{}
	var add func(sqlparser.TableExpr)
	add = func(te sqlparser.TableExpr) {
		switch t := te.(type) {
		case *sqlparser.AliasedTableExpr:
			if tn, ok := t.Expr.(sqlparser.TableName); ok {
				names[strings.ToLower(tn.Name.String())] = true
			}
			if !t.As.IsEmpty() {
				names[strings.ToLower(t.As.String())] = true
			}
		case *sqlparser.JoinTableExpr:
			add(t.LeftExpr)
			add(t.RightExpr)
		case *sqlparser.ParenTableExpr:
			for _, x := range t.Exprs {
				add(x)
			}
		}
	}
	for _, te := range exprs {
		add(te)
	}
	return names
}

// mysqlReadsOuter reports whether e reads a column of the statement's own
// rows, by the rules pgReadsOuter applies.
func mysqlReadsOuter(e sqlparser.SQLNode, outer map[string]bool) bool {
	reads := false
	_ = sqlparser.Walk(func(n sqlparser.SQLNode) (bool, error) {
		if reads {
			return false, nil
		}
		switch x := n.(type) {
		case *sqlparser.ColName:
			reads = true
			return false, nil
		case *sqlparser.Subquery:
			if mysqlSubqueryReadsOuter(x.Select, outer) {
				reads = true
			}
			return false, nil
		}
		return true, nil
	}, e)
	return reads
}

// mysqlSubqueryReadsOuter reports whether a subquery refers to the outer
// statement's rows: a column that is unqualified, or qualified with an
// outer table or a name the subquery does not define.
func mysqlSubqueryReadsOuter(sub sqlparser.SQLNode, outer map[string]bool) bool {
	inner := map[string]bool{}
	_ = sqlparser.Walk(func(n sqlparser.SQLNode) (bool, error) {
		switch x := n.(type) {
		case *sqlparser.AliasedTableExpr:
			if tn, ok := x.Expr.(sqlparser.TableName); ok {
				inner[strings.ToLower(tn.Name.String())] = true
			}
			if !x.As.IsEmpty() {
				inner[strings.ToLower(x.As.String())] = true
			}
		case *sqlparser.CommonTableExpr:
			inner[strings.ToLower(x.ID.String())] = true
		}
		return true, nil
	}, sub)
	reads := false
	_ = sqlparser.Walk(func(n sqlparser.SQLNode) (bool, error) {
		if c, ok := n.(*sqlparser.ColName); ok {
			q := strings.ToLower(c.Qualifier.Name.String())
			if q == "" || outer[q] || !inner[q] {
				reads = true
			}
		}
		return !reads, nil
	}, sub)
	return reads
}
