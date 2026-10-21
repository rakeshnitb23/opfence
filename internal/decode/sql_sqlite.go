package decode

import (
	"strings"
	"unicode"

	sqlite "github.com/rqlite/sql"

	"github.com/rakeshnitb23/opfence/internal/classes"
)

// ClassifySQLite classifies SQLite SQL text, as Cloudflare D1 and libSQL
// (Turso) run it, by the same table as ClassifySQL (docs/ARCHITECTURE.md
// §3.4). It parses with rqlite/sql, which accepts what the sqlite3 binary
// accepts. SQL that does not parse, and every statement type not listed
// below, is unknown.
func ClassifySQLite(sql string) (out []classes.Class) {
	unknown := []classes.Class{classes.Unknown}
	if len(sql) > maxSQL {
		return unknown
	}
	defer func() {
		if recover() != nil {
			out = unknown
		}
	}()
	stmts, err := sqlite.NewParser(strings.NewReader(sqliteText(sql))).ParseStatements()
	if err != nil {
		return unknown
	}
	seen := map[classes.Class]bool{}
	add := func(cs ...classes.Class) {
		for _, c := range cs {
			if !seen[c] {
				seen[c] = true
				out = append(out, c)
			}
		}
	}
	for _, st := range stmts {
		add(sqliteStatement(st)...)
		add(sqliteInside(st)...)
	}
	if len(out) == 0 {
		return []classes.Class{classes.Read}
	}
	return out
}

// sqliteText returns the text as SQLite's tokenizer reads it. SQLite stops at
// the first NUL, so what follows one never runs: "DELETE FROM t\x00 WHERE
// id = 1" deletes every row. And SQLite counts every character from 0x80 up
// as part of an identifier, including non-ASCII spaces that rqlite/sql would
// skip, so those become a letter.
func sqliteText(sql string) string {
	if i := strings.IndexByte(sql, 0); i >= 0 {
		sql = sql[:i]
	}
	return strings.Map(func(r rune) rune {
		if r >= 0x80 && unicode.IsSpace(r) {
			return 'À'
		}
		return r
	}, sql)
}

// sqliteStatement classifies what a statement itself does. Function calls
// anywhere inside it are added by sqliteInside.
func sqliteStatement(n sqlite.Statement) []classes.Class {
	switch st := n.(type) {
	case *sqlite.SelectStatement:
		return one(classes.Read)
	case *sqlite.ExplainStatement:
		return one(classes.Read) // SQLite's EXPLAIN never runs the statement
	case *sqlite.BeginStatement, *sqlite.CommitStatement, *sqlite.RollbackStatement,
		*sqlite.SavepointStatement, *sqlite.ReleaseStatement, *sqlite.DetachStatement:
		return one(classes.Read)

	case *sqlite.InsertStatement:
		if sqliteSystemTable(st.Table) {
			return one(classes.Irreversible)
		}
		if st.Replace.IsValid() || st.InsertOrReplace.IsValid() {
			// REPLACE deletes every row the new one conflicts with on any
			// unique key, not only the row it replaces.
			return []classes.Class{classes.Write, classes.Delete}
		}
		return one(classes.Write)
	case *sqlite.UpdateStatement:
		if st.Table != nil && sqliteSystemTable(st.Table.Name) {
			return one(classes.Irreversible)
		}
		if !sqliteLimits(st.WhereExpr, sqliteTableNames(st.Table)) {
			return one(classes.Irreversible)
		}
		if st.UpdateOrReplace.IsValid() {
			return []classes.Class{classes.Write, classes.Delete} // deletes the rows it conflicts with
		}
		return one(classes.Write)
	case *sqlite.DeleteStatement:
		if st.Table != nil && sqliteSystemTable(st.Table.Name) {
			return one(classes.Irreversible)
		}
		if sqliteLimits(st.WhereExpr, sqliteTableNames(st.Table)) {
			return one(classes.Delete)
		}
		return one(classes.Irreversible)

	case *sqlite.DropTableStatement, *sqlite.DropViewStatement, *sqlite.DropIndexStatement, *sqlite.DropTriggerStatement:
		return one(classes.Irreversible)
	case *sqlite.AlterTableStatement:
		if st.DropColumnName != nil {
			return []classes.Class{classes.Write, classes.Irreversible}
		}
		return one(classes.Write)
	case *sqlite.CreateTriggerStatement:
		// A trigger runs its body on every later statement it fires on.
		out := one(classes.Write)
		for _, b := range st.Body {
			out = append(out, sqliteStatement(b)...)
		}
		return out
	case *sqlite.CreateVirtualTableStatement:
		if st.ModuleName == nil || !sqliteSafeModules[strings.ToLower(st.ModuleName.Name)] {
			return one(classes.Unknown) // a module can read or write files
		}
		return one(classes.Write)
	case *sqlite.CreateTableStatement, *sqlite.CreateViewStatement, *sqlite.CreateIndexStatement,
		*sqlite.AnalyzeStatement, *sqlite.ReindexStatement:
		return one(classes.Write)
	case *sqlite.VacuumStatement:
		if st.Filename != nil {
			return one(classes.Unknown) // VACUUM INTO writes a file
		}
		return one(classes.Write)
	case *sqlite.AttachStatement:
		return one(classes.Unknown) // opens, or creates, a file
	case *sqlite.PragmaStatement:
		return sqlitePragma(st)
	}
	return one(classes.Unknown)
}

// sqliteSystemTable reports whether a statement writes the schema table or
// raw database pages, which corrupts the database or bypasses every
// constraint.
func sqliteSystemTable(name *sqlite.Ident) bool {
	if name == nil {
		return false
	}
	switch strings.ToLower(name.Name) {
	case "sqlite_master", "sqlite_schema", "sqlite_temp_master", "sqlite_temp_schema", "sqlite_dbpage":
		return true
	}
	return false
}

// Virtual table modules that keep their data in the database.
var sqliteSafeModules = map[string]bool{
	"fts3": true, "fts4": true, "fts5": true, "fts5vocab": true,
	"rtree": true, "rtree_i32": true, "geopoly": true,
}

// sqlitePragma classifies a PRAGMA: reading one is a read, setting one a
// write, and the few settings that switch off checks or corrupt the
// database are access or irreversible. A pragma Opfence does not know is
// unknown.
func sqlitePragma(st *sqlite.PragmaStatement) []classes.Class {
	var name string
	set := false
	switch e := st.Expr.(type) {
	case *sqlite.Ident:
		name = e.Name
	case *sqlite.Call:
		if e.Name != nil {
			name = e.Name.Name
		}
		set = !sqliteTargetPragmas[strings.ToLower(name)] // PRAGMA foreign_keys(0) sets
	case *sqlite.BinaryExpr:
		if id, ok := e.X.(*sqlite.Ident); ok && e.Op == sqlite.EQ {
			name, set = id.Name, true
		}
	}
	name = strings.ToLower(name)
	switch {
	case sqliteTargetPragmas[name]:
		if set {
			return one(classes.Unknown)
		}
		return one(classes.Read)
	case sqliteActionPragmas[name]:
		return one(classes.Write)
	case !sqliteSettingPragmas[name]:
		return one(classes.Unknown)
	case !set:
		return one(classes.Read)
	}
	switch name {
	case "writable_schema", "schema_version":
		return one(classes.Irreversible) // lets SQL edit, or desynchronises, the schema
	case "foreign_keys", "ignore_check_constraints", "trusted_schema", "query_only":
		return one(classes.Access) // switches off a check
	}
	return one(classes.Write)
}

// Pragmas whose argument names what to read (a table, an index, a limit).
var sqliteTargetPragmas = map[string]bool{
	"table_info": true, "table_xinfo": true, "table_list": true, "index_info": true, "index_xinfo": true,
	"index_list": true, "foreign_key_list": true, "foreign_key_check": true, "integrity_check": true,
	"quick_check": true, "collation_list": true, "compile_options": true, "database_list": true,
	"function_list": true, "module_list": true, "pragma_list": true, "stats": true, "data_version": true,
	"freelist_count": true, "page_count": true,
}

// Pragmas that do work rather than read or set a value.
var sqliteActionPragmas = map[string]bool{
	"optimize": true, "incremental_vacuum": true, "wal_checkpoint": true, "shrink_memory": true,
}

// Pragmas that hold a setting: without a value they read it.
var sqliteSettingPragmas = map[string]bool{
	"analysis_limit": true, "application_id": true, "auto_vacuum": true, "automatic_index": true,
	"busy_timeout": true, "cache_size": true, "cache_spill": true, "case_sensitive_like": true,
	"cell_size_check": true, "checkpoint_fullfsync": true, "defer_foreign_keys": true, "encoding": true,
	"foreign_keys": true, "fullfsync": true, "hard_heap_limit": true, "ignore_check_constraints": true,
	"journal_mode": true, "journal_size_limit": true, "legacy_alter_table": true, "locking_mode": true,
	"max_page_count": true, "mmap_size": true, "page_size": true, "query_only": true,
	"read_uncommitted": true, "recursive_triggers": true, "reverse_unordered_selects": true,
	"schema_version": true, "secure_delete": true, "soft_heap_limit": true, "synchronous": true,
	"temp_store": true, "threads": true, "trusted_schema": true, "user_version": true,
	"wal_autocheckpoint": true, "writable_schema": true,
}

// sqliteInside finds function calls with side effects anywhere in a
// statement, including trigger bodies, views and subqueries.
func sqliteInside(st sqlite.Statement) []classes.Class {
	var out []classes.Class
	check := func(name *sqlite.Ident) {
		if name != nil && sqliteDangerousFuncs[strings.ToLower(name.Name)] {
			out = append(out, classes.Unknown)
		}
	}
	_, _ = sqlite.Walk(sqlite.VisitFunc(func(n sqlite.Node) (sqlite.Node, error) {
		switch x := n.(type) {
		case *sqlite.Call:
			check(x.Name)
		case *sqlite.QualifiedTableFunctionName:
			check(x.Name)
		}
		return n, nil
	}), st)
	return out
}

// Functions that reach outside the database: extensions, and the file and
// editor functions of the sqlite3 shell.
var sqliteDangerousFuncs = map[string]bool{
	"load_extension": true, "fts3_tokenizer": true, "readfile": true, "writefile": true,
	"edit": true, "fsdir": true, "lsdir": true, "lsmode": true, "zipfile": true,
}

// sqliteLimits reports whether a WHERE clause limits the rows an UPDATE or
// DELETE of the outer table touches, by the rules effectiveWhere applies to
// Postgres. A bare double-quoted name does not count as a column: SQLite
// reads it as a string when no column has that name, so WHERE "1" is
// WHERE '1', which is true.
func sqliteLimits(e sqlite.Expr, outer map[string]bool) bool {
	switch n := e.(type) {
	case nil:
		return false
	case *sqlite.ParenExpr:
		return sqliteLimits(n.X, outer)
	case *sqlite.UnaryExpr:
		if n.Op == sqlite.NOT {
			x := n.X
			for p, ok := x.(*sqlite.ParenExpr); ok; p, ok = x.(*sqlite.ParenExpr) {
				x = p.X
			}
			if nl, ok := x.(*sqlite.Null); ok && nl.Op == sqlite.ISNULL {
				return false // NOT id IS NULL
			}
		}
	case *sqlite.BinaryExpr:
		switch n.Op {
		case sqlite.OR:
			return sqliteLimits(n.X, outer) && sqliteLimits(n.Y, outer)
		case sqlite.AND:
			return sqliteLimits(n.X, outer) || sqliteLimits(n.Y, outer)
		case sqlite.ISNOT:
			if _, ok := n.Y.(*sqlite.NullLit); ok {
				return false // id IS NOT NULL
			}
		case sqlite.LIKE:
			if l, ok := n.Y.(*sqlite.StringLit); ok && likeMatchesAll(l.Value) {
				return false // x LIKE '%'
			}
		case sqlite.GLOB:
			if l, ok := n.Y.(*sqlite.StringLit); ok && l.Value != "" && strings.Trim(l.Value, "*") == "" {
				return false // x GLOB '*'
			}
		case sqlite.REGEXP:
			if l, ok := n.Y.(*sqlite.StringLit); ok && regexMatchesAll(l.Value) {
				return false // x REGEXP ''
			}
		case sqlite.IN:
			if list, ok := n.Y.(*sqlite.ExprList); ok && n.X != nil {
				for _, x := range list.Exprs {
					if x != nil && x.String() == n.X.String() {
						return false // id IN (id, 7)
					}
				}
			}
		}
		if _, list := n.Y.(*sqlite.ExprList); !list && n.X != nil && n.Y != nil && n.X.String() == n.Y.String() {
			return false // id = id, id >= id, id IS id
		}
	case *sqlite.Null:
		if n.Op == sqlite.NOTNULL {
			return false // id NOT NULL, id NOTNULL
		}
	}
	return sqliteReadsColumn(e, nil, outer)
}

// sqliteTableNames returns the name and alias of the table a statement
// changes.
func sqliteTableNames(t *sqlite.QualifiedTableName) map[string]bool {
	names := map[string]bool{}
	if t == nil {
		return names
	}
	if t.Name != nil {
		names[strings.ToLower(t.Name.Name)] = true
	}
	if t.Alias != nil {
		names[strings.ToLower(t.Alias.Name)] = true
	}
	return names
}

// sqliteReadsColumn reports whether an expression reads a column of the
// statement's own rows. inner is nil at the statement's level, where every
// column counts; inside a subquery it holds the subquery's tables, and only
// a column that is unqualified, or qualified with an outer table or a name
// the subquery does not define, counts (as pgReadsOuter decides).
func sqliteReadsColumn(e sqlite.Expr, inner, outer map[string]bool) bool {
	reads := func(x sqlite.Expr) bool { return sqliteReadsColumn(x, inner, outer) }
	switch n := e.(type) {
	case nil:
		return false
	case *sqlite.Ident:
		return !n.Quoted
	case *sqlite.QualifiedRef:
		if inner == nil || n.Table == nil {
			return true
		}
		q := strings.ToLower(n.Table.Name)
		return outer[q] || !inner[q]
	case *sqlite.ParenExpr:
		return reads(n.X)
	case *sqlite.UnaryExpr:
		return reads(n.X)
	case *sqlite.BinaryExpr:
		return reads(n.X) || reads(n.Y)
	case *sqlite.CastExpr:
		return reads(n.X)
	case *sqlite.CollateExpr:
		return reads(n.X)
	case *sqlite.Null:
		return reads(n.X)
	case *sqlite.Range:
		return reads(n.X) || reads(n.Y)
	case *sqlite.ExprList:
		for _, x := range n.Exprs {
			if reads(x) {
				return true
			}
		}
	case *sqlite.Call:
		for _, x := range n.Args {
			if reads(x) {
				return true
			}
		}
	case *sqlite.CaseExpr:
		if reads(n.Operand) || reads(n.ElseExpr) {
			return true
		}
		for _, b := range n.Blocks {
			if reads(b.Condition) || reads(b.Body) {
				return true
			}
		}
	case *sqlite.Exists:
		return sqliteSelectReadsColumn(n.Select, inner, outer)
	case sqlite.SelectExpr:
		return sqliteSelectReadsColumn(n.SelectStatement, inner, outer)
	}
	return false
}

// sqliteSelectReadsColumn reports whether a subquery reads a column of the
// outer statement's rows. Its own tables, and those of any query it is
// inside, are inner names.
func sqliteSelectReadsColumn(s *sqlite.SelectStatement, inner, outer map[string]bool) bool {
	scope := map[string]bool{}
	for k := range inner {
		scope[k] = true
	}
	for x := s; x != nil; x = x.Compound {
		if x.WithClause != nil {
			for _, c := range x.WithClause.CTEs {
				if c != nil && c.TableName != nil {
					scope[strings.ToLower(c.TableName.Name)] = true
				}
			}
		}
		sqliteSourceNames(x.Source, scope)
	}
	for ; s != nil; s = s.Compound {
		for _, c := range s.Columns {
			if sqliteReadsColumn(c.Expr, scope, outer) {
				return true
			}
		}
		for _, l := range s.ValueLists {
			if sqliteReadsColumn(l, scope, outer) {
				return true
			}
		}
		if sqliteReadsColumn(s.WhereExpr, scope, outer) || sqliteReadsColumn(s.HavingExpr, scope, outer) {
			return true
		}
	}
	return false
}

// sqliteSourceNames adds the tables and aliases a FROM clause defines.
func sqliteSourceNames(src sqlite.Source, names map[string]bool) {
	switch t := src.(type) {
	case *sqlite.QualifiedTableName:
		if t.Name != nil {
			names[strings.ToLower(t.Name.Name)] = true
		}
		if t.Alias != nil {
			names[strings.ToLower(t.Alias.Name)] = true
		}
	case *sqlite.JoinClause:
		sqliteSourceNames(t.X, names)
		sqliteSourceNames(t.Y, names)
	case *sqlite.ParenSource:
		sqliteSourceNames(t.X, names)
		if t.Alias != nil {
			names[strings.ToLower(t.Alias.Name)] = true
		}
	}
}
