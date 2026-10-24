package decode

import (
	"strings"

	"github.com/multigres/multigres/go/common/parser"
	"github.com/multigres/multigres/go/common/parser/ast"

	"github.com/rakeshnitb23/opfence/internal/classes"
)

// ClassifySQL classifies Postgres SQL text for tools like Supabase's
// execute_sql. It returns the distinct classes of its statements, in order;
// the engine decides each and takes the strictest decision.
//
// It parses with a Go port of Postgres' own grammar (docs/ARCHITECTURE.md
// §3.4). SQL that does not parse, and every statement type not listed
// below, is unknown.
func ClassifySQL(sql string) (out []classes.Class) {
	unknown := []classes.Class{classes.Unknown}
	if len(sql) > maxSQL {
		// Deep enough nesting overflows the parser's stack, which recover
		// cannot catch.
		return unknown
	}
	defer func() {
		if recover() != nil {
			out = unknown
		}
	}()
	stmts, err := parser.ParseSQL(sql)
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
	c := &sqlClassifier{funcs: map[string][]classes.Class{}}
	for _, st := range stmts {
		c.collectFunctions(st)
	}
	for _, st := range stmts {
		add(classifyStatement(st)...)
		add(c.classifyInside(st)...)
	}
	if len(out) == 0 {
		return []classes.Class{classes.Read}
	}
	return out
}

// ClassifySQLDialect classifies SQL text in a dialect: postgres (or empty),
// mysql, sqlite or googlesql. Any other dialect is unknown.
func ClassifySQLDialect(dialect, sql string) []classes.Class {
	switch dialect {
	case "", "postgres":
		return ClassifySQL(sql)
	case "mysql":
		return ClassifyMySQL(sql)
	case "sqlite":
		return ClassifySQLite(sql)
	case "googlesql":
		return ClassifyGoogleSQL(sql)
	}
	return []classes.Class{classes.Unknown}
}

// maxSQL is the longest SQL ClassifySQL parses. Request bodies are capped
// well below it.
const maxSQL = 1 << 20

func one(c classes.Class) []classes.Class { return []classes.Class{c} }

// classifyStatement classifies what a statement itself does. Data-modifying
// CTEs and function calls anywhere inside it are added by classifyInside.
func classifyStatement(n ast.Node) []classes.Class {
	switch st := n.(type) {
	case nil:
		return nil
	case *ast.RawStmt:
		return classifyStatement(st.Stmt)
	case *ast.SelectStmt:
		if st.IntoClause != nil {
			return one(classes.Write) // SELECT ... INTO new_table
		}
		if st.Larg != nil || st.Rarg != nil {
			return append(classifyStatement(st.Larg), classifyStatement(st.Rarg)...)
		}
		return one(classes.Read)
	case *ast.InsertStmt:
		return one(classes.Write)
	case *ast.UpdateStmt:
		if effectiveWhere(st.WhereClause, st.Relation) {
			return one(classes.Write)
		}
		return one(classes.Irreversible)
	case *ast.DeleteStmt:
		if effectiveWhere(st.WhereClause, st.Relation) {
			return one(classes.Delete)
		}
		return one(classes.Irreversible)
	case *ast.MergeStmt:
		if st.MergeWhenClauses != nil {
			for _, c := range st.MergeWhenClauses.Items {
				if w, ok := c.(*ast.MergeWhenClause); ok && w.CommandType == ast.CMD_DELETE {
					return one(classes.Delete)
				}
			}
		}
		return one(classes.Write)
	case *ast.TruncateStmt, *ast.DropdbStmt, *ast.DropTableSpaceStmt:
		return one(classes.Irreversible)
	case *ast.DropStmt:
		if st.RemoveType == ast.OBJECT_POLICY {
			return one(classes.Access)
		}
		return one(classes.Irreversible)
	case *ast.DropOwnedStmt:
		return []classes.Class{classes.Irreversible, classes.Access}
	case *ast.DropRoleStmt, *ast.DropUserMappingStmt:
		return one(classes.Access)

	case *ast.ExplainStmt:
		if explainAnalyze(st.Options) {
			return classifyStatement(st.Query) // EXPLAIN ANALYZE runs the statement
		}
		return one(classes.Read)
	case *ast.DeclareCursorStmt:
		return classifyStatement(st.Query)
	case *ast.PrepareStmt:
		// It runs later, through EXECUTE; classify what it would run.
		return classifyStatement(st.Query)
	case *ast.CopyStmt:
		switch {
		case st.IsProgram:
			return one(classes.Unknown)
		case st.IsFrom:
			return one(classes.Write)
		case st.Filename != "":
			return one(classes.Unknown) // writes a file on the server
		case st.Query != nil:
			return classifyStatement(st.Query) // COPY (DELETE ... RETURNING) TO STDOUT
		}
		return one(classes.Read)
	case *ast.VariableSetStmt:
		if st.Kind == ast.VAR_RESET_ALL || privilegedSetting(st.Name) {
			return one(classes.Access) // RESET ALL undoes an earlier SET ROLE
		}
		return one(classes.Read)
	case *ast.AlterDatabaseSetStmt:
		if st.Setstmt != nil && (st.Setstmt.Kind == ast.VAR_RESET_ALL || privilegedSetting(st.Setstmt.Name)) {
			return []classes.Class{classes.Write, classes.Access}
		}
		return one(classes.Write)
	case *ast.DiscardStmt:
		if st.Target == ast.DISCARD_ALL {
			return one(classes.Access) // includes RESET ALL
		}
		return one(classes.Read)
	case *ast.VariableShowStmt, *ast.TransactionStmt, *ast.FetchStmt, *ast.ClosePortalStmt,
		*ast.ListenStmt, *ast.UnlistenStmt, *ast.DeallocateStmt, *ast.ConstraintsSetStmt:
		return one(classes.Read)

	case *ast.GrantStmt, *ast.GrantRoleStmt, *ast.ReassignOwnedStmt, *ast.SecLabelStmt,
		*ast.CreateRoleStmt, *ast.AlterRoleStmt, *ast.AlterRoleSetStmt,
		*ast.CreatePolicyStmt, *ast.AlterPolicyStmt, *ast.AlterDefaultPrivilegesStmt,
		*ast.CreateUserMappingStmt, *ast.AlterUserMappingStmt:
		return one(classes.Access)
	case *ast.AlterOwnerStmt:
		return []classes.Class{classes.Write, classes.Access}
	case *ast.CreateFunctionStmt:
		if securityDefiner(st.Options) {
			return []classes.Class{classes.Write, classes.Access}
		}
		return one(classes.Write)
	case *ast.AlterFunctionStmt:
		if securityDefiner(st.Actions) {
			return []classes.Class{classes.Write, classes.Access}
		}
		return one(classes.Write)
	case *ast.AlterTableStmt:
		return classifyAlterTable(st)
	case *ast.CreateSchemaStmt:
		out := one(classes.Write)
		if st.SchemaElts != nil {
			for _, e := range st.SchemaElts.Items {
				out = append(out, classifyStatement(e)...)
			}
		}
		return out

	case *ast.RuleStmt:
		// A rule rewrites later statements on its table into its actions.
		out := one(classes.Write)
		if st.Actions != nil {
			for _, a := range st.Actions.Items {
				out = append(out, classifyStatement(a)...)
			}
		}
		return out
	case *ast.CreateStmt, *ast.CreateTableAsStmt, *ast.IndexStmt, *ast.ViewStmt,
		*ast.CreateTriggerStmt, *ast.CreateEventTrigStmt, *ast.AlterEventTrigStmt, *ast.CreateExtensionStmt,
		*ast.AlterExtensionStmt, *ast.AlterExtensionContentsStmt, *ast.CreateSeqStmt, *ast.AlterSeqStmt,
		*ast.DefineStmt, *ast.CompositeTypeStmt, *ast.CreateEnumStmt, *ast.AlterEnumStmt, *ast.CreateRangeStmt,
		*ast.CreateDomainStmt, *ast.AlterDomainStmt, *ast.AlterTypeStmt, *ast.AlterCompositeTypeStmt,
		*ast.CreateCastStmt, *ast.CreateConversionStmt, *ast.CreateOpClassStmt, *ast.CreateOpFamilyStmt,
		*ast.AlterOpFamilyStmt, *ast.AlterOperatorStmt, *ast.CreateAmStmt, *ast.CreateTransformStmt,
		*ast.CreatePLangStmt, *ast.CreateFdwStmt, *ast.AlterFdwStmt, *ast.CreateForeignServerStmt,
		*ast.AlterForeignServerStmt, *ast.CreateForeignTableStmt, *ast.ImportForeignSchemaStmt,
		*ast.CreatePublicationStmt, *ast.AlterPublicationStmt, *ast.CreateSubscriptionStmt, *ast.AlterSubscriptionStmt,
		*ast.CreateStatsStmt, *ast.AlterStatsStmt, *ast.CreateTableSpaceStmt, *ast.AlterTableSpaceStmt,
		*ast.AlterTableMoveAllStmt, *ast.CreatedbStmt, *ast.AlterDatabaseStmt,
		*ast.AlterDatabaseRefreshCollStmt, *ast.AlterCollationStmt, *ast.AlterTSConfigurationStmt,
		*ast.AlterTSDictionaryStmt, *ast.AlterObjectSchemaStmt, *ast.AlterObjectDependsStmt, *ast.RenameStmt,
		*ast.ReplicaIdentityStmt, *ast.CreateAssertionStmt, *ast.CommentStmt, *ast.VacuumStmt,
		*ast.ClusterStmt, *ast.ReindexStmt, *ast.RefreshMatViewStmt, *ast.LockStmt, *ast.NotifyStmt,
		*ast.CheckPointStmt:
		return one(classes.Write)
	}
	// DO, CALL, EXECUTE, LOAD, ALTER SYSTEM and anything else.
	return one(classes.Unknown)
}

func classifyAlterTable(st *ast.AlterTableStmt) []classes.Class {
	out := one(classes.Write)
	if st.Cmds == nil {
		return out
	}
	for _, c := range st.Cmds.Items {
		cmd, ok := c.(*ast.AlterTableCmd)
		if !ok {
			continue
		}
		switch cmd.Subtype {
		case ast.AT_DropColumn:
			out = append(out, classes.Irreversible)
		case ast.AT_AlterColumnType:
			if d, ok := cmd.Def.(*ast.ColumnDef); ok && d.RawDefault != nil {
				out = append(out, classes.Irreversible) // USING rewrites every row
			}
		case ast.AT_DisableRowSecurity, ast.AT_NoForceRowSecurity, ast.AT_ChangeOwner:
			out = append(out, classes.Access)
		}
	}
	return out
}

// sqlClassifier holds what one batch of SQL defines that later statements
// in it can use.
type sqlClassifier struct {
	// funcs maps the name of each function the batch creates to what its
	// body does, so CREATE FUNCTION f ... AS $$ DELETE ... $$; SELECT f()
	// is not a read.
	funcs map[string][]classes.Class
}

// collectFunctions records the functions a statement creates.
func (c *sqlClassifier) collectFunctions(st ast.Node) {
	f, ok := st.(*ast.CreateFunctionStmt)
	if !ok {
		return
	}
	parts := nameParts(f.FuncName)
	if len(parts) == 0 {
		return
	}
	c.funcs[parts[len(parts)-1]] = functionBodyClasses(f)
}

// functionBodyClasses classifies a function's body: SQL bodies by their
// statements, every other language as unknown.
func functionBodyClasses(f *ast.CreateFunctionStmt) []classes.Class {
	if f.SQLBody != nil {
		var out []classes.Class
		ast.Rewrite(f.SQLBody, func(cur *ast.Cursor) bool {
			if st, ok := cur.Node().(ast.Stmt); ok {
				out = append(out, classifyStatement(st)...)
				return false
			}
			return true
		}, nil)
		return out
	}
	lang, body := "sql", ""
	if f.Options != nil {
		for _, o := range f.Options.Items {
			d, ok := o.(*ast.DefElem)
			if !ok {
				continue
			}
			switch strings.ToLower(d.Defname) {
			case "language":
				if v, ok := d.Arg.(*ast.String); ok {
					lang = strings.ToLower(v.SVal)
				}
			case "as":
				if l, ok := d.Arg.(*ast.NodeList); ok && len(l.Items) > 0 {
					if v, ok := l.Items[0].(*ast.String); ok {
						body = v.SVal
					}
				}
			}
		}
	}
	if lang != "sql" {
		return one(classes.Unknown)
	}
	return ClassifySQL(body)
}

// classifyInside finds what a statement's parts can do beyond the
// statement itself: data-modifying CTEs at any depth (Postgres runs them
// even under a SELECT), functions with side effects or defined in the same
// batch, and relations that hold secrets.
func (c *sqlClassifier) classifyInside(st ast.Node) []classes.Class {
	var out []classes.Class
	ast.Rewrite(st, func(cur *ast.Cursor) bool {
		switch n := cur.Node().(type) {
		case *ast.CommonTableExpr:
			out = append(out, classifyStatement(n.Ctequery)...)
		case *ast.FuncCall:
			parts := nameParts(n.Funcname)
			if cl, ok := sqlFunctionClass(parts); ok {
				out = append(out, cl)
			}
			if len(parts) > 0 {
				out = append(out, c.funcs[parts[len(parts)-1]]...)
				if strings.EqualFold(parts[len(parts)-1], "set_config") && setConfigPrivileged(n.Args) {
					out = append(out, classes.Access)
				}
			}
		case *ast.CreateTriggerStmt:
			out = append(out, c.triggerFunction(n.Funcname)...)
		case *ast.CreateEventTrigStmt:
			out = append(out, c.triggerFunction(n.FuncName)...)
		case *ast.RangeVar:
			if strings.EqualFold(n.SchemaName, "vault") && strings.EqualFold(n.RelName, "decrypted_secrets") {
				out = append(out, classes.Credential) // Supabase Vault, decrypted
			}
		}
		return true
	}, nil)
	return out
}

// triggerFunction classifies the function a trigger runs on every later
// statement it fires on: by its body when the batch defines it, otherwise
// unknown.
func (c *sqlClassifier) triggerFunction(name *ast.NodeList) []classes.Class {
	parts := nameParts(name)
	if len(parts) > 0 {
		if cs, ok := c.funcs[parts[len(parts)-1]]; ok {
			return cs
		}
	}
	return one(classes.Unknown)
}

// privilegedSetting reports whether a setting changes whose privileges a
// session acts with. Supabase's auth.uid() and auth.role(), which RLS
// policies call, read request.jwt.*.
func privilegedSetting(name string) bool {
	name = strings.ToLower(name)
	switch name {
	case "role", "session_authorization", "session_replication_role", "row_security":
		return true
	}
	return strings.HasPrefix(name, "request.jwt")
}

// setConfigPrivileged reports whether set_config's first argument names a
// privileged setting, or cannot be read.
func setConfigPrivileged(args *ast.NodeList) bool {
	if args == nil || len(args.Items) == 0 {
		return true
	}
	a := args.Items[0]
	if t, ok := a.(*ast.TypeCast); ok {
		a = t.Arg
	}
	if k, ok := a.(*ast.A_Const); ok {
		if v, ok := k.Val.(*ast.String); ok {
			return privilegedSetting(v.SVal)
		}
	}
	return true
}

// sqlFunctionClass returns the class of a function call with side effects a
// query can hide, by its name (schema-qualified or not).
func sqlFunctionClass(parts []string) (classes.Class, bool) {
	if len(parts) == 0 {
		return "", false
	}
	name := parts[len(parts)-1]
	full := strings.Join(parts, ".")
	switch {
	case sqlDangerousFuncs[name], sqlDangerousFuncs[full],
		strings.HasPrefix(name, "lo_"), strings.HasPrefix(name, "dblink"), strings.HasPrefix(name, "pg_file_"),
		strings.HasPrefix(name, "http_") && (len(parts) == 1 || parts[0] == "extensions" || parts[0] == "net"):
		return classes.Unknown, true
	case name == "nextval", name == "setval":
		return classes.Write, true
	}
	return "", false
}

// Functions whose side effects a query can hide.
var sqlDangerousFuncs = map[string]bool{
	"pg_terminate_backend": true, "pg_cancel_backend": true, "pg_drop_replication_slot": true,
	"pg_replication_origin_drop": true, "pg_create_logical_replication_slot": true, "pg_create_physical_replication_slot": true,
	"pg_reload_conf": true, "pg_rotate_logfile": true, "pg_promote": true, "pg_switch_wal": true,
	"pg_read_file": true, "pg_read_binary_file": true, "pg_ls_dir": true, "pg_stat_file": true,
	"pg_ls_logdir": true, "pg_ls_waldir": true, "pg_ls_tmpdir": true, "pg_ls_archive_statusdir": true,
	"set_config": true, "pg_advisory_lock": true, "pg_advisory_xact_lock": true, "pg_logical_emit_message": true,
	"query_to_xml": true, "query_to_xml_and_xmlschema": true, "query_to_xmlschema": true,
	"cursor_to_xml": true, "cursor_to_xmlschema": true,
	"http": true, "net.http_get": true, "net.http_post": true, "net.http_delete": true,
}

func nameParts(l *ast.NodeList) []string {
	if l == nil {
		return nil
	}
	var out []string
	for _, n := range l.Items {
		if s, ok := n.(*ast.String); ok {
			out = append(out, strings.ToLower(s.SVal))
		}
	}
	return out
}

// effectiveWhere reports whether a WHERE clause limits the rows an UPDATE
// or DELETE of target touches. A missing clause does not, and neither does
// one that reads no column of the statement (WHERE true, WHERE 1 = 1,
// WHERE $1, WHERE EXISTS (SELECT 1 FROM admins a WHERE a.id = 7)), an OR
// with such a branch (WHERE id = 5 OR true), an AND with no limiting
// branch, or a common tautology: id IS NOT NULL and its other spellings
// (NOT id IS NULL, id IS DISTINCT FROM NULL), id = id, id IN (id, ...),
// and patterns that match every value (LIKE '%', SIMILAR TO '%', a regex
// match with an empty pattern).
// Other tautologies can't be told apart from real filters; see
// docs/LIMITS.md.
func effectiveWhere(w ast.Node, target *ast.RangeVar) bool {
	switch n := w.(type) {
	case nil:
		return false
	case *ast.ParenExpr:
		return effectiveWhere(n.Expr, target)
	case *ast.BoolExpr:
		if n.Args == nil {
			return false
		}
		switch n.Boolop {
		case ast.OR_EXPR:
			for _, a := range n.Args.Items {
				if !effectiveWhere(a, target) {
					return false
				}
			}
			return true
		case ast.AND_EXPR:
			for _, a := range n.Args.Items {
				if effectiveWhere(a, target) {
					return true
				}
			}
			return false
		case ast.NOT_EXPR:
			if len(n.Args.Items) == 1 {
				arg := n.Args.Items[0]
				for p, ok := arg.(*ast.ParenExpr); ok; p, ok = arg.(*ast.ParenExpr) {
					arg = p.Expr
				}
				if nt, ok := arg.(*ast.NullTest); ok && nt.Nulltesttype == ast.IS_NULL {
					return false // NOT id IS NULL
				}
			}
		}
	case *ast.NullTest:
		if n.Nulltesttype == ast.IS_NOT_NULL {
			return false
		}
	case *ast.A_Expr:
		if _, list := n.Rexpr.(*ast.NodeList); !list && n.Lexpr != nil && n.Rexpr != nil && n.Lexpr.SqlString() == n.Rexpr.SqlString() {
			return false // id = id, id >= id
		}
		if pgTautology(n) {
			return false
		}
	}
	outer := map[string]bool{}
	if target != nil {
		outer[strings.ToLower(target.RelName)] = true
		if target.Alias != nil {
			outer[strings.ToLower(target.Alias.AliasName)] = true
		}
	}
	return pgReadsOuter(w, outer)
}

// pgTautology reports whether an operator expression holds for every row
// whose operand is not null.
func pgTautology(n *ast.A_Expr) bool {
	op := ""
	if n.Name != nil && len(n.Name.Items) > 0 {
		if s, ok := n.Name.Items[len(n.Name.Items)-1].(*ast.String); ok {
			op = s.SVal
		}
	}
	switch n.Kind {
	case ast.AEXPR_DISTINCT:
		return pgNullConst(n.Lexpr) || pgNullConst(n.Rexpr) // id IS DISTINCT FROM NULL
	case ast.AEXPR_LIKE, ast.AEXPR_ILIKE:
		if op == "~~" || op == "~~*" {
			s, ok := pgStringConst(n.Rexpr)
			return ok && likeMatchesAll(s)
		}
	case ast.AEXPR_SIMILAR:
		if f, ok := n.Rexpr.(*ast.FuncCall); ok && op == "~" && f.Args != nil && len(f.Args.Items) == 1 {
			s, ok := pgStringConst(f.Args.Items[0])
			return ok && likeMatchesAll(s)
		}
	case ast.AEXPR_OP:
		if op == "~" || op == "~*" {
			s, ok := pgStringConst(n.Rexpr)
			return ok && regexMatchesAll(s)
		}
	case ast.AEXPR_IN:
		if l, ok := n.Rexpr.(*ast.NodeList); ok && op == "=" && n.Lexpr != nil {
			for _, item := range l.Items {
				if item != nil && item.SqlString() == n.Lexpr.SqlString() {
					return true // id IN (id, 7)
				}
			}
		}
	}
	return false
}

func pgNullConst(n ast.Node) bool {
	c, ok := n.(*ast.A_Const)
	return ok && c.Isnull
}

func pgStringConst(n ast.Node) (string, bool) {
	c, ok := n.(*ast.A_Const)
	if !ok || c.Isnull {
		return "", false
	}
	s, ok := c.Val.(*ast.String)
	if !ok {
		return "", false
	}
	return s.SVal, true
}

// pgReadsOuter reports whether n reads a column of the statement's own
// rows: any column outside a subquery, and inside one any column that is
// not qualified with a table of that subquery. An unqualified name in a
// subquery may be the outer table's (when the inner tables have no such
// column), so it counts.
func pgReadsOuter(n ast.Node, outer map[string]bool) bool {
	reads := false
	ast.Rewrite(n, func(c *ast.Cursor) bool {
		if reads {
			return false
		}
		switch x := c.Node().(type) {
		case *ast.ColumnRef, *ast.CurrentOfExpr:
			reads = true
			return false
		case *ast.SubLink:
			if x.Testexpr != nil && pgReadsOuter(x.Testexpr, outer) {
				reads = true
			} else if x.Subselect != nil && pgSubqueryReadsOuter(x.Subselect, outer) {
				reads = true
			}
			return false
		}
		return true
	}, nil)
	return reads
}

// pgSubqueryReadsOuter reports whether a subquery refers to the outer
// statement's rows: a column reference that is unqualified, or qualified
// with the outer table, or with a name the subquery does not define.
func pgSubqueryReadsOuter(sub ast.Node, outer map[string]bool) bool {
	inner := map[string]bool{}
	ast.Rewrite(sub, func(c *ast.Cursor) bool {
		switch x := c.Node().(type) {
		case *ast.RangeVar:
			inner[strings.ToLower(x.RelName)] = true
			if x.Alias != nil {
				inner[strings.ToLower(x.Alias.AliasName)] = true
			}
		case *ast.RangeSubselect:
			if x.Alias != nil {
				inner[strings.ToLower(x.Alias.AliasName)] = true
			}
		case *ast.CommonTableExpr:
			inner[strings.ToLower(x.Ctename)] = true
		}
		return true
	}, nil)
	reads := false
	ast.Rewrite(sub, func(c *ast.Cursor) bool {
		if reads {
			return false
		}
		switch x := c.Node().(type) {
		case *ast.CurrentOfExpr:
			reads = true
		case *ast.ColumnRef:
			var parts []string
			if x.Fields != nil {
				for _, f := range x.Fields.Items {
					if s, ok := f.(*ast.String); ok {
						parts = append(parts, strings.ToLower(s.SVal))
					} else {
						parts = append(parts, "*")
					}
				}
			}
			if len(parts) < 2 {
				reads = true // unqualified: may be the outer table's column
				break
			}
			q := parts[len(parts)-2] // the table: a.id, s.a.id, a.*
			if outer[q] || !inner[q] {
				reads = true
			}
		}
		return !reads
	}, nil)
	return reads
}

// likeMatchesAll reports whether a LIKE or SIMILAR TO pattern matches
// every string: it is made of % only.
func likeMatchesAll(p string) bool {
	return p != "" && strings.Trim(p, "%") == ""
}

// regexMatchesAll reports whether a regular expression matches every
// string, in the spellings that say so outright.
func regexMatchesAll(p string) bool {
	switch p {
	case "", "^", "$", ".*", "^.*", ".*$", "^.*$", "(?:)", "()":
		return true
	}
	return false
}

// explainAnalyze reports whether EXPLAIN's options run the statement:
// ANALYZE, unless set to false, off or 0.
func explainAnalyze(opts *ast.NodeList) bool {
	if opts == nil {
		return false
	}
	on := false
	for _, o := range opts.Items {
		d, ok := o.(*ast.DefElem)
		if !ok || !strings.EqualFold(d.Defname, "analyze") {
			continue
		}
		on = !falseOption(d.Arg)
	}
	return on
}

// securityDefiner reports whether function options include SECURITY
// DEFINER, which runs the function with its owner's privileges.
func securityDefiner(opts *ast.NodeList) bool {
	if opts == nil {
		return false
	}
	for _, o := range opts.Items {
		if d, ok := o.(*ast.DefElem); ok && strings.EqualFold(d.Defname, "security") && !falseOption(d.Arg) {
			return true
		}
	}
	return false
}

// falseOption reports whether an option's value turns it off. No value
// turns it on.
func falseOption(arg ast.Node) bool {
	switch v := arg.(type) {
	case *ast.Boolean:
		return !v.BoolVal
	case *ast.Integer:
		return v.IVal == 0
	case *ast.String:
		switch strings.ToLower(v.SVal) {
		case "false", "off", "0", "no":
			return true
		}
	}
	return false
}
