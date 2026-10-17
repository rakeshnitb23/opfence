package decode

import (
	"strings"
	"unicode"

	"github.com/rakeshnitb23/opfence/internal/classes"
)

// ClassifySQL classifies Postgres SQL text for tools like Supabase's
// execute_sql. It returns the distinct classes of its statements, in order;
// the engine decides each and takes the strictest decision.
//
// This is a tokenizer, not a parser (docs/ARCHITECTURE.md §3.4). It strips
// comments and literals, splits statements on semicolons and classifies by
// keywords. Anything it does not recognise, or cannot tokenize, is unknown.
func ClassifySQL(sql string) []classes.Class {
	toks, ok := sqlTokenize(sql)
	if !ok {
		return []classes.Class{classes.Unknown}
	}
	var out []classes.Class
	seen := map[classes.Class]bool{}
	add := func(cs ...classes.Class) {
		for _, c := range cs {
			if !seen[c] {
				seen[c] = true
				out = append(out, c)
			}
		}
	}
	for _, stmt := range splitStatements(toks) {
		add(classifyStatement(stmt)...)
	}
	if len(out) == 0 {
		return []classes.Class{classes.Read}
	}
	return out
}

type tokKind int

const (
	tkWord   tokKind = iota // keyword or bare identifier, upper-cased
	tkQuoted                // "quoted identifier"
	tkString                // string literal (any quoting)
	tkNumber
	tkPunct
)

type sqlTok struct {
	kind tokKind
	text string
}

func (t sqlTok) is(words ...string) bool {
	if t.kind != tkWord {
		return false
	}
	for _, w := range words {
		if t.text == w {
			return true
		}
	}
	return false
}

func (t sqlTok) punct(p string) bool { return t.kind == tkPunct && t.text == p }

// sqlTokenize splits SQL into tokens, dropping whitespace and comments. It
// reports false on an unterminated comment, string or quoted identifier.
func sqlTokenize(s string) ([]sqlTok, bool) {
	var toks []sqlTok
	rs := []rune(s)
	n := len(rs)
	for i := 0; i < n; {
		c := rs[i]
		switch {
		case unicode.IsSpace(c):
			i++
		case c == '-' && i+1 < n && rs[i+1] == '-':
			for i < n && rs[i] != '\n' {
				i++
			}
		case c == '/' && i+1 < n && rs[i+1] == '*':
			depth := 0
			for {
				if i+1 >= n {
					return nil, false
				}
				if rs[i] == '/' && rs[i+1] == '*' {
					depth++
					i += 2
					continue
				}
				if rs[i] == '*' && rs[i+1] == '/' {
					depth--
					i += 2
					if depth == 0 {
						break
					}
					continue
				}
				i++
			}
		case c == '\'' || ((c == 'E' || c == 'e') && i+1 < n && rs[i+1] == '\''):
			escapes := c != '\''
			if escapes {
				i++
			}
			i++
			var b strings.Builder
			for {
				if i >= n {
					return nil, false
				}
				if escapes && rs[i] == '\\' && i+1 < n {
					b.WriteRune(rs[i+1])
					i += 2
					continue
				}
				if rs[i] == '\'' {
					if i+1 < n && rs[i+1] == '\'' {
						b.WriteRune('\'')
						i += 2
						continue
					}
					i++
					break
				}
				b.WriteRune(rs[i])
				i++
			}
			toks = append(toks, sqlTok{tkString, b.String()})
		case c == '$' && i+1 < n && (rs[i+1] == '$' || isIdentStart(rs[i+1])):
			// Dollar quoting: $tag$ ... $tag$. A bare $1 is a parameter.
			j := i + 1
			for j < n && rs[j] != '$' && isIdentPart(rs[j]) {
				j++
			}
			if j >= n || rs[j] != '$' {
				toks = append(toks, sqlTok{tkPunct, "$"})
				i++
				continue
			}
			tag := string(rs[i : j+1])
			end := strings.Index(string(rs[j+1:]), tag)
			if end < 0 {
				return nil, false
			}
			body := string(rs[j+1:])[:end]
			toks = append(toks, sqlTok{tkString, body})
			i = j + 1 + len([]rune(body)) + len([]rune(tag))
		case c == '"':
			i++
			var b strings.Builder
			for {
				if i >= n {
					return nil, false
				}
				if rs[i] == '"' {
					if i+1 < n && rs[i+1] == '"' {
						b.WriteRune('"')
						i += 2
						continue
					}
					i++
					break
				}
				b.WriteRune(rs[i])
				i++
			}
			toks = append(toks, sqlTok{tkQuoted, b.String()})
		case isIdentStart(c):
			j := i
			for j < n && isIdentPart(rs[j]) {
				j++
			}
			toks = append(toks, sqlTok{tkWord, strings.ToUpper(string(rs[i:j]))})
			i = j
		case c >= '0' && c <= '9':
			j := i
			for j < n && (unicode.IsDigit(rs[j]) || rs[j] == '.' || rs[j] == 'e' || rs[j] == 'E' || rs[j] == '_') {
				j++
			}
			toks = append(toks, sqlTok{tkNumber, string(rs[i:j])})
			i = j
		default:
			toks = append(toks, sqlTok{tkPunct, string(c)})
			i++
		}
	}
	return toks, true
}

func isIdentStart(c rune) bool { return c == '_' || unicode.IsLetter(c) }
func isIdentPart(c rune) bool {
	return c == '_' || c == '$' || unicode.IsLetter(c) || unicode.IsDigit(c)
}

func splitStatements(toks []sqlTok) [][]sqlTok {
	var out [][]sqlTok
	start := 0
	for i, t := range toks {
		if t.punct(";") {
			if i > start {
				out = append(out, toks[start:i])
			}
			start = i + 1
		}
	}
	if start < len(toks) {
		out = append(out, toks[start:])
	}
	return out
}

// Functions whose side effects a SELECT can hide.
var sqlDangerousFuncs = map[string]bool{
	"PG_TERMINATE_BACKEND": true, "PG_CANCEL_BACKEND": true, "PG_DROP_REPLICATION_SLOT": true,
	"LO_UNLINK": true, "LO_IMPORT": true, "LO_EXPORT": true, "LO_FROM_BYTEA": true, "LO_PUT": true,
	"DBLINK": true, "DBLINK_EXEC": true, "DBLINK_CONNECT": true,
	"PG_RELOAD_CONF": true, "PG_ROTATE_LOGFILE": true, "PG_PROMOTE": true,
	"PG_READ_FILE": true, "PG_READ_BINARY_FILE": true, "PG_LS_DIR": true, "PG_STAT_FILE": true,
	"SET_CONFIG": true, "PG_ADVISORY_LOCK": true, "QUERY_TO_XML": true,
	"HTTP": true, "HTTP_GET": true, "HTTP_POST": true, "NET.HTTP_POST": true,
}

func classifyStatement(st []sqlTok) []classes.Class {
	if len(st) == 0 {
		return nil
	}
	one := func(c classes.Class) []classes.Class { return []classes.Class{c} }
	first := st[0]
	if first.punct("(") {
		// (SELECT ...) UNION ...: classify as a query.
		return classifySelect(st)
	}
	if first.kind != tkWord {
		return one(classes.Unknown)
	}
	switch first.text {
	case "SELECT", "TABLE", "VALUES":
		return classifySelect(st)
	case "WITH":
		return classifyWith(st)
	case "EXPLAIN":
		return classifyExplain(st)
	case "SHOW", "FETCH", "MOVE", "CLOSE", "LISTEN", "UNLISTEN", "DEALLOCATE", "DISCARD", "RESET",
		"BEGIN", "START", "COMMIT", "END", "ROLLBACK", "ABORT", "SAVEPOINT", "RELEASE":
		return one(classes.Read)
	case "DECLARE":
		// DECLARE c CURSOR FOR <query>
		for i, t := range st {
			if t.is("FOR") && i+1 < len(st) {
				return classifyStatement(st[i+1:])
			}
		}
		return one(classes.Unknown)
	case "SET":
		return classifySet(st)
	case "INSERT":
		return one(classes.Write)
	case "UPDATE":
		if hasEffectiveWhere(st) {
			return one(classes.Write)
		}
		return one(classes.Irreversible)
	case "DELETE":
		if hasEffectiveWhere(st) {
			return one(classes.Delete)
		}
		return one(classes.Irreversible)
	case "MERGE":
		if containsWord(st, "DELETE") {
			return one(classes.Delete)
		}
		return one(classes.Write)
	case "TRUNCATE":
		return one(classes.Irreversible)
	case "DROP":
		if len(st) > 1 && st[1].is("ROLE", "USER", "GROUP", "POLICY") {
			return one(classes.Access)
		}
		return one(classes.Irreversible)
	case "CREATE":
		rest := st[1:]
		if len(rest) > 1 && rest[0].is("OR") && rest[1].is("REPLACE") {
			rest = rest[2:]
		}
		if len(rest) > 0 && rest[0].is("ROLE", "USER", "GROUP", "POLICY") {
			return one(classes.Access)
		}
		return one(classes.Write)
	case "ALTER":
		return classifyAlter(st)
	case "GRANT", "REVOKE", "REASSIGN":
		return one(classes.Access)
	case "SECURITY":
		return one(classes.Access) // SECURITY LABEL
	case "COPY":
		switch {
		case containsWord(st, "PROGRAM"):
			return one(classes.Unknown)
		case containsWord(st, "FROM"):
			return one(classes.Write)
		case containsWord(st, "STDOUT"):
			return one(classes.Read)
		}
		return one(classes.Unknown)
	case "COMMENT", "VACUUM", "ANALYZE", "ANALYSE", "REINDEX", "CLUSTER", "REFRESH", "LOCK",
		"NOTIFY", "CHECKPOINT", "IMPORT":
		return one(classes.Write)
	}
	// DO, CALL, EXECUTE, PREPARE, LOAD and anything else.
	return one(classes.Unknown)
}

func classifySelect(st []sqlTok) []classes.Class {
	depth := 0
	for i, t := range st {
		switch {
		case t.punct("("):
			depth++
		case t.punct(")"):
			depth--
		case t.is("INTO") && depth == 0:
			return []classes.Class{classes.Write} // SELECT ... INTO new_table
		case t.kind == tkWord && i+1 < len(st) && st[i+1].punct("("):
			if sqlDangerousFuncs[t.text] {
				return []classes.Class{classes.Unknown}
			}
		case t.kind == tkWord && i+3 < len(st) && st[i+1].punct(".") && st[i+3].punct("("):
			if sqlDangerousFuncs[t.text+"."+st[i+2].text] || sqlDangerousFuncs[st[i+2].text] {
				return []classes.Class{classes.Unknown}
			}
		}
	}
	return []classes.Class{classes.Read}
}

// classifyWith classifies each CTE body and the main statement. Postgres
// runs data-modifying CTEs even when the main statement is a SELECT.
func classifyWith(st []sqlTok) []classes.Class {
	i := 1
	if i < len(st) && st[i].is("RECURSIVE") {
		i++
	}
	var out []classes.Class
	for {
		// name [ (columns) ] AS [ [NOT] MATERIALIZED ] ( body )
		if i >= len(st) || (st[i].kind != tkWord && st[i].kind != tkQuoted) {
			return []classes.Class{classes.Unknown}
		}
		i++
		if i < len(st) && st[i].punct("(") {
			end := matchParen(st, i)
			if end < 0 {
				return []classes.Class{classes.Unknown}
			}
			i = end + 1
		}
		if i >= len(st) || !st[i].is("AS") {
			return []classes.Class{classes.Unknown}
		}
		i++
		if i < len(st) && st[i].is("NOT") {
			i++
		}
		if i < len(st) && st[i].is("MATERIALIZED") {
			i++
		}
		if i >= len(st) || !st[i].punct("(") {
			return []classes.Class{classes.Unknown}
		}
		end := matchParen(st, i)
		if end < 0 {
			return []classes.Class{classes.Unknown}
		}
		body := classifyStatement(st[i+1 : end])
		if body == nil {
			return []classes.Class{classes.Unknown}
		}
		out = append(out, body...)
		i = end + 1
		// SEARCH / CYCLE clauses of recursive CTEs are not supported.
		if i < len(st) && st[i].punct(",") {
			i++
			continue
		}
		break
	}
	if i >= len(st) {
		return []classes.Class{classes.Unknown}
	}
	return append(out, classifyStatement(st[i:])...)
}

func classifyExplain(st []sqlTok) []classes.Class {
	analyze := false
	i := 1
	if i < len(st) && st[i].punct("(") {
		end := matchParen(st, i)
		if end < 0 {
			return []classes.Class{classes.Unknown}
		}
		for j := i + 1; j < end; j++ {
			if st[j].is("ANALYZE", "ANALYSE") {
				// ANALYZE [true|on|1] enables; ANALYZE false|off|0 disables.
				analyze = !(j+1 < end && (st[j+1].is("FALSE", "OFF") || (st[j+1].kind == tkNumber && st[j+1].text == "0")))
			}
		}
		i = end + 1
	}
	for i < len(st) && st[i].is("ANALYZE", "ANALYSE", "VERBOSE") {
		if st[i].is("ANALYZE", "ANALYSE") {
			analyze = true
		}
		i++
	}
	if i >= len(st) {
		return []classes.Class{classes.Unknown}
	}
	if !analyze {
		return []classes.Class{classes.Read}
	}
	return classifyStatement(st[i:]) // EXPLAIN ANALYZE runs the statement
}

func classifySet(st []sqlTok) []classes.Class {
	rest := st[1:]
	if len(rest) > 0 && rest[0].is("SESSION", "LOCAL") {
		rest = rest[1:]
	}
	if len(rest) > 0 {
		switch {
		case rest[0].is("ROLE", "AUTHORIZATION"),
			rest[0].is("SESSION_REPLICATION_ROLE", "ROW_SECURITY"),
			rest[0].is("SESSION") && len(rest) > 1 && rest[1].is("AUTHORIZATION"):
			return []classes.Class{classes.Access}
		}
	}
	return []classes.Class{classes.Read}
}

func classifyAlter(st []sqlTok) []classes.Class {
	if len(st) < 2 {
		return []classes.Class{classes.Unknown}
	}
	switch {
	case st[1].is("ROLE", "USER", "GROUP", "POLICY"):
		return []classes.Class{classes.Access}
	case st[1].is("DEFAULT") && len(st) > 2 && st[2].is("PRIVILEGES"):
		return []classes.Class{classes.Access}
	case st[1].is("SYSTEM"):
		return []classes.Class{classes.Unknown}
	}
	out := []classes.Class{classes.Write}
	for i := 2; i < len(st); i++ {
		t := st[i]
		switch {
		case t.is("OWNER") && i+1 < len(st) && st[i+1].is("TO"):
			out = append(out, classes.Access)
		case t.is("ROW") && i+2 < len(st) && st[i+1].is("LEVEL") && st[i+2].is("SECURITY") && i > 0 && st[i-1].is("DISABLE", "FORCE", "NO"):
			if st[i-1].is("DISABLE") || (st[i-1].is("FORCE") && i > 1 && st[i-2].is("NO")) {
				out = append(out, classes.Access)
			}
		case t.is("DROP"):
			next := ""
			if i+1 < len(st) {
				next = st[i+1].text
			}
			switch next {
			case "CONSTRAINT", "DEFAULT", "NOT", "IDENTITY", "EXPRESSION":
			default:
				// DROP COLUMN, DROP <column>, DROP ATTRIBUTE, DROP VALUE ...
				out = append(out, classes.Irreversible)
			}
		}
	}
	return out
}

// hasEffectiveWhere reports whether an UPDATE or DELETE has a top-level
// WHERE clause that is not a literal tautology such as WHERE true or
// WHERE 1 = 1.
func hasEffectiveWhere(st []sqlTok) bool {
	depth := 0
	for i, t := range st {
		switch {
		case t.punct("("):
			depth++
		case t.punct(")"):
			depth--
		case depth == 0 && t.is("WHERE"):
			if i+1 < len(st) && st[i+1].is("CURRENT") {
				return true // WHERE CURRENT OF cursor
			}
			var cond []sqlTok
			for _, c := range st[i+1:] {
				if c.is("RETURNING") {
					break
				}
				cond = append(cond, c)
			}
			return !tautology(cond)
		}
	}
	return false
}

func tautology(c []sqlTok) bool {
	for len(c) >= 2 && c[0].punct("(") && c[len(c)-1].punct(")") && matchParen(c, 0) == len(c)-1 {
		c = c[1 : len(c)-1]
	}
	switch {
	case len(c) == 0:
		return true
	case len(c) == 1:
		return c[0].is("TRUE") || (c[0].kind == tkString && strings.EqualFold(c[0].text, "t"))
	case len(c) == 3 && c[1].punct("="):
		return (c[0].kind == tkNumber || c[0].kind == tkString) && c[0].kind == c[2].kind && c[0].text == c[2].text
	case len(c) == 2 && c[0].is("NOT"):
		return c[1].is("FALSE")
	}
	return false
}

func matchParen(st []sqlTok, open int) int {
	depth := 0
	for i := open; i < len(st); i++ {
		switch {
		case st[i].punct("("):
			depth++
		case st[i].punct(")"):
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

func containsWord(st []sqlTok, w string) bool {
	for _, t := range st {
		if t.is(w) {
			return true
		}
	}
	return false
}
