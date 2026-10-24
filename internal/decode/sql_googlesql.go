package decode

import (
	"errors"
	"slices"
	"strings"

	"github.com/rakeshnitb23/opfence/internal/classes"
)

// GoogleSQL is BigQuery's and Spanner's SQL (stage 27c). No pure Go parser
// reads all of it (memefish reads Spanner's but not BigQuery's window
// functions, MERGE, TRUNCATE or scripts), so Opfence reads it the way it
// needs to: a lexer that follows GoogleSQL's quoting and comment rules, so
// statement boundaries are where BigQuery puts them, and a classifier that
// looks at each statement's leading keywords, its WHERE clause and the
// functions it calls. What it does not recognise is unknown.
//
// Lexing follows the GoogleSQL lexical reference: strings in single,
// double or triple quotes, where a backslash always takes the next
// character with it (in raw strings too, which cannot end in a lone
// backslash); single-quoted strings cannot span lines; backtick-quoted
// identifiers; comments with #, -- and non-nesting /* */; @param, @@var
// and ? parameters. Anything else (a stray $, characters outside ASCII
// outside quotes, an unterminated string or comment) fails the parse.

type gsqlKind int

const (
	gsqlIdent  gsqlKind = iota // unquoted identifier or keyword
	gsqlQIdent                 // `quoted identifier`, text without the backticks
	gsqlString                 // string or bytes literal
	gsqlNumber
	gsqlParam // @name, @@name or ?
	gsqlPunct // operators and punctuation
)

type gsqlTok struct {
	kind gsqlKind
	text string // as written for idents and punctuation; the content of a quoted identifier
	up   string // upper-case text of an unquoted identifier
}

var errGSQL = errors.New("GoogleSQL does not lex")

func gsqlLex(s string) ([]gsqlTok, error) {
	var toks []gsqlTok
	i := 0
	for i < len(s) {
		c := s[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v':
			i++
		case c == '#' || (c == '-' && i+1 < len(s) && s[i+1] == '-'):
			for i < len(s) && s[i] != '\n' {
				i++
			}
		case c == '/' && i+1 < len(s) && s[i+1] == '*':
			end := strings.Index(s[i+2:], "*/")
			if end < 0 {
				return nil, errGSQL
			}
			i += 2 + end + 2
		case c == '`':
			j, text, err := gsqlQuoted(s, i, "`", false)
			if err != nil || text == "" {
				return nil, errGSQL
			}
			toks = append(toks, gsqlTok{kind: gsqlQIdent, text: text})
			i = j
		case c == '\'' || c == '"' || ((c == 'r' || c == 'R' || c == 'b' || c == 'B') && gsqlStringPrefix(s, i)):
			raw := false
			for s[i] != '\'' && s[i] != '"' {
				raw = raw || s[i] == 'r' || s[i] == 'R'
				i++
			}
			q := string(s[i])
			if strings.HasPrefix(s[i:], q+q+q) {
				q = q + q + q
			}
			j, text, err := gsqlQuoted(s, i, q, raw)
			if err != nil {
				return nil, errGSQL
			}
			toks = append(toks, gsqlTok{kind: gsqlString, text: text})
			i = j
		case c == '_' || isLetter(c):
			j := i
			for j < len(s) && (s[j] == '_' || isLetter(s[j]) || isDigit(s[j])) {
				j++
			}
			toks = append(toks, gsqlTok{kind: gsqlIdent, text: s[i:j], up: strings.ToUpper(s[i:j])})
			i = j
		case isDigit(c) || (c == '.' && i+1 < len(s) && isDigit(s[i+1]) && (len(toks) == 0 || toks[len(toks)-1].kind == gsqlPunct)):
			j := i + 1
			for j < len(s) && (isDigit(s[j]) || isLetter(s[j]) || s[j] == '_' || s[j] == '.' ||
				((s[j] == '+' || s[j] == '-') && (s[j-1] == 'e' || s[j-1] == 'E'))) {
				j++
			}
			toks = append(toks, gsqlTok{kind: gsqlNumber, text: s[i:j]})
			i = j
		case c == '@' || c == '?':
			j := i + 1
			if c == '@' {
				if j < len(s) && s[j] == '@' {
					j++
				}
				k := j
				for j < len(s) && (s[j] == '_' || isLetter(s[j]) || isDigit(s[j])) {
					j++
				}
				if j == k {
					return nil, errGSQL
				}
			}
			toks = append(toks, gsqlTok{kind: gsqlParam, text: s[i:j]})
			i = j
		default:
			op := gsqlOperator(s[i:])
			if op == "" {
				return nil, errGSQL
			}
			toks = append(toks, gsqlTok{kind: gsqlPunct, text: op})
			i += len(op)
		}
	}
	return toks, nil
}

func isLetter(c byte) bool { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }
func isDigit(c byte) bool  { return c >= '0' && c <= '9' }

// gsqlStringPrefix reports whether s[i:] starts a prefixed literal: r, b,
// rb or br in either case, then a quote.
func gsqlStringPrefix(s string, i int) bool {
	if i > 0 && (s[i-1] == '_' || isLetter(s[i-1]) || isDigit(s[i-1])) {
		return false
	}
	j := i
	for j < len(s) && j < i+2 && strings.IndexByte("rRbB", s[j]) >= 0 {
		j++
	}
	if j-i == 2 && strings.EqualFold(s[i:i+1], s[i+1:i+2]) {
		return false // rr, bb
	}
	return j < len(s) && (s[j] == '\'' || s[j] == '"')
}

// gsqlQuoted reads a quoted token starting at s[i], whose quote is q (one
// character or three). A backslash takes the next character with it, so an
// escaped quote never ends the token, in raw strings too. It returns the
// index after the closing quote and the content (escapes kept as written
// in raw strings and identifiers, undone for the common ones otherwise).
func gsqlQuoted(s string, i int, q string, raw bool) (int, string, error) {
	j := i + len(q)
	var b strings.Builder
	for j < len(s) {
		switch {
		case s[j] == '\\':
			if j+1 >= len(s) {
				return 0, "", errGSQL
			}
			if raw {
				b.WriteString(s[j : j+2])
			} else {
				b.WriteByte(gsqlUnescape(s[j+1]))
			}
			j += 2
		case strings.HasPrefix(s[j:], q):
			return j + len(q), b.String(), nil
		case s[j] == '\n' && len(q) == 1:
			return 0, "", errGSQL // only triple-quoted strings span lines
		default:
			b.WriteByte(s[j])
			j++
		}
	}
	return 0, "", errGSQL
}

func gsqlUnescape(c byte) byte {
	switch c {
	case 'n':
		return '\n'
	case 't':
		return '\t'
	case 'r':
		return '\r'
	}
	return c
}

var gsqlOperators = []string{"<<=", ">>=", "<=>", "<>", "<=", ">=", "!=", "||", "<<", ">>", "=>", "->",
	"(", ")", "[", "]", "{", "}", ",", ";", ".", "+", "-", "*", "/", "%", "=", "<", ">", "!", "|", "&", "^", "~", ":"}

func gsqlOperator(s string) string {
	for _, op := range gsqlOperators {
		if strings.HasPrefix(s, op) {
			return op
		}
	}
	return ""
}

// gsqlStatements splits tokens into statements at semicolons outside
// brackets.
func gsqlStatements(toks []gsqlTok) [][]gsqlTok {
	var out [][]gsqlTok
	depth, start := 0, 0
	for i, t := range toks {
		if t.kind != gsqlPunct {
			continue
		}
		switch t.text {
		case "(", "[", "{":
			depth++
		case ")", "]", "}":
			depth--
		case ";":
			if depth <= 0 {
				if i > start {
					out = append(out, toks[start:i])
				}
				start = i + 1
			}
		}
	}
	if start < len(toks) {
		out = append(out, toks[start:])
	}
	return out
}

func (t gsqlTok) is(kw string) bool   { return t.kind == gsqlIdent && t.up == kw }
func (t gsqlTok) punct(p string) bool { return t.kind == gsqlPunct && t.text == p }

// gsqlStmt is one statement being read.
type gsqlStmt []gsqlTok

func (s gsqlStmt) kw(i int, kws ...string) bool {
	for k, kw := range kws {
		if i+k >= len(s) || !s[i+k].is(kw) {
			return false
		}
	}
	return true
}

// ClassifyGoogleSQL classifies GoogleSQL text (BigQuery, Spanner). It
// returns the distinct classes of its statements; SQL that does not lex, a
// script with control flow, and statements it does not know are unknown.
func ClassifyGoogleSQL(sql string) []classes.Class {
	stmts, ok := gsqlParse(sql)
	if !ok {
		return []classes.Class{classes.Unknown}
	}
	var out []classes.Class
	for _, st := range stmts {
		for _, c := range st.classes {
			if !slices.Contains(out, c) {
				out = append(out, c)
			}
		}
	}
	if len(out) == 0 {
		return []classes.Class{classes.Read}
	}
	return out
}

func summarizeGoogleSQL(sql string) []string {
	stmts, ok := gsqlParse(sql)
	if !ok {
		return nil
	}
	var out []string
	for _, st := range stmts {
		out = append(out, st.summary.String())
	}
	return out
}

type gsqlResult struct {
	classes []classes.Class
	summary sqlSummary
}

func gsqlParse(sql string) ([]gsqlResult, bool) {
	if len(sql) > maxSQL {
		return nil, false
	}
	toks, err := gsqlLex(sql)
	if err != nil {
		return nil, false
	}
	var out []gsqlResult
	for _, st := range gsqlStatements(toks) {
		r, ok := gsqlClassify(gsqlStmt(st))
		if !ok {
			return nil, false
		}
		out = append(out, r)
	}
	return out, true
}

// Statements that start control flow or run SQL from a string. Opfence does
// not follow a script's blocks, so a script with any of them is unknown.
var gsqlScripting = map[string]bool{"IF": true, "LOOP": true, "WHILE": true, "REPEAT": true, "FOR": true, "CASE": true,
	"EXECUTE": true, "CALL": true, "RAISE": true, "RETURN": true, "BREAK": true, "LEAVE": true, "CONTINUE": true,
	"ITERATE": true, "EXCEPTION": true, "END": true, "ELSE": true, "ELSEIF": true, "UNTIL": true, "WHEN": true}

// gsqlClassify classifies one statement. ok is false when the whole SQL
// must be unknown (scripting).
func gsqlClassify(s gsqlStmt) (gsqlResult, bool) {
	unknown := gsqlResult{classes: []classes.Class{classes.Unknown}, summary: sqlSummary{verb: "SQL Opfence cannot read"}}
	res := func(c classes.Class, sum sqlSummary) (gsqlResult, bool) {
		cls := []classes.Class{c}
		for _, x := range gsqlCalls(s) {
			if !slices.Contains(cls, x.class) {
				cls = append(cls, x.class)
			}
			sum.calls = append(sum.calls, x.name)
		}
		return gsqlResult{classes: cls, summary: sum}, true
	}
	if len(s) == 0 {
		return gsqlResult{}, true
	}
	first := s[0]
	if first.kind == gsqlIdent && gsqlScripting[first.up] {
		return gsqlResult{}, false
	}
	if first.punct("(") || first.is("SELECT") || first.is("WITH") || first.is("FROM") { // FROM … |> is pipe syntax
		return res(classes.Read, sqlSummary{verb: "SELECT", prep: "from", names: gsqlFromTables(s)})
	}
	if first.kind != gsqlIdent {
		return unknown, true
	}
	switch first.up {
	case "BEGIN":
		if len(s) == 1 || s.kw(1, "TRANSACTION") {
			return res(classes.Read, sqlSummary{verb: "BEGIN"})
		}
		return gsqlResult{}, false // a BEGIN … END block
	case "COMMIT", "ROLLBACK":
		return res(classes.Read, sqlSummary{verb: first.up})
	case "DECLARE", "SET":
		return res(classes.Read, sqlSummary{verb: first.up})
	case "ASSERT":
		return res(classes.Read, sqlSummary{verb: "ASSERT"})
	case "INSERT":
		i := 1
		if s.kw(i, "OR") { // Spanner: INSERT OR UPDATE / OR IGNORE
			i += 2
		}
		if s.kw(i, "INTO") {
			i++
		}
		return res(classes.Write, sqlSummary{verb: "INSERT", prep: "into", names: gsqlNames(s, i)})
	case "UPDATE":
		limited := gsqlWhereLimits(s, 1)
		c := classes.Write
		if !limited {
			c = classes.Irreversible
		}
		return res(c, sqlSummary{verb: "UPDATE", names: gsqlNames(s, 1), allRows: !limited})
	case "DELETE":
		i := 1
		if s.kw(i, "FROM") {
			i++
		}
		limited := gsqlWhereLimits(s, i)
		c := classes.Delete
		if !limited {
			c = classes.Irreversible
		}
		return res(c, sqlSummary{verb: "DELETE", prep: "from", names: gsqlNames(s, i), allRows: !limited})
	case "MERGE":
		i := 1
		if s.kw(i, "INTO") {
			i++
		}
		// The ON condition and the source decide how many rows a DELETE,
		// or an UPDATE of rows not in the source, reaches; Opfence does
		// not work that out, so either can reach every row.
		c := classes.Write
		for j := range s {
			if s.kw(j, "THEN", "DELETE") || (s.kw(j, "BY", "SOURCE") && gsqlThenUpdate(s, j)) {
				c = classes.Irreversible
			}
		}
		return res(c, sqlSummary{verb: "MERGE", prep: "into", names: gsqlNames(s, i)})
	case "TRUNCATE":
		i := 1
		if s.kw(i, "TABLE") {
			i++
		}
		return res(classes.Irreversible, sqlSummary{verb: "TRUNCATE TABLE", names: gsqlNames(s, i)})
	case "DROP":
		if s.kw(1, "ROW", "ACCESS", "POLICY") || s.kw(1, "ALL", "ROW", "ACCESS", "POLICIES") {
			return res(classes.Access, sqlSummary{verb: "DROP ROW ACCESS POLICY"})
		}
		verb, i := gsqlObjectWords(s, 1)
		return res(classes.Irreversible, sqlSummary{verb: "DROP " + verb, names: gsqlNames(s, gsqlSkipIfExists(s, i))})
	case "UNDROP":
		verb, i := gsqlObjectWords(s, 1)
		return res(classes.Write, sqlSummary{verb: "UNDROP " + verb, names: gsqlNames(s, gsqlSkipIfExists(s, i))})
	case "CREATE":
		return gsqlCreate(s, res)
	case "ALTER":
		return gsqlAlter(s, res)
	case "GRANT", "REVOKE":
		return res(classes.Access, sqlSummary{verb: first.up})
	case "EXPORT":
		// Writes data to the location the statement names, which can
		// belong to another project, as Cloud SQL's export is.
		verb, _ := gsqlObjectWords(s, 1)
		return res(classes.Access, sqlSummary{verb: "EXPORT " + verb})
	case "LOAD":
		if s.kw(1, "DATA", "OVERWRITE") {
			return res(classes.Irreversible, sqlSummary{verb: "LOAD DATA OVERWRITE", names: gsqlNames(s, 3)})
		}
		i := 2
		if s.kw(i, "INTO") {
			i++
		}
		return res(classes.Write, sqlSummary{verb: "LOAD DATA", prep: "into", names: gsqlNames(s, i)})
	}
	return unknown, true
}

// gsqlThenUpdate reports whether a WHEN NOT MATCHED BY SOURCE clause at j
// updates.
func gsqlThenUpdate(s gsqlStmt, j int) bool {
	for k := j; k < len(s); k++ {
		if s[k].is("WHEN") {
			return false
		}
		if s.kw(k, "THEN", "UPDATE") {
			return true
		}
	}
	return false
}

// Words that name what a DDL statement acts on, read until the object's
// name.
var gsqlObjectWord = map[string]bool{"TABLE": true, "VIEW": true, "SCHEMA": true, "DATABASE": true, "FUNCTION": true,
	"PROCEDURE": true, "MODEL": true, "SNAPSHOT": true, "MATERIALIZED": true, "EXTERNAL": true, "SEARCH": true,
	"VECTOR": true, "INDEX": true, "CAPACITY": true, "RESERVATION": true, "ASSIGNMENT": true, "AGGREGATE": true,
	"TEMP": true, "TEMPORARY": true, "OR": true, "REPLACE": true, "DATA": true, "METADATA": true, "CHANGE": true,
	"STREAM": true, "ROLE": true, "SEQUENCE": true, "UNIQUE": true, "NULL_FILTERED": true, "PROPERTY": true,
	"GRAPH": true, "LOCALITY": true, "GROUP": true, "PLACEMENT": true, "ORGANIZATION": true, "PROJECT": true,
	"CONNECTION": true, "PROTO": true, "BUNDLE": true, "ROW": true, "ACCESS": true, "POLICY": true, "ALL": true,
	"POLICIES": true}

// gsqlObjectWords reads the words after CREATE, DROP or ALTER that say what
// kind of object follows ("OR REPLACE TABLE"), and returns them with the
// index after them.
func gsqlObjectWords(s gsqlStmt, i int) (string, int) {
	var w []string
	for i < len(s) && s[i].kind == gsqlIdent && gsqlObjectWord[s[i].up] {
		w = append(w, s[i].up)
		i++
	}
	return strings.Join(w, " "), i
}

func gsqlSkipIfExists(s gsqlStmt, i int) int {
	switch {
	case s.kw(i, "IF", "NOT", "EXISTS"):
		return i + 3
	case s.kw(i, "IF", "EXISTS"):
		return i + 2
	}
	return i
}

func gsqlCreate(s gsqlStmt, res func(classes.Class, sqlSummary) (gsqlResult, bool)) (gsqlResult, bool) {
	words, i := gsqlObjectWords(s, 1)
	sum := sqlSummary{verb: "CREATE " + words, names: gsqlNames(s, gsqlSkipIfExists(s, i))}
	w := strings.Fields(words)
	has := func(x string) bool { return slices.Contains(w, x) }
	switch {
	case (has("ROW") && has("ACCESS")) || has("ROLE"):
		return res(classes.Access, sum)
	case has("CAPACITY") || has("RESERVATION") || has("ASSIGNMENT"):
		return res(classes.Money, sum) // reserved slots and commitments are billed
	case has("OR") && has("REPLACE") && has("TABLE") && !has("TEMP") && !has("TEMPORARY") && !has("EXTERNAL") && !has("FUNCTION"):
		// Replaces an existing table, with its data (a snapshot table is a
		// backup).
		return res(classes.Irreversible, sum)
	}
	if words == "" {
		return gsqlResult{classes: []classes.Class{classes.Unknown}, summary: sqlSummary{verb: "CREATE"}}, true
	}
	// A function or procedure is not run by being created; its body is not
	// read.
	if has("FUNCTION") || has("PROCEDURE") || (has("VIEW") && !has("MATERIALIZED")) {
		return gsqlResult{classes: []classes.Class{classes.Write}, summary: sum}, true
	}
	return res(classes.Write, sum)
}

// Options that make BigQuery delete data later, or shorten the window in
// which deleted data can be recovered.
var gsqlExpiryOptions = map[string]bool{"EXPIRATION_TIMESTAMP": true, "PARTITION_EXPIRATION_DAYS": true,
	"DEFAULT_TABLE_EXPIRATION_DAYS": true, "DEFAULT_PARTITION_EXPIRATION_DAYS": true, "MAX_TIME_TRAVEL_HOURS": true,
	"DEFAULT_MAX_TIME_TRAVEL_HOURS": true, "VERSION_RETENTION_PERIOD": true}

func gsqlAlter(s gsqlStmt, res func(classes.Class, sqlSummary) (gsqlResult, bool)) (gsqlResult, bool) {
	words, i := gsqlObjectWords(s, 1)
	sum := sqlSummary{verb: "ALTER " + words, names: gsqlNames(s, gsqlSkipIfExists(s, i))}
	w := strings.Fields(words)
	if slices.Contains(w, "CAPACITY") || slices.Contains(w, "RESERVATION") {
		return res(classes.Money, sum)
	}
	if slices.Contains(w, "ROW") || slices.Contains(w, "ROLE") {
		return res(classes.Access, sum)
	}
	if words == "" {
		return gsqlResult{classes: []classes.Class{classes.Unknown}, summary: sqlSummary{verb: "ALTER"}}, true
	}
	for j := i; j < len(s); j++ {
		if s.kw(j, "DROP", "COLUMN") || (s.kw(j, "DROP") && j+1 < len(s) && (s[j+1].kind == gsqlQIdent || (s[j+1].kind == gsqlIdent && !gsqlObjectWord[s[j+1].up] && s[j+1].up != "CONSTRAINT" && s[j+1].up != "PRIMARY" && s[j+1].up != "REPLICA" && s[j+1].up != "DEFAULT" && s[j+1].up != "NOT"))) {
			sum.verb += " DROP COLUMN"
			return res(classes.Irreversible, sum)
		}
		if s[j].kind == gsqlIdent && gsqlExpiryOptions[s[j].up] && j+1 < len(s) && s[j+1].punct("=") {
			return res(classes.Irreversible, sum)
		}
		// Spanner deletes rows a row deletion policy names, later.
		if (s.kw(j, "ADD") || s.kw(j, "REPLACE")) && s.kw(j+1, "ROW", "DELETION", "POLICY") {
			return res(classes.Irreversible, sum)
		}
	}
	return res(classes.Write, sum)
}

// gsqlNames reads the name at s[i], a path of identifiers joined by dots
// (and the dashes of a project ID), as one name.
func gsqlNames(s gsqlStmt, i int) []string {
	n, _ := gsqlPathAt(s, i)
	if n == "" {
		return nil
	}
	return []string{n}
}

func gsqlPathAt(s gsqlStmt, i int) (string, int) {
	var parts []string
	for i < len(s) {
		t := s[i]
		if t.kind != gsqlIdent && t.kind != gsqlQIdent && t.kind != gsqlNumber {
			break
		}
		if len(parts) == 0 && t.kind == gsqlIdent && gsqlReserved[t.up] {
			break
		}
		part := t.text
		i++
		// my-project.dataset.table: dashes join unquoted parts.
		for i+1 < len(s) && s[i].punct("-") && (s[i+1].kind == gsqlIdent || s[i+1].kind == gsqlNumber) && t.kind != gsqlQIdent {
			part += "-" + s[i+1].text
			i += 2
		}
		parts = append(parts, strings.Split(part, ".")...)
		if i < len(s) && s[i].punct(".") {
			i++
			continue
		}
		break
	}
	if len(parts) == 0 {
		return "", i
	}
	return sqlName(parts...), i
}

// gsqlFromTables lists the tables a query reads, after FROM and JOIN at
// any depth.
func gsqlFromTables(s gsqlStmt) []string {
	var out []string
	for i := 0; i+1 < len(s); i++ {
		if s[i].is("FROM") || s[i].is("JOIN") {
			if n, j := gsqlPathAt(s, i+1); n != "" && !(j < len(s) && s[j].punct("(")) {
				out = append(out, n)
			}
		}
	}
	return out
}

// Keywords that cannot start a name, so "DELETE FROM WHERE" has none.
var gsqlReserved = map[string]bool{"ALL": true, "AND": true, "ANY": true, "ARRAY": true, "AS": true, "ASC": true,
	"BETWEEN": true, "BY": true, "CASE": true, "CAST": true, "CROSS": true, "CURRENT": true, "DEFAULT": true,
	"DESC": true, "DISTINCT": true, "ELSE": true, "END": true, "EXCEPT": true, "EXISTS": true, "EXTRACT": true,
	"FALSE": true, "FOR": true, "FROM": true, "FULL": true, "GROUP": true, "HAVING": true, "IF": true, "IN": true,
	"INNER": true, "INTERSECT": true, "INTERVAL": true, "INTO": true, "IS": true, "JOIN": true, "LEFT": true,
	"LIKE": true, "LIMIT": true, "NOT": true, "NULL": true, "ON": true, "OR": true, "ORDER": true, "OUTER": true,
	"RIGHT": true, "SELECT": true, "SET": true, "SOME": true, "STRUCT": true, "THEN": true, "TRUE": true,
	"UNION": true, "UNNEST": true, "USING": true, "WHEN": true, "WHERE": true, "WINDOW": true, "WITH": true,
	"NEW": true, "NULLS": true, "OVER": true, "PARTITION": true, "QUALIFY": true, "RANGE": true, "ROWS": true,
	"TABLESAMPLE": true, "TREAT": true, "UNBOUNDED": true, "WITHIN": true, "LATERAL": true, "LOOKUP": true,
	"MERGE": true, "NATURAL": true, "NO": true, "PRECEDING": true, "FOLLOWING": true, "RECURSIVE": true,
	"RESPECT": true, "IGNORE": true, "ROLLUP": true, "CUBE": true, "GROUPING": true, "GROUPS": true, "HASH": true,
	"ENUM": true, "PROTO": true, "COLLATE": true, "CONTAINS": true, "DEFINE": true, "ESCAPE": true, "EXCLUDE": true,
	"FETCH": true, "TO": true, "AT": true, "ASSERT_ROWS_MODIFIED": true, "CREATE": true, "OF": true}

// gsqlCall is a function call that changes what a statement is.
type gsqlCall struct {
	name  string
	class classes.Class
}

// Functions that call a Cloud AI model or service, billed apart from the
// query.
var gsqlAIFunctions = map[string]bool{"ML.GENERATE_TEXT": true, "ML.GENERATE_EMBEDDING": true, "ML.GENERATE_TABLE": true,
	"ML.TRANSLATE": true, "ML.UNDERSTAND_TEXT": true, "ML.ANNOTATE_IMAGE": true, "ML.PROCESS_DOCUMENT": true,
	"ML.TRANSCRIBE": true}

// Namespaces of built-in functions; a dotted call outside them is a
// persistent function.
var gsqlBuiltinNamespaces = map[string]bool{"SAFE": true, "NET": true, "ML": true, "AI": true, "AEAD": true, "KEYS": true,
	"HLL_COUNT": true, "KLL_QUANTILES": true, "OBJ": true, "D3A_COUNT": true, "VECTOR": true, "APPENDS": true,
	"CHANGES": true}

// Tokens before a dotted name followed by "(" that make it a table, a
// definition or a table function rather than a call to a scalar function.
var gsqlNotACall = map[string]bool{"INTO": true, "TABLE": true, "VIEW": true, "FUNCTION": true, "PROCEDURE": true,
	"MODEL": true, "EXISTS": true, "INSERT": true, "UPDATE": true, "MERGE": true, "DELETE": true, "FROM": true,
	"JOIN": true, "SCHEMA": true, "INDEX": true, "ON": true, "CALL": true, "USING": true, "CLONE": true, "COPY": true,
	"OF": true, "REFERENCES": true}

// gsqlCalls finds the calls that make a statement stricter:
// EXTERNAL_QUERY (which runs SQL on another database), persistent
// functions (any of which may be a remote function that calls an HTTP
// endpoint) are unknown; Cloud AI functions are money; AEAD decryption,
// which returns the plain text of encrypted values, is credential.
func gsqlCalls(s gsqlStmt) []gsqlCall {
	var out []gsqlCall
	for i := 0; i+1 < len(s); i++ {
		if !s[i+1].punct("(") || (s[i].kind != gsqlIdent && s[i].kind != gsqlQIdent) {
			continue
		}
		// Walk back over the dotted name that ends at i.
		start := i
		for start >= 2 && s[start-1].punct(".") && (s[start-2].kind == gsqlIdent || s[start-2].kind == gsqlQIdent) {
			start -= 2
		}
		var parts, shown []string
		for k := start; k <= i; k += 2 {
			parts = append(parts, strings.Split(strings.ToUpper(s[k].text), ".")...)
			shown = append(shown, strings.Split(s[k].text, ".")...)
		}
		if parts[0] == "SAFE" && len(parts) > 1 {
			parts, shown = parts[1:], shown[1:]
		}
		name := strings.Join(parts, ".")
		if name == "EXTERNAL_QUERY" { // a table function, so after FROM
			out = append(out, gsqlCall{"EXTERNAL_QUERY", classes.Unknown})
			continue
		}
		if start > 0 && s[start-1].kind == gsqlIdent && gsqlNotACall[s[start-1].up] {
			continue
		}
		switch {
		case strings.HasPrefix(name, "AEAD.DECRYPT") || strings.HasPrefix(name, "DETERMINISTIC_DECRYPT"):
			out = append(out, gsqlCall{name, classes.Credential})
		case gsqlAIFunctions[name] || (len(parts) > 1 && parts[0] == "AI"):
			out = append(out, gsqlCall{name, classes.Money})
		case len(parts) > 1 && !gsqlBuiltinNamespaces[parts[0]]:
			out = append(out, gsqlCall{sqlName(shown...), classes.Unknown})
		}
	}
	return out
}

// gsqlWhereLimits reports whether the WHERE clause of an UPDATE or DELETE
// (searched for at depth 0 from i) limits the rows it changes, as
// effectiveWhere does for Postgres: it must read a column, outside a
// subquery, in a way that is not one of the tautologies Opfence knows. No
// WHERE limits nothing.
func gsqlWhereLimits(s gsqlStmt, i int) bool {
	depth := 0
	for j := i; j < len(s); j++ {
		switch {
		case s[j].punct("(") || s[j].punct("[") || s[j].punct("{"):
			depth++
		case s[j].punct(")") || s[j].punct("]") || s[j].punct("}"):
			depth--
		case depth == 0 && s[j].is("WHERE"):
			end := len(s)
			for k := j + 1; k < len(s); k++ {
				if s[k].is("THEN") && k+1 < len(s) && s[k+1].is("RETURN") { // Spanner's THEN RETURN
					end = k
					break
				}
			}
			return gsqlLimits(s[j+1 : end])
		}
	}
	return false
}

// gsqlLimits reports whether a boolean expression can leave rows out.
func gsqlLimits(e gsqlStmt) bool {
	e = gsqlTrimParens(e)
	if len(e) == 0 {
		return false
	}
	if parts := gsqlSplitAt(e, "OR"); len(parts) > 1 {
		for _, p := range parts {
			if !gsqlLimits(p) {
				return false
			}
		}
		return true
	}
	if parts := gsqlSplitAt(e, "AND"); len(parts) > 1 {
		for _, p := range parts {
			if gsqlLimits(p) {
				return true
			}
		}
		return false
	}
	if e[0].is("NOT") {
		inner := gsqlTrimParens(e[1:])
		// NOT col IS NULL is col IS NOT NULL.
		if n := len(inner); n >= 3 && inner[n-2].is("IS") && inner[n-1].is("NULL") {
			return false
		}
		return gsqlLimits(inner)
	}
	return gsqlPredicateLimits(e)
}

// gsqlTrimParens removes parentheses around a whole expression.
func gsqlTrimParens(e gsqlStmt) gsqlStmt {
	for len(e) >= 2 && e[0].punct("(") && e[len(e)-1].punct(")") && gsqlMatchingParen(e, 0) == len(e)-1 &&
		!(len(e) > 1 && (e[1].is("SELECT") || e[1].is("WITH"))) {
		e = e[1 : len(e)-1]
	}
	return e
}

func gsqlMatchingParen(e gsqlStmt, i int) int {
	depth := 0
	for j := i; j < len(e); j++ {
		switch {
		case e[j].punct("("):
			depth++
		case e[j].punct(")"):
			depth--
			if depth == 0 {
				return j
			}
		}
	}
	return -1
}

// gsqlSplitAt splits an expression at a keyword (AND, OR) outside brackets
// and CASE … END, keeping BETWEEN x AND y together.
func gsqlSplitAt(e gsqlStmt, kw string) []gsqlStmt {
	var out []gsqlStmt
	depth, cases, between, start := 0, 0, 0, 0
	for j, t := range e {
		switch {
		case t.punct("(") || t.punct("[") || t.punct("{"):
			depth++
		case t.punct(")") || t.punct("]") || t.punct("}"):
			depth--
		case depth > 0:
		case t.is("CASE"):
			cases++
		case t.is("END") && cases > 0:
			cases--
		case cases > 0:
		case t.is("BETWEEN"):
			between++
		case t.is("AND") && between > 0:
			between--
			continue
		case t.is(kw):
			out = append(out, e[start:j])
			start = j + 1
		}
	}
	return append(out, e[start:])
}

// Keywords and literals that are not columns.
var gsqlNotColumn = map[string]bool{"TRUE": true, "FALSE": true, "NULL": true, "IS": true, "NOT": true, "IN": true,
	"LIKE": true, "BETWEEN": true, "AND": true, "OR": true, "CASE": true, "WHEN": true, "THEN": true, "ELSE": true,
	"END": true, "CAST": true, "SAFE_CAST": true, "AS": true, "INTERVAL": true, "DATE": true, "TIME": true,
	"DATETIME": true, "TIMESTAMP": true, "NUMERIC": true, "BIGNUMERIC": true, "JSON": true, "RANGE": true,
	"CURRENT_DATE": true, "CURRENT_TIME": true, "CURRENT_DATETIME": true, "CURRENT_TIMESTAMP": true, "EXISTS": true,
	"ANY": true, "ALL": true, "SOME": true, "UNNEST": true, "ARRAY": true, "STRUCT": true, "DISTINCT": true,
	"FROM": true, "UNKNOWN": true, "INT64": true, "STRING": true, "BOOL": true, "FLOAT64": true, "BYTES": true,
	"DAY": true, "HOUR": true, "MINUTE": true, "SECOND": true, "MONTH": true, "YEAR": true, "WEEK": true,
	"QUARTER": true, "MILLISECOND": true, "MICROSECOND": true, "ESCAPE": true}

// gsqlPredicateLimits reads one predicate (no AND, OR or NOT at its top).
func gsqlPredicateLimits(p gsqlStmt) bool {
	if !gsqlReadsColumn(p) {
		return false // TRUE, 1 = 1, @param, EXISTS (SELECT …)
	}
	n := len(p)
	switch {
	case n >= 3 && p[n-3].is("IS") && p[n-2].is("NOT") && (p[n-1].is("NULL") || p[n-1].is("UNKNOWN")):
		return false
	case gsqlIsDistinctFromNull(p):
		return false
	}
	// x = x, x >= x, x <= x: the same expression on both sides.
	for j := 1; j+1 < len(p); j++ {
		if p[j].kind == gsqlPunct && (p[j].text == "=" || p[j].text == ">=" || p[j].text == "<=") && gsqlTopLevel(p, j) {
			if gsqlSame(p[:j], p[j+1:]) {
				return false
			}
			break
		}
	}
	// x IN (…, x, …)
	for j := 1; j+1 < len(p); j++ {
		if p[j].is("IN") && gsqlTopLevel(p, j) && !p[j-1].is("NOT") && p[j+1].punct("(") {
			end := gsqlMatchingParen(p, j+1)
			if end == len(p)-1 {
				for _, item := range gsqlSplitPunct(p[j+2:end], ",") {
					if gsqlSame(p[:j], item) {
						return false
					}
				}
			}
			break
		}
	}
	// x LIKE '%', x LIKE ANY ('%', …)
	for j := 1; j+1 < len(p); j++ {
		if p[j].is("LIKE") && gsqlTopLevel(p, j) && !p[j-1].is("NOT") {
			for _, t := range p[j+1:] {
				if t.kind == gsqlString && likeMatchesAll(t.text) {
					return false
				}
			}
			break
		}
	}
	// REGEXP_CONTAINS(x, r'.*')
	if p[0].is("REGEXP_CONTAINS") && len(p) >= 2 && p[1].punct("(") && gsqlMatchingParen(p, 1) == len(p)-1 {
		args := gsqlSplitPunct(p[2:len(p)-1], ",")
		if len(args) == 2 && len(args[1]) == 1 && args[1][0].kind == gsqlString && regexMatchesAll(args[1][0].text) {
			return false
		}
	}
	return true
}

func gsqlIsDistinctFromNull(p gsqlStmt) bool {
	n := len(p)
	return n >= 5 && p[n-4].is("IS") && p[n-3].is("DISTINCT") && p[n-2].is("FROM") && p[n-1].is("NULL")
}

// gsqlReadsColumn reports whether an expression names a column outside a
// subquery: an identifier that is not a keyword, a literal or a function's
// name.
func gsqlReadsColumn(p gsqlStmt) bool {
	sub := 0 // depth inside subqueries
	depth := 0
	var subAt []int
	for j, t := range p {
		switch {
		case t.punct("("):
			depth++
			if j+1 < len(p) && (p[j+1].is("SELECT") || p[j+1].is("WITH")) {
				sub++
				subAt = append(subAt, depth)
			}
			continue
		case t.punct(")"):
			if len(subAt) > 0 && subAt[len(subAt)-1] == depth {
				subAt = subAt[:len(subAt)-1]
				sub--
			}
			depth--
			continue
		}
		if sub > 0 {
			continue
		}
		switch t.kind {
		case gsqlQIdent:
			if j+1 < len(p) && p[j+1].punct("(") {
				continue
			}
			return true
		case gsqlIdent:
			if gsqlNotColumn[t.up] || (j+1 < len(p) && p[j+1].punct("(")) {
				continue
			}
			if j > 0 && p[j-1].punct(".") {
				continue // a field of something already counted
			}
			return true
		}
	}
	return false
}

func gsqlTopLevel(p gsqlStmt, at int) bool {
	depth := 0
	for j := 0; j < at; j++ {
		switch {
		case p[j].punct("(") || p[j].punct("[") || p[j].punct("{"):
			depth++
		case p[j].punct(")") || p[j].punct("]") || p[j].punct("}"):
			depth--
		}
	}
	return depth == 0
}

func gsqlSplitPunct(e gsqlStmt, sep string) []gsqlStmt {
	var out []gsqlStmt
	depth, start := 0, 0
	for j, t := range e {
		switch {
		case t.punct("(") || t.punct("[") || t.punct("{"):
			depth++
		case t.punct(")") || t.punct("]") || t.punct("}"):
			depth--
		case depth == 0 && t.punct(sep):
			out = append(out, e[start:j])
			start = j + 1
		}
	}
	return append(out, e[start:])
}

// gsqlSame reports whether two expressions are written the same, ignoring
// the case of unquoted words and surrounding parentheses.
func gsqlSame(a, b gsqlStmt) bool {
	a, b = gsqlTrimParens(a), gsqlTrimParens(b)
	if len(a) != len(b) || len(a) == 0 {
		return false
	}
	for i := range a {
		if a[i].kind != b[i].kind {
			return false
		}
		if a[i].kind == gsqlIdent {
			if a[i].up != b[i].up {
				return false
			}
		} else if a[i].text != b[i].text {
			return false
		}
	}
	return true
}
