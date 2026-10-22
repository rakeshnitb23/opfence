package decode

import (
	"slices"
	"strings"
)

// PostgRESTLimitsRows reports whether the query parameters of a PostgREST
// request (Supabase's /rest/v1) limit the rows a PATCH or DELETE changes,
// as a SQL WHERE does (effectiveWhere). PostgREST turns each parameter that
// names a column into a filter (id=eq.5), ANDs them, and changes every row
// of the table when there is none.
//
// A filter counts only when it can leave rows out. These do not:
//   - not.is.null and is.not_null, as id IS NOT NULL does not in SQL;
//   - like and ilike patterns made only of wildcards (* or %), regex
//     matches (match, imatch) that match any string, isdistinct.null, and
//     not.in.() with an empty list;
//   - an or=(...) group with any branch that does not limit;
//   - negated groups (not.or, not.and), whose effect Opfence does not work
//     out, and filters on embedded resources (actors.name=eq.x), which
//     filter the embedded rows, not the table's.
//
// An and=(...) group limits if any branch does. Reserved parameters
// (select, order, limit, offset, columns, on_conflict) are not filters:
// a limit does not count, since a large one changes every row. Anything
// that does not parse as a filter does not count either.
func PostgRESTLimitsRows(query map[string]any) bool {
	for key, v := range query {
		values, ok := postgrestValues(v)
		if !ok {
			continue
		}
		for _, val := range values {
			if postgrestParamLimits(key, val) {
				return true
			}
		}
	}
	return false
}

// PostgRESTFilters lists a PostgREST request's filters for an approval card,
// "id=eq.5, status=neq.old", sorted, leaving out the reserved parameters
// (select, order, limit and the rest).
func PostgRESTFilters(query map[string]any) []string {
	var out []string
	for key, v := range query {
		if postgrestReserved[key] {
			continue
		}
		values, ok := postgrestValues(v)
		if !ok {
			continue
		}
		for _, val := range values {
			out = append(out, key+"="+val)
		}
	}
	slices.Sort(out)
	return out
}

// postgrestValues returns a parameter's values: one string, or each string
// of a repeated parameter.
func postgrestValues(v any) ([]string, bool) {
	switch t := v.(type) {
	case string:
		return []string{t}, true
	case []any:
		out := make([]string, 0, len(t))
		for _, el := range t {
			s, ok := el.(string)
			if !ok {
				return nil, false
			}
			out = append(out, s)
		}
		return out, true
	}
	return nil, false // a bracketed key the form decoder nested
}

var postgrestReserved = map[string]bool{
	"select": true, "order": true, "limit": true, "offset": true, "columns": true, "on_conflict": true,
}

func postgrestParamLimits(key, val string) bool {
	switch {
	case postgrestReserved[key]:
		return false
	case key == "and":
		return postgrestGroupLimits("and", val, 0)
	case key == "or":
		return postgrestGroupLimits("or", val, 0)
	case strings.Contains(key, "."):
		return false // not.or, not.and, or an embedded resource's filter
	case key == "":
		return false
	}
	return postgrestFilterLimits(val)
}

// postgrestGroupLimits reads a logical group's value, "(a.eq.1,b.gt.2)".
func postgrestGroupLimits(op, val string, depth int) bool {
	if depth > 16 || len(val) < 2 || val[0] != '(' || val[len(val)-1] != ')' {
		return false
	}
	items, ok := postgrestSplit(val[1 : len(val)-1])
	if !ok || len(items) == 0 {
		return false
	}
	some, every := false, true
	for _, it := range items {
		l := postgrestItemLimits(it, depth+1)
		some = some || l
		every = every && l
	}
	if op == "and" {
		return some
	}
	return every
}

// postgrestItemLimits reads one item of a group: a nested group (and(...),
// or(...)) or a filter on a column (col.op.value).
func postgrestItemLimits(it string, depth int) bool {
	switch {
	case strings.HasPrefix(it, "and("):
		return postgrestGroupLimits("and", it[len("and"):], depth)
	case strings.HasPrefix(it, "or("):
		return postgrestGroupLimits("or", it[len("or"):], depth)
	case strings.HasPrefix(it, "not."):
		rest := it[len("not."):]
		if strings.HasPrefix(rest, "and(") || strings.HasPrefix(rest, "or(") {
			return false // a negated group
		}
	}
	col, filter, ok := strings.Cut(it, ".")
	if !ok || col == "" || strings.ContainsAny(col, "()") {
		return false
	}
	return postgrestFilterLimits(filter)
}

// postgrestSplit splits a group's items at commas outside parentheses,
// braces and double quotes.
func postgrestSplit(s string) ([]string, bool) {
	var out []string
	depth, quoted, start := 0, false, 0
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case quoted && c == '\\':
			i++
		case c == '"':
			quoted = !quoted
		case quoted:
		case c == '(' || c == '{':
			depth++
		case c == ')' || c == '}':
			depth--
			if depth < 0 {
				return nil, false
			}
		case c == ',' && depth == 0:
			out = append(out, strings.TrimSpace(s[start:i]))
			start = i + 1
		}
	}
	if quoted || depth != 0 {
		return nil, false
	}
	return append(out, strings.TrimSpace(s[start:])), true
}

var postgrestOps = map[string]bool{
	"eq": true, "neq": true, "gt": true, "gte": true, "lt": true, "lte": true, "like": true, "ilike": true,
	"match": true, "imatch": true, "in": true, "is": true, "isdistinct": true, "fts": true, "plfts": true,
	"phfts": true, "wfts": true, "cs": true, "cd": true, "ov": true, "sl": true, "sr": true, "nxr": true,
	"nxl": true, "adj": true,
}

// postgrestFilterLimits reads a filter's value, "[not.]op[(any|all)].operand",
// and reports whether it can leave rows out.
func postgrestFilterLimits(f string) bool {
	negated := false
	if rest, ok := strings.CutPrefix(f, "not."); ok {
		negated, f = true, rest
	}
	op, operand, ok := strings.Cut(f, ".")
	if !ok {
		return false
	}
	modifier := ""
	if i := strings.IndexByte(op, '('); i >= 0 && strings.HasSuffix(op, ")") {
		op, modifier = op[:i], op[i+1:len(op)-1]
		if modifier != "any" && modifier != "all" {
			return false
		}
	}
	if !postgrestOps[op] {
		return false
	}
	switch op {
	case "is":
		v := strings.ToLower(operand)
		if (v == "null" && negated) || (v == "not_null" && !negated) {
			return false // every row where a NOT NULL column has a value
		}
	case "isdistinct":
		if strings.EqualFold(operand, "null") && !negated {
			return false
		}
	case "in":
		if negated && strings.TrimSpace(operand) == "()" {
			return false
		}
	case "like", "ilike", "match", "imatch":
		if negated {
			break
		}
		pats := []string{operand}
		if modifier != "" {
			p, ok := postgrestList(operand)
			if !ok {
				return false
			}
			pats = p
		}
		matchAll := func(p string) bool {
			if op == "like" || op == "ilike" {
				return likeMatchesAll(strings.ReplaceAll(p, "*", "%"))
			}
			return regexMatchesAll(p)
		}
		anyAll, allAll := false, true
		for _, p := range pats {
			m := matchAll(p)
			anyAll = anyAll || m
			allAll = allAll && m
		}
		if (modifier == "all" && allAll) || (modifier != "all" && anyAll) {
			return false
		}
	}
	return true
}

// postgrestList reads a modifier's operand list, "{a*,b*}".
func postgrestList(s string) ([]string, bool) {
	if len(s) < 2 || s[0] != '{' || s[len(s)-1] != '}' {
		return nil, false
	}
	items, ok := postgrestSplit(s[1 : len(s)-1])
	if !ok {
		return nil, false
	}
	for i, it := range items {
		items[i] = strings.Trim(it, `"`)
	}
	return items, true
}
