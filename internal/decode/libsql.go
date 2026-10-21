package decode

import "fmt"

// LibSQLStatements reads a libSQL (Turso) HTTP request body and returns the
// SQL texts it runs, as SQLite. It reads the three bodies a libSQL server
// takes (docs/ARCHITECTURE.md §3.4):
//
//   - a Hrana pipeline (/v2/pipeline, /v3/pipeline): {"requests": [...]},
//     whose execute, batch and sequence requests run SQL;
//   - a Hrana cursor (/v3/cursor): {"batch": {"steps": [...]}};
//   - the legacy sqld API (POST /): {"statements": [sql | {"q": sql}]}.
//
// A store_sql request's text is returned as if it ran, because a later
// request on the stream can run it by its sql_id. unread is true when the
// body runs SQL the reader cannot see: a sql_id this body did not store
// (stored by an earlier request on the stream), a request type it does not
// know, or a statement with neither sql nor sql_id. ok is false when the
// body is none of the three shapes.
func LibSQLStatements(body any) (texts []string, unread, ok bool) {
	m, isMap := body.(map[string]any)
	if !isMap {
		return nil, false, false
	}
	r := libsqlReader{stored: map[string]bool{}}
	switch {
	case m["requests"] != nil:
		reqs, isList := m["requests"].([]any)
		if !isList {
			return nil, false, false
		}
		for _, req := range reqs {
			r.request(req)
		}
	case m["batch"] != nil:
		r.batch(m["batch"])
	case m["statements"] != nil:
		stmts, isList := m["statements"].([]any)
		if !isList {
			return nil, false, false
		}
		for _, s := range stmts {
			switch v := s.(type) {
			case string:
				r.texts = append(r.texts, v)
			case map[string]any:
				if q, isStr := v["q"].(string); isStr {
					r.texts = append(r.texts, q)
				} else {
					r.unread = true
				}
			default:
				r.unread = true
			}
		}
	default:
		return nil, false, false
	}
	return r.texts, r.unread, true
}

type libsqlReader struct {
	texts  []string
	unread bool
	stored map[string]bool // sql_ids this body stores
}

func (r *libsqlReader) request(v any) {
	req, ok := v.(map[string]any)
	if !ok {
		r.unread = true
		return
	}
	switch req["type"] {
	case "execute":
		r.stmt(req["stmt"])
	case "batch":
		r.batch(req["batch"])
	case "sequence":
		r.stmt(req) // sql or sql_id, like a statement; may hold several statements
	case "store_sql":
		if s, isStr := req["sql"].(string); isStr && req["sql_id"] != nil {
			r.texts = append(r.texts, s)
			r.stored[fmt.Sprint(req["sql_id"])] = true
		} else {
			r.unread = true
		}
	case "close_sql":
		delete(r.stored, fmt.Sprint(req["sql_id"]))
	case "describe", "close", "get_autocommit":
		// Nothing runs: describe only prepares the statement.
	default:
		r.unread = true
	}
}

func (r *libsqlReader) batch(v any) {
	b, ok := v.(map[string]any)
	if !ok {
		r.unread = true
		return
	}
	steps, ok := b["steps"].([]any)
	if !ok {
		r.unread = true
		return
	}
	for _, st := range steps {
		step, ok := st.(map[string]any)
		if !ok {
			r.unread = true
			continue
		}
		r.stmt(step["stmt"])
	}
}

// stmt reads a statement's sql, or the sql_id of a text stored earlier.
func (r *libsqlReader) stmt(v any) {
	st, ok := v.(map[string]any)
	if !ok {
		r.unread = true
		return
	}
	s, hasSQL := st["sql"].(string)
	if hasSQL {
		r.texts = append(r.texts, s)
	}
	if id := st["sql_id"]; id != nil {
		if !r.stored[fmt.Sprint(id)] {
			r.unread = true
		}
	} else if !hasSQL {
		r.unread = true
	}
}
