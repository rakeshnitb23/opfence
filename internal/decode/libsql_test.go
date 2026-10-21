package decode

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestLibSQLStatements(t *testing.T) {
	cases := []struct {
		body   string
		texts  []string
		unread bool
		ok     bool
	}{
		// Hrana pipeline: every request type.
		{`{"baton":null,"requests":[{"type":"execute","stmt":{"sql":"select 1","args":[]}},{"type":"close"}]}`, []string{"select 1"}, false, true},
		{`{"requests":[{"type":"batch","batch":{"steps":[{"stmt":{"sql":"begin"}},{"condition":{"type":"ok","step":0},"stmt":{"sql":"delete from t"}}]}}]}`,
			[]string{"begin", "delete from t"}, false, true},
		{`{"requests":[{"type":"sequence","sql":"create table t (a); insert into t values (1)"}]}`, []string{"create table t (a); insert into t values (1)"}, false, true},
		{`{"requests":[{"type":"describe","sql":"drop table t"},{"type":"get_autocommit"}]}`, nil, false, true},
		// A stored text counts as if it ran, and running it by id is then known.
		{`{"requests":[{"type":"store_sql","sql_id":1,"sql":"drop table t"},{"type":"execute","stmt":{"sql_id":1}}]}`, []string{"drop table t"}, false, true},
		{`{"requests":[{"type":"store_sql","sql_id":1,"sql":"select 1"},{"type":"sequence","sql_id":1}]}`, []string{"select 1"}, false, true},
		// An id stored by an earlier request on the stream cannot be seen.
		{`{"baton":"b","requests":[{"type":"execute","stmt":{"sql_id":7}}]}`, nil, true, true},
		{`{"requests":[{"type":"store_sql","sql_id":1,"sql":"select 1"},{"type":"close_sql","sql_id":1},{"type":"execute","stmt":{"sql_id":1}}]}`, []string{"select 1"}, true, true},
		{`{"requests":[{"type":"batch","batch":{"steps":[{"stmt":{"sql_id":3}}]}}]}`, nil, true, true},
		// Both sql and sql_id: both count.
		{`{"requests":[{"type":"execute","stmt":{"sql":"select 1","sql_id":9}}]}`, []string{"select 1"}, true, true},
		// What the reader does not know.
		{`{"requests":[{"type":"open_cursor"}]}`, nil, true, true},
		{`{"requests":[{"type":"execute"}]}`, nil, true, true},
		{`{"requests":[{"type":"execute","stmt":{}}]}`, nil, true, true},
		{`{"requests":[{"type":"execute","stmt":{"sql":7}}]}`, nil, true, true},
		{`{"requests":[{"type":"store_sql","sql_id":1}]}`, nil, true, true},
		{`{"requests":["execute"]}`, nil, true, true},
		{`{"requests":[{"type":"batch","batch":{"steps":"x"}}]}`, nil, true, true},
		// Hrana cursor.
		{`{"baton":null,"batch":{"steps":[{"stmt":{"sql":"select * from t"}}]}}`, []string{"select * from t"}, false, true},
		{`{"batch":[]}`, nil, true, true},
		// Legacy sqld API.
		{`{"statements":["select 1",{"q":"delete from t where id = ?","params":[1]}]}`, []string{"select 1", "delete from t where id = ?"}, false, true},
		{`{"statements":[{"query":"select 1"}]}`, nil, true, true},
		{`{"statements":[7]}`, nil, true, true},
		// Not a libSQL body.
		{`{"requests":"x"}`, nil, false, false},
		{`{"statements":"select 1"}`, nil, false, false},
		{`{"sql":"select 1"}`, nil, false, false},
		{`[]`, nil, false, false},
		{`"select 1"`, nil, false, false},
	}
	for _, c := range cases {
		var body any
		if err := json.Unmarshal([]byte(c.body), &body); err != nil {
			t.Fatalf("%s: %v", c.body, err)
		}
		texts, unread, ok := LibSQLStatements(body)
		if !reflect.DeepEqual(texts, c.texts) || unread != c.unread || ok != c.ok {
			t.Errorf("LibSQLStatements(%s) = %q, %v, %v; want %q, %v, %v", c.body, texts, unread, ok, c.texts, c.unread, c.ok)
		}
	}
	if _, _, ok := LibSQLStatements(nil); ok {
		t.Error("nil body read as libSQL")
	}
}

func FuzzLibSQLStatements(f *testing.F) {
	for _, s := range []string{`{"requests":[{"type":"execute","stmt":{"sql":"select 1"}}]}`, `{"batch":{"steps":[{"stmt":{"sql_id":1}}]}}`,
		`{"statements":["x",{"q":"y"}]}`, `{"requests":[{"type":"store_sql","sql_id":1,"sql":"x"},{"type":"close_sql","sql_id":1}]}`} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		var body any
		if json.Unmarshal([]byte(s), &body) != nil {
			return
		}
		texts, unread, ok := LibSQLStatements(body)
		if !ok && (texts != nil || unread) {
			t.Fatalf("not a body, yet texts %q unread %v", texts, unread)
		}
	})
}
