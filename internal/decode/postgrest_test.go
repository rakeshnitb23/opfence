package decode

import (
	"net/url"
	"testing"
)

func TestPostgRESTLimitsRows(t *testing.T) {
	cases := []struct {
		query string
		want  bool
	}{
		// No filter: every row.
		{"", false},
		{"select=id,name", false},
		{"order=id&limit=1", false}, // a limit is not a filter
		{"columns=a,b&on_conflict=id", false},
		// A filter on a column limits.
		{"id=eq.5", true},
		{"status=neq.archived", true},
		{"created_at=lt.2024-01-01", true},
		{"id=in.(1,2,3)", true},
		{"id=in.()", true}, // matches nothing
		{"deleted_at=is.null", true},
		{"done=is.true", true},
		{"name=like.a*", true},
		{"name=not.like.*", true}, // matches nothing
		{"tags=cs.{a,b}", true},
		{"select=id&id=eq.5", true},
		// Filters that match every row.
		{"id=not.is.null", false},
		{"id=is.not_null", false},
		{"id=not.is.not_null", true},
		{"name=like.*", false},
		{"name=ilike.%25%25", false},
		{"name=like(any).{*,a*}", false},
		{"name=like(all).{*,a*}", true},
		{"name=like(all).{*,%25}", false},
		{"name=match.", false},
		{"name=imatch..*", false},
		{"name=match.^a", true},
		{"id=isdistinct.null", false},
		{"id=not.in.()", false},
		// Several filters are ANDed: one that limits is enough.
		{"id=not.is.null&status=eq.old", true},
		{"id=not.is.null&name=like.*", false},
		// A repeated parameter: each value is a filter.
		{"id=not.is.null&id=eq.4", true},
		// Logical groups.
		{"or=(id.eq.1,id.eq.2)", true},
		{"or=(id.eq.1,id.not.is.null)", false},
		{"and=(id.not.is.null,status.eq.old)", true},
		{"and=(id.not.is.null,name.like.*)", false},
		{"or=(id.eq.1,and(a.eq.1,b.not.is.null))", true},
		{"or=(id.eq.1,and(a.not.is.null,b.not.is.null))", false},
		{"or=(id.eq.1,not.and(a.eq.1,b.eq.2))", false}, // negated groups do not count
		{"not.or=(id.eq.1,id.eq.2)", false},
		{"not.and=(id.eq.1)", false},
		{`or=(name.eq."a,b",id.eq.3)`, true},
		{"or=(id.eq.1", false}, // malformed
		{"or=()", false},
		{"or=(id)", false},
		// Embedded resources' filters do not filter the table's rows.
		{"actors.name=eq.x", false},
		{"actors.or=(a.eq.1)", false},
		// What does not parse as a filter does not count.
		{"id=5", false},
		{"id=nope.5", false},
		{"id=like(some).{a}", false},
		{"id=like(any).a", false},
		{"id[x]=eq.1", false}, // nested by the form decoder
	}
	for _, c := range cases {
		v, err := url.ParseQuery(c.query)
		if err != nil {
			t.Fatalf("%q: %v", c.query, err)
		}
		q, err := formArgs(v)
		if err != nil {
			q = valuesToMap(v)
		}
		if got := PostgRESTLimitsRows(q); got != c.want {
			t.Errorf("%q: limits %v, want %v", c.query, got, c.want)
		}
	}
	if PostgRESTLimitsRows(nil) {
		t.Error("nil query limits rows")
	}
}

func FuzzPostgRESTLimitsRows(f *testing.F) {
	for _, s := range []string{"id=eq.5", "or=(a.eq.1,and(b.not.is.null))", "name=like(any).{*,a}", `or=(a.eq."x,y")`} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		v, err := url.ParseQuery(s)
		if err != nil {
			return
		}
		q, err := formArgs(v)
		if err != nil {
			q = valuesToMap(v)
		}
		PostgRESTLimitsRows(q)
	})
}
