package engine

import (
	"testing"

	"github.com/rakeshnitb23/opfence/internal/catalog"
	"github.com/rakeshnitb23/opfence/internal/classes"
	"github.com/rakeshnitb23/opfence/internal/policy"
	"github.com/rakeshnitb23/opfence/internal/request"
)

// A Supabase project's own API: the ref in the host is the resource and
// maps to an environment, and PostgREST filters decide how many rows a
// PATCH or DELETE changes, which the card says.
func TestSupabaseProjectAPI(t *testing.T) {
	c, err := catalog.Embedded()
	if err != nil {
		t.Fatal(err)
	}
	user := &policy.File{Version: 1, Environments: map[string]map[string]map[string][]string{
		"development": {"supabase-project": {"ref": {"devdevdevdevdevdevde"}}},
	}}
	e := New(c, policy.Resolve(user, nil))
	send := func(method, host, target string) Evaluation {
		t.Helper()
		req, _, err := request.ParseFixture([]byte(method + " " + target + " HTTP/1.1\nHost: " + host + "\n\n"))
		if err != nil {
			t.Fatal(err)
		}
		res := e.Evaluate(req)
		if res.Provider == nil || res.Provider.ID != "supabase-project" {
			t.Fatalf("%s %s: provider %v", method, host, res.Provider)
		}
		return res.Evaluations[0]
	}
	cases := []struct {
		method, host, target string
		class                classes.Class
		decision             classes.Decision
		env, card            string
	}{
		{"DELETE", "prodprodprodprodprod.supabase.co", "/rest/v1/orders?id=eq.5", classes.Delete, classes.Ask, "production",
			"Delete rows from orders in project prodprodprodprodprod where id=eq.5"},
		{"DELETE", "prodprodprodprodprod.supabase.co", "/rest/v1/orders", classes.Irreversible, classes.Confirm, "production",
			"Delete rows from orders in project prodprodprodprodprod (every row)"},
		{"DELETE", "prodprodprodprodprod.supabase.co", "/rest/v1/orders?id=not.is.null&select=id", classes.Irreversible, classes.Confirm, "production",
			"Delete rows from orders in project prodprodprodprodprod (every row)"},
		{"PATCH", "prodprodprodprodprod.supabase.co", "/rest/v1/orders?a=eq.1&b=eq.2&c=eq.3&d=eq.4", classes.Write, classes.Ask, "production",
			"Update rows of orders in project prodprodprodprodprod where a=eq.1, b=eq.2, c=eq.3 and 1 more"},
		// The mapped project is development.
		{"DELETE", "devdevdevdevdevdevde.supabase.co", "/rest/v1/orders", classes.Irreversible, classes.Ask, "development",
			"Delete rows from orders in project devdevdevdevdevdevde (every row)"},
		{"GET", "prodprodprodprodprod.supabase.co", "/rest/v1/orders?select=*", classes.Read, classes.Allow, "production", ""},
		{"GET", "prodprodprodprodprod.supabase.co", "/functions/v1/send-email", classes.Unknown, classes.Ask, "production",
			"Call edge function send-email of project prodprodprodprodprod"},
	}
	for _, tc := range cases {
		ev := send(tc.method, tc.host, tc.target)
		if ev.Class != tc.class || ev.Decision != tc.decision || ev.Environment != tc.env || (tc.card != "" && ev.Card != tc.card) {
			t.Errorf("%s %s%s: %s %s %s %q, want %s %s %s %q", tc.method, tc.host, tc.target, ev.Class, ev.Decision, ev.Environment, ev.Card,
				tc.class, tc.decision, tc.env, tc.card)
		}
		if want := tc.host[:20]; ev.Rule != nil && ev.Rule.Resource != nil && ev.Resource != want {
			t.Errorf("%s %s: resource %q, want %q", tc.method, tc.host, ev.Resource, want)
		}
	}
}
