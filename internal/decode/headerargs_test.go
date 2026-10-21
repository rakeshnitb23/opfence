package decode

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/rakeshnitb23/opfence/internal/request"
)

func TestHeaderArg(t *testing.T) {
	basic := func(s string) string { return "Basic " + base64.StdEncoding.EncodeToString([]byte(s)) }
	cases := []struct {
		value, parse string
		want         map[string]any
	}{
		{"postgresql://neondb_owner:npg_SECRET@ep-x.us-east-2.aws.neon.tech/neondb?sslmode=require", "url",
			map[string]any{"host": "ep-x.us-east-2.aws.neon.tech", "user": "neondb_owner", "database": "neondb"}},
		{"postgres://u:p@EP-X.Example.COM:5433/db", "url", map[string]any{"host": "ep-x.example.com", "port": "5433", "user": "u", "database": "db"}},
		{"postgres://ep-x.example.com", "url", map[string]any{"host": "ep-x.example.com"}},
		{"  postgres://u@h.example.com/d  ", "url", map[string]any{"host": "h.example.com", "user": "u", "database": "d"}},
		{"not a url", "url", nil},
		{"postgres://u:p@/db", "url", nil},
		{"", "url", nil},
		{basic("r8m2k1x:pscale_pw_SECRET"), "basic", map[string]any{"username": "r8m2k1x"}},
		{"basic " + base64.StdEncoding.EncodeToString([]byte("u:p")), "basic", map[string]any{"username": "u"}},
		{basic("no-colon"), "basic", nil},
		{basic(":only-password"), "basic", nil},
		{"Basic !!!not base64", "basic", nil},
		{"Bearer eyJ.e30.x", "basic", nil},
		{"Basic", "basic", nil},
		{"postgres://u:p@h.example.com/d", "json", nil},
	}
	for _, c := range cases {
		got := headerArg(c.value, c.parse)
		if c.want == nil {
			if got != nil {
				t.Errorf("headerArg(%q, %s) = %v, want nil", c.value, c.parse, got)
			}
			continue
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("headerArg(%q, %s) = %v, want %v", c.value, c.parse, got, c.want)
		}
	}
}

// Header arguments reach every operation of a request, and never carry the
// password.
func TestDecodeHeaderArgs(t *testing.T) {
	r := &request.Request{Method: "POST", Path: "/sql", Header: http.Header{}, Body: []byte(`{"query":"select 1"}`)}
	r.Header.Set("Neon-Connection-String", "postgresql://owner:npg_SECRET@ep-x.us-east-2.aws.neon.tech/neondb")
	r.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("user1:pscale_pw_SECRET")))
	r.Header.Set("X-HTTP-Method-Override", "DELETE")
	h := Hints{HeaderArgs: []HeaderArg{
		{Header: "Neon-Connection-String", Arg: "connection", Parse: "url"},
		{Header: "Authorization", Arg: "credentials", Parse: "basic"},
		{Header: "Absent", Arg: "absent", Parse: "url"},
	}}
	ops := Decode(r, h)
	if len(ops) != 2 {
		t.Fatalf("%d operations, want the request and its override", len(ops))
	}
	for _, op := range ops {
		conn, _ := op.Args["connection"].(map[string]any)
		cred, _ := op.Args["credentials"].(map[string]any)
		if conn["host"] != "ep-x.us-east-2.aws.neon.tech" || cred["username"] != "user1" {
			t.Fatalf("%s: args %v", op.Method, op.Args)
		}
		if _, ok := op.Args["absent"]; ok {
			t.Fatal("an absent header became an argument")
		}
		if s := fmt.Sprint(op.Args); strings.Contains(s, "SECRET") {
			t.Fatalf("a password reached the arguments: %s", s)
		}
	}
}
