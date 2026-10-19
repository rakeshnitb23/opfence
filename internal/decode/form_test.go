package decode

import (
	"encoding/json"
	"net/url"
	"strings"
	"testing"
)

func TestFormArgs(t *testing.T) {
	cases := []struct{ in, want string }{
		{"a=1&b=2&b=3", `{"a":"1","b":["2","3"]}`},
		{"expand[]=number&expand[]=cvc", `{"expand":["number","cvc"]}`},
		{"expand[]=number", `{"expand":["number"]}`},
		{"expand=x&expand[]=y", `{"expand":["x","y"]}`},
		{"metadata[plan]=pro&metadata[tier]=1", `{"metadata":{"plan":"pro","tier":"1"}}`},
		{"items[1][price]=p2&items[0][price]=p1&items[0][quantity]=3", `{"items":[{"price":"p1","quantity":"3"},{"price":"p2"}]}`},
		{"items[5][price]=a&items[10][price]=b", `{"items":[{"price":"a"},{"price":"b"}]}`},
		{"metadata[0]=x&metadata[name]=y", `{"metadata":{"0":"x","name":"y"}}`},
		{"a[b][c][d]=1", `{"a":{"b":{"c":{"d":"1"}}}}`},
		// Not bracket keys: kept as they are.
		{"[a]=1&a]=2&a[b=3&a[][b]=4&a[b]c=5", `{"[a]":"1","a[][b]":"4","a[b":"3","a[b]c":"5","a]":"2"}`},
		{"x" + strings.Repeat("[a]", 11) + "=1", `{"x` + strings.Repeat("[a]", 11) + `":"1"}`},
	}
	for _, c := range cases {
		v, _ := url.ParseQuery(c.in)
		got, err := formArgs(v)
		if err != nil {
			t.Errorf("%s: %v", c.in, err)
			continue
		}
		b, _ := json.Marshal(got)
		if string(b) != c.want {
			t.Errorf("%s:\n got  %s\n want %s", c.in, b, c.want)
		}
	}
	for _, bad := range []string{"a=1&a[b]=2", "a[]=1&a[b]=2", "a[0]=1&a[0][b]=2"} {
		v, _ := url.ParseQuery(bad)
		if _, err := formArgs(v); err == nil {
			t.Errorf("%s: no error", bad)
		}
	}
}
