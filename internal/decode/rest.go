package decode

import (
	"net/url"
	"strings"

	"github.com/rakeshnitb23/opfence/internal/request"
)

// methodOverrideHeaders are honoured by some servers to tunnel one method
// through another (POST carrying a DELETE). The overriding method is used
// for matching: accurate when the server honours it, stricter when not.
var methodOverrideHeaders = []string{"X-Http-Method-Override", "X-Http-Method", "X-Method-Override"}

func decodeREST(r *request.Request) Operation {
	op := Operation{Protocol: REST, Method: r.Method, Path: r.Path, Args: map[string]any{}}
	for _, h := range methodOverrideHeaders {
		if v := strings.ToUpper(strings.TrimSpace(r.Header.Get(h))); v != "" {
			op.Method = v
		}
	}
	op.Args["query"] = valuesToMap(r.Query)
	if r.BodyErr != nil {
		op.BodyErr = r.BodyErr.Error()
		return op
	}
	if len(r.Body) == 0 {
		return op
	}
	ct := r.ContentType()
	switch {
	case ct == "application/json" || strings.HasSuffix(ct, "+json"):
		v, err := parseJSON(r.Body)
		if err != nil {
			op.BodyErr = err.Error()
			return op
		}
		op.Args["body"] = v
	case ct == "application/x-www-form-urlencoded":
		vals, err := url.ParseQuery(string(r.Body))
		if err != nil {
			op.BodyErr = "invalid form body: " + err.Error()
			return op
		}
		op.Args["body"] = valuesToMap(vals)
	}
	return op
}

// valuesToMap turns url.Values into args: a single value stays a string,
// repeated keys become a list.
func valuesToMap(v url.Values) map[string]any {
	m := make(map[string]any, len(v))
	for k, vs := range v {
		if len(vs) == 1 {
			m[k] = vs[0]
			continue
		}
		list := make([]any, len(vs))
		for i, s := range vs {
			list[i] = s
		}
		m[k] = list
	}
	return m
}
