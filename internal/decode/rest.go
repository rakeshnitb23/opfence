package decode

import (
	"bytes"
	"net/url"
	"slices"
	"strings"

	"github.com/rakeshnitb23/opfence/internal/request"
)

// methodOverrideHeaders are honoured by some servers to tunnel one method
// through another (POST carrying a DELETE). Whether a server honours them is
// not known, so the request is decoded once for its real method and once for
// each overriding method, and the strictest decision wins.
var methodOverrideHeaders = []string{"X-Http-Method-Override", "X-Http-Method", "X-Method-Override"}

func decodeREST(r *request.Request) []Operation {
	op := Operation{Protocol: REST, Method: r.Method, Path: r.Path, Args: map[string]any{}}
	op.Args["query"] = valuesToMap(r.Query)
	decodeRESTBody(r, &op)
	ops := []Operation{op}
	methods := []string{r.Method}
	for _, h := range methodOverrideHeaders {
		for _, v := range r.Header.Values(h) {
			m := strings.ToUpper(strings.TrimSpace(v))
			if m == "" || slices.Contains(methods, m) {
				continue
			}
			methods = append(methods, m)
			o := op
			o.Method = m
			ops = append(ops, o)
		}
	}
	return ops
}

// decodeRESTBody puts the body's fields in op.Args["body"]. A body that
// looks like JSON is parsed as JSON whatever its Content-Type, because many
// APIs (GitHub's among them) parse it anyway. A body that is neither JSON
// nor a form sets BodyErr, so rules that read body fields fail closed.
func decodeRESTBody(r *request.Request, op *Operation) {
	if r.BodyErr != nil {
		op.BodyErr = r.BodyErr.Error()
		return
	}
	body := bytes.TrimLeft(r.Body, " \t\r\n")
	if len(body) == 0 {
		return
	}
	ct := r.ContentType()
	switch {
	case body[0] == '{' || body[0] == '[' || ct == "application/json" || strings.HasSuffix(ct, "+json"):
		v, err := parseJSON(r.Body)
		if err != nil {
			op.BodyErr = err.Error()
			return
		}
		op.Args["body"] = v
	case ct == "application/x-www-form-urlencoded":
		vals, err := url.ParseQuery(string(r.Body))
		if err != nil {
			op.BodyErr = "invalid form body: " + err.Error()
			return
		}
		op.Args["body"] = valuesToMap(vals)
	default:
		op.BodyErr = "the body is neither JSON nor a form"
	}
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
