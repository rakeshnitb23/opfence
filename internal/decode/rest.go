package decode

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
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
	decodeRESTBody(r, &op)
	query, err := formArgs(r.Query)
	if err != nil {
		// Conditions on the body fail closed; ones on the query see the
		// keys unnested.
		query = valuesToMap(r.Query)
		if op.BodyErr == "" {
			op.BodyErr = "query string: " + err.Error()
		}
	}
	op.Args["query"] = query
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
		m, err := formArgs(vals)
		if err != nil {
			op.BodyErr = "invalid form body: " + err.Error()
			return
		}
		op.Args["body"] = m
	case ct == "multipart/form-data":
		v, err := parseMultipart(r.Header.Get("Content-Type"), r.Body)
		if err != nil {
			op.BodyErr = "invalid multipart body: " + err.Error()
			return
		}
		op.Args["body"] = v
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

// maxParts caps the parts of a multipart body.
const maxParts = 1000

// parseMultipart reads a multipart/form-data body into args by part name:
// a JSON part (Cloudflare's Worker upload metadata) is parsed, another part
// without a filename is its text, and a file part is "" (present, not
// read). A repeated name becomes a list.
func parseMultipart(contentType string, body []byte) (map[string]any, error) {
	_, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		return nil, err
	}
	if params["boundary"] == "" {
		return nil, errors.New("no boundary")
	}
	mr := multipart.NewReader(bytes.NewReader(body), params["boundary"])
	out, seen := map[string]any{}, map[string]int{}
	for n := 0; ; n++ {
		p, err := mr.NextRawPart()
		if err == io.EOF {
			return out, nil
		}
		if err != nil {
			return nil, err
		}
		if n >= maxParts {
			return nil, fmt.Errorf("more than %d parts", maxParts)
		}
		switch cte := strings.ToLower(strings.TrimSpace(p.Header.Get("Content-Transfer-Encoding"))); cte {
		case "", "7bit", "8bit", "binary":
		default:
			// Servers differ on whether they decode it.
			return nil, fmt.Errorf("part encoded with %s", cte)
		}
		data, err := io.ReadAll(p)
		if err != nil {
			return nil, err
		}
		name := p.FormName()
		if name == "" {
			continue
		}
		var v any = string(data)
		pct, _, _ := mime.ParseMediaType(p.Header.Get("Content-Type"))
		trimmed := bytes.TrimLeft(data, " \t\r\n")
		switch {
		case pct == "application/json" || strings.HasSuffix(pct, "+json") || (p.FileName() == "" && len(trimmed) > 0 && trimmed[0] == '{'):
			if v, err = parseJSON(data); err != nil {
				return nil, fmt.Errorf("part %q: %w", name, err)
			}
		case p.FileName() != "":
			v = ""
		}
		switch seen[name]++; seen[name] {
		case 1:
			out[name] = v
		case 2:
			out[name] = []any{out[name], v}
		default:
			out[name] = append(out[name].([]any), v)
		}
	}
}
