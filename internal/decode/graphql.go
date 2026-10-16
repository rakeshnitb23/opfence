package decode

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/vektah/gqlparser/v2/ast"
	"github.com/vektah/gqlparser/v2/parser"

	"github.com/rakeshnitb23/opfence/internal/request"
)

// graphqlRequest is one GraphQL request: a body object, one element of a
// batch, or the parameters of a GET request.
type graphqlRequest struct {
	query     string
	variables map[string]any
	persisted bool // carries a persisted-query hash instead of (or as well as) a query
}

func decodeGraphQL(r *request.Request) []Operation {
	base := Operation{Protocol: GraphQL, Method: r.Method, Path: r.Path}
	fail := func(msg string) []Operation {
		op := base
		op.Error = msg
		return []Operation{op}
	}
	if r.BodyErr != nil {
		return fail(r.BodyErr.Error())
	}

	var reqs []graphqlRequest
	switch {
	case r.Method == "GET":
		gr, err := graphqlFromQuery(r)
		if err != nil {
			return fail(err.Error())
		}
		reqs = []graphqlRequest{gr}
	case r.Method == "POST" && r.ContentType() == "application/graphql":
		reqs = []graphqlRequest{{query: string(r.Body)}}
	case r.Method == "POST" && (r.ContentType() == "application/json" || r.ContentType() == "" || strings.HasSuffix(r.ContentType(), "+json")):
		v, err := parseJSON(r.Body)
		if err != nil {
			return fail(err.Error())
		}
		switch t := v.(type) {
		case map[string]any:
			gr, err := graphqlFromObject(t)
			if err != nil {
				return fail(err.Error())
			}
			reqs = []graphqlRequest{gr}
		case []any:
			if len(t) == 0 {
				return fail("empty GraphQL batch")
			}
			for i, el := range t {
				obj, ok := el.(map[string]any)
				if !ok {
					return fail(fmt.Sprintf("GraphQL batch element %d is not an object", i))
				}
				gr, err := graphqlFromObject(obj)
				if err != nil {
					return fail(fmt.Sprintf("GraphQL batch element %d: %v", i, err))
				}
				reqs = append(reqs, gr)
			}
		default:
			return fail("GraphQL body is not an object or a batch")
		}
	default:
		return fail(fmt.Sprintf("unsupported GraphQL request: %s with Content-Type %q", r.Method, r.ContentType()))
	}

	var ops []Operation
	for _, gr := range reqs {
		got, err := graphqlOperations(gr, base)
		if err != nil {
			return fail(err.Error())
		}
		ops = append(ops, got...)
		if len(ops) > MaxOperations {
			return fail("request carries more than 200 operations")
		}
	}
	return ops
}

func graphqlFromQuery(r *request.Request) (graphqlRequest, error) {
	gr := graphqlRequest{query: r.Query.Get("query")}
	if len(r.Query["query"]) > 1 {
		return gr, fmt.Errorf("query parameter repeated")
	}
	if ext := r.Query.Get("extensions"); strings.Contains(ext, "persistedQuery") {
		gr.persisted = true
	}
	if vs := r.Query.Get("variables"); vs != "" {
		v, err := parseJSON([]byte(vs))
		if err != nil {
			return gr, fmt.Errorf("variables: %v", err)
		}
		m, ok := v.(map[string]any)
		if !ok && v != nil {
			return gr, fmt.Errorf("variables is not an object")
		}
		gr.variables = m
	}
	return gr, nil
}

func graphqlFromObject(obj map[string]any) (graphqlRequest, error) {
	var gr graphqlRequest
	switch q := obj["query"].(type) {
	case string:
		gr.query = q
	case nil:
	default:
		return gr, fmt.Errorf("query is not a string")
	}
	switch v := obj["variables"].(type) {
	case map[string]any:
		gr.variables = v
	case nil:
	case string:
		// Some clients send variables as a JSON string.
		pv, err := parseJSON([]byte(v))
		if err != nil {
			return gr, fmt.Errorf("variables: %v", err)
		}
		if m, ok := pv.(map[string]any); ok {
			gr.variables = m
		} else if pv != nil {
			return gr, fmt.Errorf("variables is not an object")
		}
	default:
		return gr, fmt.Errorf("variables is not an object")
	}
	if ext, ok := obj["extensions"].(map[string]any); ok {
		if _, ok := ext["persistedQuery"]; ok {
			gr.persisted = true
		}
	}
	return gr, nil
}

// graphqlOperations parses one request and returns one operation per root
// field of every operation in the document. Every operation is evaluated,
// not only the one operationName selects: that is stricter than the server
// and costs nothing in the common single-operation case.
func graphqlOperations(gr graphqlRequest, base Operation) ([]Operation, error) {
	if strings.TrimSpace(gr.query) == "" {
		if gr.persisted {
			return nil, fmt.Errorf("persisted query without query text")
		}
		return nil, fmt.Errorf("GraphQL request has no query")
	}
	doc, err := parser.ParseQuery(&ast.Source{Input: gr.query})
	if err != nil {
		return nil, fmt.Errorf("GraphQL parse error: %v", err)
	}
	if len(doc.Operations) == 0 {
		return nil, fmt.Errorf("GraphQL document has no operations")
	}
	var ops []Operation
	for _, od := range doc.Operations {
		opType := string(od.Operation)
		if opType == "" {
			opType = "query"
		}
		vars := map[string]any{}
		for _, vd := range od.VariableDefinitions {
			if v, ok := gr.variables[vd.Variable]; ok {
				vars[vd.Variable] = v
			} else if vd.DefaultValue != nil {
				dv, err := gqlValue(vd.DefaultValue, nil)
				if err != nil {
					return nil, err
				}
				vars[vd.Variable] = dv
			}
		}
		fields, err := rootFields(doc, od.SelectionSet, map[string]bool{})
		if err != nil {
			return nil, err
		}
		if len(fields) == 0 {
			return nil, fmt.Errorf("GraphQL operation selects no fields")
		}
		for _, f := range fields {
			args := map[string]any{}
			for _, a := range f.Arguments {
				if _, dup := args[a.Name]; dup {
					return nil, fmt.Errorf("argument %q repeated on %s", a.Name, f.Name)
				}
				v, err := gqlValue(a.Value, vars)
				if err != nil {
					return nil, err
				}
				args[a.Name] = v
			}
			op := base
			op.GraphQLType = opType
			op.Field = f.Name
			op.Args = args
			ops = append(ops, op)
			if len(ops) > MaxOperations {
				return nil, fmt.Errorf("request carries more than 200 operations")
			}
		}
	}
	return ops, nil
}

// rootFields flattens fragment spreads and inline fragments so aliases and
// fragments cannot hide a root field. @skip and @include are ignored: a
// field that might run is treated as running.
func rootFields(doc *ast.QueryDocument, set ast.SelectionSet, active map[string]bool) ([]*ast.Field, error) {
	var out []*ast.Field
	for _, sel := range set {
		switch s := sel.(type) {
		case *ast.Field:
			out = append(out, s)
		case *ast.InlineFragment:
			fs, err := rootFields(doc, s.SelectionSet, active)
			if err != nil {
				return nil, err
			}
			out = append(out, fs...)
		case *ast.FragmentSpread:
			frag := doc.Fragments.ForName(s.Name)
			if frag == nil {
				return nil, fmt.Errorf("unknown fragment %q", s.Name)
			}
			if active[s.Name] {
				return nil, fmt.Errorf("fragment %q spreads itself", s.Name)
			}
			active[s.Name] = true
			fs, err := rootFields(doc, frag.SelectionSet, active)
			delete(active, s.Name)
			if err != nil {
				return nil, err
			}
			out = append(out, fs...)
		}
		if len(out) > MaxOperations {
			return nil, fmt.Errorf("request carries more than 200 operations")
		}
	}
	return out, nil
}

// gqlValue converts a GraphQL literal to the same Go values JSON decoding
// produces (json.Number for numbers), resolving variables.
func gqlValue(v *ast.Value, vars map[string]any) (any, error) {
	if v == nil {
		return nil, nil
	}
	switch v.Kind {
	case ast.Variable:
		return vars[v.Raw], nil
	case ast.IntValue, ast.FloatValue:
		return json.Number(v.Raw), nil
	case ast.StringValue, ast.BlockValue, ast.EnumValue:
		return v.Raw, nil
	case ast.BooleanValue:
		return v.Raw == "true", nil
	case ast.NullValue:
		return nil, nil
	case ast.ListValue:
		out := make([]any, 0, len(v.Children))
		for _, c := range v.Children {
			cv, err := gqlValue(c.Value, vars)
			if err != nil {
				return nil, err
			}
			out = append(out, cv)
		}
		return out, nil
	case ast.ObjectValue:
		out := make(map[string]any, len(v.Children))
		for _, c := range v.Children {
			if _, dup := out[c.Name]; dup {
				return nil, fmt.Errorf("object field %q repeated", c.Name)
			}
			cv, err := gqlValue(c.Value, vars)
			if err != nil {
				return nil, err
			}
			out[c.Name] = cv
		}
		return out, nil
	}
	return nil, fmt.Errorf("unsupported GraphQL value kind %v", v.Kind)
}
