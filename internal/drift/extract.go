package drift

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/vektah/gqlparser/v2/ast"
	"github.com/vektah/gqlparser/v2/parser"
	"go.yaml.in/yaml/v3"

	"github.com/rakeshnitb23/opfence/internal/catalog"
)

// Extract lists the operations a schema defines. hosts are the provider's
// hosts: OpenAPI operations whose own servers are all elsewhere are marked
// Foreign.
func Extract(sc catalog.SchemaSource, hosts []string, data []byte) ([]Op, error) {
	var ops []Op
	var err error
	switch sc.Kind {
	case "openapi":
		ops, err = extractOpenAPI(sc, hosts, data)
	case "graphql":
		ops, err = extractGraphQL(data)
	case "heroku":
		ops, err = extractHeroku(sc, data)
	case "botocore":
		ops, err = extractBotocore(sc, data)
	case "discovery":
		ops, err = extractDiscovery(sc, data)
	default:
		return nil, fmt.Errorf("unknown schema kind %q", sc.Kind)
	}
	if err != nil {
		return nil, err
	}
	if len(ops) == 0 {
		return nil, errors.New("the schema defines no operations")
	}
	for i := range ops {
		ops[i].Partial = sc.Coverage == "partial"
	}
	return ops, nil
}

// decodeDoc parses JSON or YAML into plain maps and slices.
func decodeDoc(data []byte) (map[string]any, error) {
	var doc map[string]any
	if t := bytes.TrimSpace(data); len(t) > 0 && t[0] == '{' {
		if err := json.Unmarshal(data, &doc); err != nil {
			return nil, err
		}
		return doc, nil
	}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		// Published schemas sometimes repeat a key (MongoDB's App Services
		// spec gives some operations "deprecated: true" three times), which
		// the strict decoder refuses. Read them as most YAML parsers do, the
		// last value winning.
		var n yaml.Node
		if yaml.Unmarshal(data, &n) != nil {
			return nil, err
		}
		v, lerr := nodeValue(&n, 0)
		m, ok := v.(map[string]any)
		if lerr != nil || !ok {
			return nil, err
		}
		return m, nil
	}
	return doc, nil
}

// nodeValue converts a YAML node to the values yaml.Unmarshal gives, with
// a repeated mapping key keeping its last value.
func nodeValue(n *yaml.Node, depth int) (any, error) {
	if depth > 200 {
		return nil, errors.New("YAML nested too deeply")
	}
	switch n.Kind {
	case yaml.DocumentNode:
		if len(n.Content) == 0 {
			return nil, nil
		}
		return nodeValue(n.Content[0], depth+1)
	case yaml.AliasNode:
		return nodeValue(n.Alias, depth+1)
	case yaml.SequenceNode:
		out := make([]any, 0, len(n.Content))
		for _, c := range n.Content {
			v, err := nodeValue(c, depth+1)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
		}
		return out, nil
	case yaml.MappingNode:
		out := map[string]any{}
		for i := 0; i+1 < len(n.Content); i += 2 {
			k, v := n.Content[i], n.Content[i+1]
			if k.Kind == yaml.ScalarNode && k.Tag == "!!merge" {
				continue // merge keys do not appear in the schemas read here
			}
			val, err := nodeValue(v, depth+1)
			if err != nil {
				return nil, err
			}
			out[k.Value] = val
		}
		return out, nil
	case yaml.ScalarNode:
		var v any
		if err := n.Decode(&v); err != nil {
			return nil, err
		}
		return v, nil
	}
	return nil, fmt.Errorf("unexpected YAML node kind %d", n.Kind)
}

var httpMethods = []string{"get", "put", "post", "delete", "patch", "head", "options"}

func extractOpenAPI(sc catalog.SchemaSource, hosts []string, data []byte) ([]Op, error) {
	doc, err := decodeDoc(data)
	if err != nil {
		return nil, err
	}
	base := ""
	switch {
	case doc["swagger"] != nil:
		base, _ = doc["basePath"].(string)
	case doc["openapi"] != nil:
		if servers, _ := doc["servers"].([]any); len(servers) > 0 {
			base, _ = serverBase(servers[:1], nil)
		}
	default:
		return nil, errors.New("not an OpenAPI or Swagger document")
	}
	if sc.Prefix != "" {
		base = sc.Prefix
	}
	base = strings.TrimSuffix(base, "/")
	paths, _ := doc["paths"].(map[string]any)
	var ops []Op
	for _, p := range sortedKeys(paths) {
		item, _ := paths[p].(map[string]any)
		if ref, _ := item["$ref"].(string); ref != "" && !strings.HasPrefix(ref, "#") {
			return nil, fmt.Errorf("path %s is a $ref to another file; list the bundled schema", p)
		}
		itemServers, _ := item["servers"].([]any)
		for _, m := range httpMethods {
			raw, ok := item[m]
			if !ok {
				continue
			}
			op := Op{Kind: "rest", Method: strings.ToUpper(m), Path: base + p}
			opDoc, _ := raw.(map[string]any)
			servers, _ := opDoc["servers"].([]any)
			if servers == nil {
				servers = itemServers
			}
			if servers != nil {
				// The operation is served elsewhere: its own server's path
				// replaces the document's base, and a server on another
				// host takes it out of the provider's view.
				b, ok := serverBase(servers, hosts)
				op.Path, op.Foreign = strings.TrimSuffix(b, "/")+p, !ok
			}
			if ref, _ := opDoc["$ref"].(string); ref != "" && !strings.HasPrefix(ref, "#") {
				op.Ref = resolveRef(sc.URL, ref)
			}
			ops = append(ops, op)
		}
	}
	return ops, nil
}

// serverBase returns the path of the first server on one of hosts (any
// server when hosts is nil; a relative URL is on the document's own host,
// and an absolute one with no host, such as a presigned upload URL, is on
// none), and whether there was one.
func serverBase(servers []any, hosts []string) (string, bool) {
	for _, sv := range servers {
		s, _ := sv.(map[string]any)
		raw, _ := s["url"].(string)
		u, err := url.Parse(braceRe.ReplaceAllString(raw, "x"))
		if err != nil {
			continue
		}
		relative := u.Scheme == "" && u.Host == ""
		if hosts == nil || relative || onHosts(u.Hostname(), hosts) {
			return u.Path, true
		}
	}
	return "", false
}

// onHosts reports whether host is one of hosts (with *.example.com
// wildcards).
func onHosts(host string, hosts []string) bool {
	host = strings.ToLower(host)
	for _, h := range hosts {
		if h == host || (strings.HasPrefix(h, "*.") && strings.HasSuffix(host, h[1:])) {
			return true
		}
	}
	return false
}

// resolveRef makes a $ref to another file absolute, dropping any fragment.
func resolveRef(base, ref string) string {
	ref, _, _ = strings.Cut(ref, "#")
	b, err := url.Parse(base)
	if err != nil {
		return ""
	}
	r, err := url.Parse(ref)
	if err != nil {
		return ""
	}
	return b.ResolveReference(r).String()
}

func extractGraphQL(data []byte) ([]Op, error) {
	if t := bytes.TrimSpace(data); len(t) > 0 && t[0] == '{' {
		return extractIntrospection(data)
	}
	doc, err := parser.ParseSchema(&ast.Source{Name: "schema", Input: string(data)})
	if err != nil {
		return nil, err
	}
	roots := map[string]string{"Query": "query", "Mutation": "mutation", "Subscription": "subscription"}
	for _, list := range []ast.SchemaDefinitionList{doc.Schema, doc.SchemaExtension} {
		for _, sd := range list {
			for _, ot := range sd.OperationTypes {
				roots[ot.Type] = string(ot.Operation)
			}
		}
	}
	var ops []Op
	for _, list := range []ast.DefinitionList{doc.Definitions, doc.Extensions} {
		for _, def := range list {
			typ, ok := roots[def.Name]
			if !ok || def.Kind != ast.Object {
				continue
			}
			for _, f := range def.Fields {
				ops = append(ops, Op{Kind: "graphql", Type: typ, Field: f.Name})
			}
		}
	}
	return ops, nil
}

func extractIntrospection(data []byte) ([]Op, error) {
	type named struct {
		Name string `json:"name"`
	}
	var doc struct {
		Data struct {
			Schema json.RawMessage `json:"__schema"`
		} `json:"data"`
		Schema json.RawMessage `json:"__schema"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	raw := doc.Schema
	if raw == nil {
		raw = doc.Data.Schema
	}
	if raw == nil {
		return nil, errors.New("not a GraphQL introspection result")
	}
	var s struct {
		QueryType        *named `json:"queryType"`
		MutationType     *named `json:"mutationType"`
		SubscriptionType *named `json:"subscriptionType"`
		Types            []struct {
			Name   string  `json:"name"`
			Fields []named `json:"fields"`
		} `json:"types"`
	}
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, err
	}
	roots := map[string]string{}
	for typ, n := range map[string]*named{"query": s.QueryType, "mutation": s.MutationType, "subscription": s.SubscriptionType} {
		if n != nil {
			roots[n.Name] = typ
		}
	}
	var ops []Op
	for _, t := range s.Types {
		typ, ok := roots[t.Name]
		if !ok {
			continue
		}
		for _, f := range t.Fields {
			ops = append(ops, Op{Kind: "graphql", Type: typ, Field: f.Name})
		}
	}
	return ops, nil
}

// extractHeroku reads a JSON hyper-schema's links.
func extractHeroku(sc catalog.SchemaSource, data []byte) ([]Op, error) {
	var doc struct {
		Definitions map[string]struct {
			Links []struct {
				Href   string `json:"href"`
				Method string `json:"method"`
			} `json:"links"`
		} `json:"definitions"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	var ops []Op
	for _, name := range sortedKeys(doc.Definitions) {
		for _, l := range doc.Definitions[name].Links {
			if l.Href == "" || l.Method == "" {
				continue
			}
			ops = append(ops, Op{Kind: "rest", Method: strings.ToUpper(l.Method), Path: sc.Prefix + l.Href})
		}
	}
	return ops, nil
}

// extractBotocore reads an AWS service model. Paths are kept only for
// REST protocols, where rules can match by method and path.
func extractBotocore(sc catalog.SchemaSource, data []byte) ([]Op, error) {
	var doc struct {
		Metadata struct {
			Protocol string `json:"protocol"`
		} `json:"metadata"`
		Operations map[string]struct {
			HTTP struct {
				Method     string `json:"method"`
				RequestURI string `json:"requestUri"`
			} `json:"http"`
		} `json:"operations"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	rest := strings.HasPrefix(doc.Metadata.Protocol, "rest")
	var ops []Op
	for _, name := range sortedKeys(doc.Operations) {
		o := Op{Kind: "aws", Service: sc.Service, Action: name}
		if h := doc.Operations[name].HTTP; rest && h.RequestURI != "" {
			o.Method = strings.ToUpper(h.Method)
			o.Path, _, _ = strings.Cut(h.RequestURI, "?")
		}
		ops = append(ops, o)
	}
	return ops, nil
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// discoveryDoc is the part of a Google API discovery document the check
// reads (https://developers.google.com/discovery/v1/reference/apis).
type discoveryDoc struct {
	Kind        string                       `json:"kind"`
	ServicePath string                       `json:"servicePath"`
	Methods     map[string]discoveryMethod   `json:"methods"`
	Resources   map[string]discoveryResource `json:"resources"`
}

type discoveryResource struct {
	Methods   map[string]discoveryMethod   `json:"methods"`
	Resources map[string]discoveryResource `json:"resources"`
}

type discoveryMethod struct {
	HTTPMethod  string `json:"httpMethod"`
	Path        string `json:"path"`
	FlatPath    string `json:"flatPath"`
	MediaUpload struct {
		Protocols struct {
			Simple    struct{ Path string } `json:"simple"`
			Resumable struct{ Path string } `json:"resumable"`
		} `json:"protocols"`
	} `json:"mediaUpload"`
}

// extractDiscovery reads a Google API discovery document: every method of
// every resource, at any depth, at the document's servicePath followed by
// the method's flatPath (its path when it has none), and the paths its
// media uploads go to (/upload/storage/v1/b/{bucket}/o).
func extractDiscovery(sc catalog.SchemaSource, data []byte) ([]Op, error) {
	var doc discoveryDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	if doc.Kind != "discovery#restDescription" {
		return nil, errors.New("not a Google API discovery document")
	}
	base := "/" + strings.Trim(doc.ServicePath, "/")
	if sc.Prefix != "" {
		base = sc.Prefix
	}
	base = strings.TrimSuffix(base, "/")
	var ops []Op
	seen := map[string]bool{}
	add := func(method, p string) {
		if method == "" || p == "" {
			return
		}
		key := method + " " + p
		if !seen[key] {
			seen[key] = true
			ops = append(ops, Op{Kind: "rest", Method: strings.ToUpper(method), Path: p})
		}
	}
	addMethods := func(ms map[string]discoveryMethod) {
		for _, name := range sortedKeys(ms) {
			m := ms[name]
			p := m.FlatPath
			if p == "" {
				p = m.Path
			}
			add(m.HTTPMethod, base+"/"+discoveryTemplate(strings.TrimPrefix(p, "/")))
			for _, up := range []string{m.MediaUpload.Protocols.Simple.Path, m.MediaUpload.Protocols.Resumable.Path} {
				if up != "" {
					add(m.HTTPMethod, "/"+discoveryTemplate(strings.TrimPrefix(up, "/")))
				}
			}
		}
	}
	var walk func(rs map[string]discoveryResource, depth int) error
	walk = func(rs map[string]discoveryResource, depth int) error {
		if depth > 20 {
			return errors.New("resources nest too deep")
		}
		for _, name := range sortedKeys(rs) {
			addMethods(rs[name].Methods)
			if err := walk(rs[name].Resources, depth+1); err != nil {
				return err
			}
		}
		return nil
	}
	addMethods(doc.Methods)
	if err := walk(doc.Resources, 0); err != nil {
		return nil, err
	}
	return ops, nil
}

// discoveryTemplate turns a discovery path into a rule template: {+name}
// (reserved expansion, which may hold slashes) becomes {name*}.
func discoveryTemplate(p string) string {
	return discoveryReserved.ReplaceAllString(p, "{$1*}")
}

var discoveryReserved = regexp.MustCompile(`\{\+([A-Za-z0-9_]+)\}`)
