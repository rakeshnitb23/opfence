// Package decode turns a request into the operations it performs: REST
// method and path, GraphQL root fields, MCP tool calls, AWS actions, git
// ref updates.
//
// Decoders fail closed. When a decoder cannot be sure what a request does
// (a parse error, a body too large to inspect, an unsupported encoding), it
// returns an Operation with Error set, which the engine classifies as
// unknown. See docs/ARCHITECTURE.md §3.
package decode

import (
	"encoding/base64"
	"github.com/rakeshnitb23/opfence/internal/request"
	"net/url"
	"slices"
	"strings"
)

// Protocols.
const (
	REST    = "rest"
	GraphQL = "graphql"
	MCP     = "mcp"
	AWS     = "aws"
	Git     = "git"
)

// MaxOperations caps how many operations one request may carry (GraphQL
// aliases and batches, JSON-RPC batches). More is treated as unknown.
const MaxOperations = 200

// Operation is one action a request asks a provider to perform.
type Operation struct {
	Protocol string
	Method   string // HTTP method
	Path     string // raw request path

	GraphQLType string // query, mutation or subscription
	Field       string // GraphQL root field name (never the alias)
	// Selected lists every field name selected under the root field, at
	// any depth, fragments flattened (never aliases).
	Selected []string

	Tool      string // MCP tool name, for tools/call
	MCPMethod string // JSON-RPC method, or "http GET" etc. for non-POST requests

	Service string // AWS signing name, from the credential scope; git service
	Action  string // AWS action, empty when it cannot be determined; git command

	// Args holds decoded arguments: GraphQL field arguments with variables
	// resolved, MCP tool arguments, AWS parameters, and for REST "query"
	// and "body" maps (path parameters are added by the catalog matcher).
	Args map[string]any

	// Error is set when the decoder could not be sure what the request
	// does. The engine classifies such operations as unknown.
	Error string
	// BodyErr is set on REST operations whose body could not be inspected.
	// Rules that depend on the body then classify as unknown.
	BodyErr string
}

// Hints tell the decoder what a provider speaks.
type Hints struct {
	GraphQLPaths []string    // request paths that carry GraphQL
	SigV4        bool        // AWS SigV4-signed API
	MCP          bool        // remote MCP server
	MCPPaths     []string    // paths that carry MCP, with everything under them; empty means every path
	Git          bool        // host serves git's smart HTTP protocol
	HeaderArgs   []HeaderArg // headers whose non-secret parts become arguments
}

// HeaderArg turns the non-secret parts of a request header into an
// argument that rules can name, such as the database a connection string
// points at. The parts never include a password.
type HeaderArg struct {
	Header string // header name
	Arg    string // argument name
	// Parse says how to read the value: "url" gives host, port, user and
	// database (the path); "basic" gives the username of HTTP Basic auth.
	Parse string
}

// Decode returns the operations in r. It always returns at least one.
func Decode(r *request.Request, h Hints) []Operation {
	var ops []Operation
	switch {
	case h.SigV4:
		ops = decodeAWS(r)
	case h.MCP && isMCPPath(r.Path, h.MCPPaths):
		ops = decodeMCP(r)
	case h.Git && isGitPath(r.Path):
		ops = decodeGit(r)
	case isGraphQLPath(r.Path, h.GraphQLPaths):
		ops = decodeGraphQL(r)
	default:
		ops = decodeREST(r)
	}
	if len(ops) == 0 {
		ops = []Operation{failed(r, "", "request carries no operation")}
	}
	if len(ops) > MaxOperations {
		ops = []Operation{failed(r, ops[0].Protocol, "request carries more than 200 operations")}
	}
	for _, ha := range h.HeaderArgs {
		v := headerArg(r.Header.Get(ha.Header), ha.Parse)
		if v == nil {
			continue
		}
		for i := range ops {
			if ops[i].Args == nil {
				ops[i].Args = map[string]any{}
			}
			ops[i].Args[ha.Arg] = v
		}
	}
	return ops
}

// headerArg reads the non-secret parts of a header value, or returns nil
// when it holds none. Passwords are never read.
func headerArg(v, parse string) map[string]any {
	v = strings.TrimSpace(v)
	if v == "" {
		return nil
	}
	switch parse {
	case "url":
		u, err := url.Parse(v)
		if err != nil || u.Host == "" {
			return nil
		}
		out := map[string]any{"host": strings.ToLower(u.Hostname())}
		if p := u.Port(); p != "" {
			out["port"] = p
		}
		if u.User != nil && u.User.Username() != "" {
			out["user"] = u.User.Username()
		}
		if db := strings.TrimPrefix(u.Path, "/"); db != "" {
			out["database"] = db
		}
		return out
	case "basic":
		scheme, cred, ok := strings.Cut(v, " ")
		if !ok || !strings.EqualFold(scheme, "Basic") {
			return nil
		}
		raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(cred))
		if err != nil {
			return nil
		}
		user, _, ok := strings.Cut(string(raw), ":")
		if !ok || user == "" {
			return nil
		}
		return map[string]any{"username": user}
	}
	return nil
}

func failed(r *request.Request, protocol, msg string) Operation {
	return Operation{Protocol: protocol, Method: r.Method, Path: r.Path, Error: msg}
}

// isMCPPath reports whether a request to a remote MCP server's host is an
// MCP request: its path is one of paths or under one, compared segment by
// segment after dot segments are resolved. With no paths, every path is.
// The path counts as MCP if it is under one either as sent or with its
// percent-encoding decoded first, so /models/%2e%2e%2fmcp, which a server
// that decodes before routing reads as /mcp, is not read as REST. A path
// that cannot be resolved counts as MCP, whose decoder then fails it.
func isMCPPath(rawPath string, paths []string) bool {
	if len(paths) == 0 {
		return true
	}
	segs, ok := request.NormalizePath(rawPath)
	if !ok {
		return true
	}
	forms := [][]string{segs}
	if dec, err := url.PathUnescape(rawPath); err != nil {
		return true
	} else if dec != rawPath {
		ds, ok := request.NormalizePath(dec)
		if !ok {
			return true
		}
		forms = append(forms, ds)
	}
	for _, p := range paths {
		ps, ok := request.NormalizePath(p)
		if !ok {
			continue
		}
		for _, f := range forms {
			if len(ps) <= len(f) && slices.Equal(f[:len(ps)], ps) {
				return true
			}
		}
	}
	return false
}

func isGraphQLPath(rawPath string, paths []string) bool {
	if len(paths) == 0 {
		return false
	}
	segs, ok := request.NormalizePath(rawPath)
	if !ok {
		return false
	}
	norm := "/" + joinSegs(segs)
	for _, p := range paths {
		ps, ok := request.NormalizePath(p)
		if ok && norm == "/"+joinSegs(ps) {
			return true
		}
	}
	return false
}

func joinSegs(s []string) string {
	out := ""
	for i, seg := range s {
		if i > 0 {
			out += "/"
		}
		out += seg
	}
	return out
}
