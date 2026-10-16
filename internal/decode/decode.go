// Package decode turns a request into the operations it performs: REST
// method and path, GraphQL root fields, MCP tool calls, AWS actions.
//
// Decoders fail closed. When a decoder cannot be sure what a request does
// (a parse error, a body too large to inspect, an unsupported encoding), it
// returns an Operation with Error set, which the engine classifies as
// unknown. See docs/ARCHITECTURE.md §3.
package decode

import (
	"github.com/rakeshnitb23/opfence/internal/request"
)

// Protocols.
const (
	REST    = "rest"
	GraphQL = "graphql"
	MCP     = "mcp"
	AWS     = "aws"
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

	Tool      string // MCP tool name, for tools/call
	MCPMethod string // JSON-RPC method, or "http GET" etc. for non-POST requests

	Service string // AWS signing name, from the credential scope
	Action  string // AWS action; empty when it cannot be determined

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
	GraphQLPaths []string // request paths that carry GraphQL
	SigV4        bool     // AWS SigV4-signed API
	MCP          bool     // remote MCP server
}

// Decode returns the operations in r. It always returns at least one.
func Decode(r *request.Request, h Hints) []Operation {
	var ops []Operation
	switch {
	case h.SigV4:
		ops = decodeAWS(r)
	case h.MCP:
		ops = decodeMCP(r)
	case isGraphQLPath(r.Path, h.GraphQLPaths):
		ops = decodeGraphQL(r)
	default:
		ops = []Operation{decodeREST(r)}
	}
	if len(ops) == 0 {
		ops = []Operation{failed(r, "", "request carries no operation")}
	}
	if len(ops) > MaxOperations {
		ops = []Operation{failed(r, ops[0].Protocol, "request carries more than 200 operations")}
	}
	return ops
}

func failed(r *request.Request, protocol, msg string) Operation {
	return Operation{Protocol: protocol, Method: r.Method, Path: r.Path, Error: msg}
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
