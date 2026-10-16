package decode

import (
	"fmt"

	"github.com/rakeshnitb23/opfence/internal/request"
)

// MCP JSON-RPC methods other than tools/call that only read state or manage
// the session. The engine classifies them as read.
var mcpReadMethods = map[string]bool{
	"initialize":                       true,
	"ping":                             true,
	"tools/list":                       true,
	"resources/list":                   true,
	"resources/templates/list":         true,
	"resources/read":                   true,
	"resources/subscribe":              true,
	"resources/unsubscribe":            true,
	"prompts/list":                     true,
	"prompts/get":                      true,
	"completion/complete":              true,
	"logging/setLevel":                 true,
	"notifications/initialized":        true,
	"notifications/cancelled":          true,
	"notifications/progress":           true,
	"notifications/roots/list_changed": true,
}

// IsMCPReadMethod reports whether an MCP method (other than tools/call) is
// known to be read-only or session housekeeping.
func IsMCPReadMethod(m string) bool { return mcpReadMethods[m] }

// MCPResponse is the MCPMethod given to JSON-RPC responses a client sends
// back to a server (answers to sampling or elicitation requests).
const MCPResponse = "(response)"

func decodeMCP(r *request.Request) []Operation {
	base := Operation{Protocol: MCP, Method: r.Method, Path: r.Path}
	fail := func(msg string) []Operation {
		op := base
		op.Error = msg
		return []Operation{op}
	}
	if r.Method != "POST" {
		// Streamable HTTP uses GET to open a server-sent event stream and
		// DELETE to end a session; neither carries a tool call.
		op := base
		op.MCPMethod = "http " + r.Method
		return []Operation{op}
	}
	if r.BodyErr != nil {
		return fail(r.BodyErr.Error())
	}
	v, err := parseJSON(r.Body)
	if err != nil {
		return fail(err.Error())
	}
	var msgs []any
	switch t := v.(type) {
	case map[string]any:
		msgs = []any{t}
	case []any:
		if len(t) == 0 {
			return fail("empty JSON-RPC batch")
		}
		msgs = t
	default:
		return fail("MCP body is not a JSON-RPC message")
	}
	var ops []Operation
	for i, m := range msgs {
		obj, ok := m.(map[string]any)
		if !ok {
			return fail(fmt.Sprintf("JSON-RPC batch element %d is not an object", i))
		}
		op, err := mcpOperation(obj, base)
		if err != nil {
			return fail(err.Error())
		}
		ops = append(ops, op)
	}
	return ops
}

func mcpOperation(obj map[string]any, base Operation) (Operation, error) {
	op := base
	if v, _ := obj["jsonrpc"].(string); v != "2.0" {
		return op, fmt.Errorf(`not a JSON-RPC 2.0 message`)
	}
	method, hasMethod := obj["method"]
	if !hasMethod {
		if _, ok := obj["result"]; ok {
			op.MCPMethod = MCPResponse
			return op, nil
		}
		if _, ok := obj["error"]; ok {
			op.MCPMethod = MCPResponse
			return op, nil
		}
		return op, fmt.Errorf("JSON-RPC message has no method")
	}
	name, ok := method.(string)
	if !ok || name == "" {
		return op, fmt.Errorf("JSON-RPC method is not a string")
	}
	op.MCPMethod = name
	if name != "tools/call" {
		return op, nil
	}
	params, ok := obj["params"].(map[string]any)
	if !ok {
		return op, fmt.Errorf("tools/call without params")
	}
	tool, ok := params["name"].(string)
	if !ok || tool == "" {
		return op, fmt.Errorf("tools/call without a tool name")
	}
	op.Tool = tool
	switch a := params["arguments"].(type) {
	case map[string]any:
		op.Args = a
	case nil:
		op.Args = map[string]any{}
	default:
		return op, fmt.Errorf("tools/call arguments is not an object")
	}
	return op, nil
}
