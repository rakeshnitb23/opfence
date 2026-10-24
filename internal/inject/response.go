package inject

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/rakeshnitb23/opfence/internal/catalog"
)

// MaxTransformBody is the largest response body Transform reads. Responses
// to rules with a response transform are buffered whole; a larger one is
// refused rather than passed through.
const MaxTransformBody = 8 << 20

// TransformResult says what Transform changed.
type TransformResult struct {
	// Hits counts, per path in the rule's response, the values found.
	Hits map[string]int
	// Minted lists the placeholders handed out for minted tokens.
	Minted []string
}

// Funcs are what Transform calls for minted and held values.
type Funcs struct {
	// Mint returns the placeholder for a token at a mint path.
	Mint func(value string) (string, error)
	// Hold returns the token for a string found at or below the hold
	// path path.
	Hold func(path, value string) (string, error)
}

// Transform applies a rule's response transform to a JSON body: every
// string at or below a redact path becomes catalog.RedactedValue, the value
// at a clear path becomes the empty value of its type, each string at a
// mint path is replaced with what Mint returns for it, and each non-empty
// string at or below a hold path with what Hold returns. A path steps into
// every element of a list on its way, as rule conditions do. The body is
// re-encoded; anything that is not one JSON value is an error.
func Transform(body []byte, x *catalog.Response, fn Funcs) ([]byte, TransformResult, error) {
	res := TransformResult{Hits: map[string]int{}}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, res, fmt.Errorf("the response is not JSON: %w", err)
	}
	if dec.More() {
		return nil, res, errors.New("the response holds more than one JSON value")
	}
	var mintErr error
	for _, p := range x.Redact {
		v = walk(v, strings.Split(p, "."), func(at any) any {
			res.Hits[p]++
			return redact(at)
		})
	}
	for _, p := range x.Clear {
		v = walk(v, strings.Split(p, "."), func(at any) any {
			res.Hits[p]++
			return empty(at)
		})
	}
	for _, p := range x.Mint {
		v = walk(v, strings.Split(p, "."), func(at any) any {
			s, ok := at.(string)
			if !ok || s == "" {
				return at
			}
			res.Hits[p]++
			ph, err := fn.Mint(s)
			if err != nil {
				mintErr = err
				return catalog.RedactedValue
			}
			res.Minted = append(res.Minted, ph)
			return ph
		})
	}
	for _, p := range x.Hold {
		v = walk(v, strings.Split(p, "."), func(at any) any {
			res.Hits[p]++
			return hold(at, func(s string) string {
				t, err := fn.Hold(p, s)
				if err != nil {
					mintErr = err
					return catalog.RedactedValue
				}
				return t
			})
		})
	}
	if mintErr != nil {
		return nil, res, mintErr
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, res, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), res, nil
}

// walk replaces the value at path in v with f's result. A "**" step stands
// for any number of keys, none included, so "**.env.value" reaches every
// env.value at any depth: the long-running operations of Google's APIs
// carry the resource they act on in untyped metadata and response fields.
func walk(v any, path []string, f func(any) any) any {
	if len(path) == 0 {
		return f(v)
	}
	if path[0] == "**" {
		switch t := v.(type) {
		case map[string]any:
			walk(t, path[1:], f) // ** as no keys; t changes in place
			for k, el := range t {
				t[k] = walk(el, path, f)
			}
		case []any:
			// Not here as well: the elements are walked with the rest of
			// the path as they are reached, since lists take no step.
			for i, el := range t {
				t[i] = walk(el, path, f)
			}
		}
		return v
	}
	switch t := v.(type) {
	case map[string]any:
		if next, ok := t[path[0]]; ok {
			t[path[0]] = walk(next, path[1:], f)
		}
	case []any:
		for i, el := range t {
			t[i] = walk(el, path, f)
		}
	}
	return v
}

// empty returns the empty value of v's type. Numbers, booleans and null
// are kept: they cannot hold a token.
func empty(v any) any {
	switch v.(type) {
	case string:
		return ""
	case map[string]any:
		return map[string]any{}
	case []any:
		return []any{}
	}
	return v
}

// redact replaces every string in v, at any depth.
func redact(v any) any {
	switch t := v.(type) {
	case string:
		if t == "" {
			return t
		}
		return catalog.RedactedValue
	case map[string]any:
		for k, el := range t {
			t[k] = redact(el)
		}
	case []any:
		for i, el := range t {
			t[i] = redact(el)
		}
	}
	return v
}

// hold replaces every non-empty string in v, at any depth, with f's
// result. Keys are kept: they name values, as an environment variable's
// name does.
func hold(v any, f func(string) string) any {
	switch t := v.(type) {
	case string:
		if t == "" {
			return t
		}
		return f(t)
	case map[string]any:
		for k, el := range t {
			t[k] = hold(el, f)
		}
	case []any:
		for i, el := range t {
			t[i] = hold(el, f)
		}
	}
	return v
}
