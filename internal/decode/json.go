package decode

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

const maxJSONDepth = 64

// parseJSON decodes one JSON value, keeping numbers as json.Number and
// rejecting duplicate object keys, trailing data and deep nesting.
//
// Duplicate keys matter: encoding/json keeps the last value while other
// servers keep the first, so {"query":"safe","query":"mutation ..."} could
// be read one way by Opfence and another way by the API.
func parseJSON(data []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	v, err := parseValue(dec, 0)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("trailing data after JSON value")
	}
	return v, nil
}

func parseValue(dec *json.Decoder, depth int) (any, error) {
	if depth > maxJSONDepth {
		return nil, fmt.Errorf("JSON nested deeper than %d levels", maxJSONDepth)
	}
	tok, err := dec.Token()
	if err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}
	switch t := tok.(type) {
	case json.Delim:
		switch t {
		case '{':
			m := map[string]any{}
			for dec.More() {
				kt, err := dec.Token()
				if err != nil {
					return nil, fmt.Errorf("invalid JSON: %w", err)
				}
				k, ok := kt.(string)
				if !ok {
					return nil, fmt.Errorf("invalid JSON object key")
				}
				if _, dup := m[k]; dup {
					return nil, fmt.Errorf("duplicate JSON key %q", k)
				}
				v, err := parseValue(dec, depth+1)
				if err != nil {
					return nil, err
				}
				m[k] = v
			}
			if _, err := dec.Token(); err != nil {
				return nil, fmt.Errorf("invalid JSON: %w", err)
			}
			return m, nil
		case '[':
			a := []any{}
			for dec.More() {
				v, err := parseValue(dec, depth+1)
				if err != nil {
					return nil, err
				}
				a = append(a, v)
			}
			if _, err := dec.Token(); err != nil {
				return nil, fmt.Errorf("invalid JSON: %w", err)
			}
			return a, nil
		}
		return nil, fmt.Errorf("invalid JSON delimiter %v", t)
	default:
		return t, nil // string, json.Number, bool or nil
	}
}
