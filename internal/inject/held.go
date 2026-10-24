package inject

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
)

// HeldPrefix starts every token that stands for a held value.
const HeldPrefix = "opfence-held-"

// MaxHeld caps the values one session holds. A response that would hold
// more is withheld.
const MaxHeld = 10000

const heldAlphabet = "abcdefghijklmnopqrstuvwxyz234567"

// heldTokenLen is the length of a token: the prefix and 26 characters of
// base32, 130 random bits.
const heldTokenLen = len(HeldPrefix) + 26

// Held keeps the values the proxy replaced with tokens in responses to rules
// with response.hold (stage 27b): secrets that live in an object's
// configuration, such as a Cloud Run service's environment variables, which
// clients read, change and write back whole. The agent sees a token; a
// later request may carry the token back only to the field it came from on
// the same object, where the proxy swaps the value in again, so a
// read-modify-write keeps the values without the agent ever seeing them.
// Values live in memory for the session, never in the keychain.
type Held struct {
	mu      sync.Mutex
	byToken map[string]heldValue
	byValue map[heldValue]string
}

// heldValue is a value and where it was read: the provider, the object (the
// request path it was read from) and the hold path it was found under.
type heldValue struct {
	provider, object, path, value string
}

// NewHeld returns an empty store.
func NewHeld() *Held {
	return &Held{byToken: map[string]heldValue{}, byValue: map[heldValue]string{}}
}

// Hold returns the token for a value read from object under path. The same
// value read again from the same place gets the same token, so a client
// polling an object sees stable values.
func (h *Held) Hold(provider, object, path, value string) (string, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	k := heldValue{provider, object, path, value}
	if t, ok := h.byValue[k]; ok {
		return t, nil
	}
	if len(h.byToken) >= MaxHeld {
		return "", fmt.Errorf("this session already holds %d values", MaxHeld)
	}
	b := make([]byte, heldTokenLen-len(HeldPrefix))
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	for i := range b {
		b[i] = heldAlphabet[b[i]%32]
	}
	t := HeldPrefix + string(b)
	h.byToken[t], h.byValue[k] = k, t
	return t, nil
}

// Len returns how many values are held.
func (h *Held) Len() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.byToken)
}

// ErrHeld is wrapped by every error Restore returns, so callers can tell
// a request that carries held tokens wrongly from other failures.
var ErrHeld = errors.New("held value")

// Restore swaps the held tokens in a JSON request body for their values.
// A token is swapped only where every one of these holds: it is a whole
// string value, found at or below one of the request's restore paths, held
// by this provider from this same object (request path) under that same
// path. Anything else that contains HeldPrefix (a token moved to another
// field or object, a token from an earlier session, one inside a longer
// string, in a key, or escaped) is an error, because sending it would write
// the token text in place of the value, or the value somewhere it was not.
// The body is changed only where tokens stand, byte for byte elsewhere. It
// returns the new body and how many tokens it swapped; a body without
// HeldPrefix comes back unchanged.
func (h *Held) Restore(provider, object string, restore []string, body []byte) ([]byte, int, error) {
	if !bytes.Contains(body, []byte(HeldPrefix)) {
		return body, 0, nil
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil || dec.More() {
		return nil, 0, fmt.Errorf("%w: the body carries %s… but is not one JSON value", ErrHeld, HeldPrefix)
	}
	h.mu.Lock()
	defer h.mu.Unlock()

	// Every string that contains the prefix, with where it is.
	found := map[string]int{} // token -> occurrences at allowed places
	var bad error
	var visit func(v any, path []string)
	visit = func(v any, path []string) {
		if bad != nil {
			return
		}
		switch t := v.(type) {
		case string:
			if !strings.Contains(t, HeldPrefix) {
				return
			}
			hv, ok := h.byToken[t]
			switch {
			case !ok:
				bad = fmt.Errorf("%w: %s is not a value this session holds (a token from an earlier session, or one changed)", ErrHeld, clipToken(t))
			case hv.provider != provider || hv.object != object:
				bad = fmt.Errorf("%w: %s was read from %s %s; Opfence writes a held value back only to the object it came from", ErrHeld, clipToken(t), hv.provider, hv.object)
			case !under(path, hv.path):
				bad = fmt.Errorf("%w: %s belongs at %s, not at %s", ErrHeld, clipToken(t), hv.path, strings.Join(path, "."))
			case !containsPath(restore, hv.path):
				bad = fmt.Errorf("%w: this request does not take held values at %s", ErrHeld, hv.path)
			default:
				found[t]++
			}
		case map[string]any:
			for k, el := range t {
				if strings.Contains(k, HeldPrefix) {
					bad = fmt.Errorf("%w: a key carries %s…", ErrHeld, HeldPrefix)
					return
				}
				visit(el, append(path[:len(path):len(path)], k))
			}
		case []any:
			for _, el := range t {
				visit(el, path) // paths step into lists, as rule paths do
			}
		}
	}
	visit(v, nil)
	if bad != nil {
		return nil, 0, bad
	}
	// Swap in one pass over the body, so a value swapped in is never read
	// again as a token. Each token must appear in the bytes exactly as
	// often as the parse found it at an allowed place; an escaped spelling
	// would otherwise reach the API unswapped.
	var out bytes.Buffer
	seen := map[string]int{}
	rest := body
	for {
		i := bytes.Index(rest, []byte(`"`+HeldPrefix))
		if i < 0 {
			out.Write(rest)
			break
		}
		end := i + 1 + heldTokenLen
		if end >= len(rest) || rest[end] != '"' {
			return nil, 0, fmt.Errorf("%w: a string carries %s… that is not a whole token", ErrHeld, HeldPrefix)
		}
		t := string(rest[i+1 : end])
		if found[t] == 0 {
			return nil, 0, fmt.Errorf("%w: %s is written in a form Opfence does not swap", ErrHeld, clipToken(t))
		}
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		enc.SetEscapeHTML(false)
		if err := enc.Encode(h.byToken[t].value); err != nil {
			return nil, 0, err
		}
		out.Write(rest[:i])
		out.Write(bytes.TrimSuffix(buf.Bytes(), []byte("\n")))
		seen[t]++
		rest = rest[end+1:]
	}
	n := 0
	for t, count := range found {
		if seen[t] != count {
			return nil, 0, fmt.Errorf("%w: %s is written in a form Opfence does not swap", ErrHeld, clipToken(t))
		}
		n += count
	}
	return out.Bytes(), n, nil
}

// under reports whether path is p or below it.
func under(path []string, p string) bool {
	ps := strings.Split(p, ".")
	if len(path) < len(ps) {
		return false
	}
	for i, s := range ps {
		if path[i] != s {
			return false
		}
	}
	return true
}

func containsPath(paths []string, p string) bool {
	for _, q := range paths {
		if q == p {
			return true
		}
	}
	return false
}

// clipToken shortens a string that carries a token for an error message.
func clipToken(s string) string {
	if i := strings.Index(s, HeldPrefix); i >= 0 && len(s) > i+heldTokenLen {
		s = s[i : i+heldTokenLen]
	}
	if len(s) > heldTokenLen {
		s = s[:heldTokenLen]
	}
	return s
}
