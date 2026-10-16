package secrets

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"regexp"
	"strings"
)

// MinLength is the shortest value Opfence will hold. Shorter values are not
// API tokens, and scrubbing them out of responses would hit ordinary text.
const MinLength = 16

var genericPrefix = regexp.MustCompile(`^[A-Za-z]{2,12}_`)

const (
	lower    = "abcdefghijklmnopqrstuvwxyz"
	upper    = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	digits   = "0123456789"
	hexLower = "0123456789abcdef"
	hexUpper = "0123456789ABCDEF"
)

// NewPlaceholder returns a random stand-in for value with the same length
// and shape: the token's prefix (from prefixes, or a generic "abc_"), the
// same alphabet, and punctuation in the same places. Clients that check a
// token's format keep working, and swapping it for the real value never
// changes a request's or response's length. Only the alphabet and the
// punctuation positions are carried over, never which character class sits
// where, so the placeholder says nothing about the secret part of the value.
//
// A JSON Web Token keeps its header and payload, which are not secret and
// which clients may decode, and gets a random signature.
func NewPlaceholder(value string, prefixes []string) (string, error) {
	if len(value) < MinLength {
		return "", errors.New("value is too short to be an API token")
	}
	for range 8 {
		p, err := placeholder(value, prefixes)
		if err != nil {
			return "", err
		}
		if p != value {
			return p, nil
		}
	}
	return "", errors.New("could not make a placeholder different from the value")
}

func placeholder(value string, prefixes []string) (string, error) {
	if head, sig, ok := splitJWT(value); ok {
		r, err := randomLike(sig)
		return head + r, err
	}
	prefix := ""
	for _, p := range prefixes {
		if strings.HasPrefix(value, p) && len(p) > len(prefix) {
			prefix = p
		}
	}
	if prefix == "" {
		prefix = genericPrefix.FindString(value)
	}
	r, err := randomLike(value[len(prefix):])
	return prefix + r, err
}

// randomLike returns a random string shaped like s: letters and digits
// drawn from s's alphabet, other bytes kept in place.
func randomLike(s string) (string, error) {
	alphabet := alphabetOf(s)
	out := []byte(s)
	max := big.NewInt(int64(len(alphabet)))
	for i := range len(out) {
		if !isAlnum(out[i]) {
			continue
		}
		n, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", err
		}
		out[i] = alphabet[n.Int64()]
	}
	return string(out), nil
}

func alphabetOf(s string) string {
	var hasLower, hasUpper, hasDigit, nonHexLower, nonHexUpper bool
	for i := range len(s) {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z':
			hasLower = true
			nonHexLower = nonHexLower || c > 'f'
		case c >= 'A' && c <= 'Z':
			hasUpper = true
			nonHexUpper = nonHexUpper || c > 'F'
		case c >= '0' && c <= '9':
			hasDigit = true
		}
	}
	switch {
	case hasLower && !hasUpper && !nonHexLower:
		return hexLower
	case hasUpper && !hasLower && !nonHexUpper:
		return hexUpper
	}
	a := ""
	if hasLower {
		a += lower
	}
	if hasUpper {
		a += upper
	}
	if hasDigit || a == "" {
		a += digits
	}
	return a
}

func isAlnum(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

// splitJWT splits a JWS compact token into "header.payload." and the
// signature, when the header decodes to a JSON object with an alg.
func splitJWT(v string) (head, sig string, ok bool) {
	parts := strings.Split(v, ".")
	if len(parts) != 3 || parts[2] == "" {
		return "", "", false
	}
	h, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", "", false
	}
	var hdr struct {
		Alg string `json:"alg"`
	}
	if json.Unmarshal(h, &hdr) != nil || hdr.Alg == "" {
		return "", "", false
	}
	return parts[0] + "." + parts[1] + ".", parts[2], true
}
