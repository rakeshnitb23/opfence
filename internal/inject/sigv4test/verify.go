// Package sigv4test checks AWS SigV4 signatures the way AWS does, written
// from AWS's documentation rather than with the SDK that Opfence signs
// with, so tests do not check the signer against itself.
package sigv4test

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

// Creds are the real credentials the fake AWS accepts.
type Creds struct {
	AccessKeyID, SecretAccessKey, SessionToken string
}

// Verify checks a server-side request's Authorization header against
// creds. It reads the body when the request has no X-Amz-Content-Sha256
// header and returns it either way.
func Verify(r *http.Request, creds Creds) ([]byte, error) {
	body, _ := io.ReadAll(r.Body)
	auth := r.Header.Get("Authorization")
	rest, ok := strings.CutPrefix(auth, "AWS4-HMAC-SHA256 ")
	if !ok {
		return body, fmt.Errorf("not a SigV4 Authorization header: %q", auth)
	}
	fields := map[string]string{}
	for _, p := range strings.Split(rest, ",") {
		k, v, _ := strings.Cut(strings.TrimSpace(p), "=")
		fields[k] = v
	}
	scope := strings.Split(fields["Credential"], "/")
	if len(scope) != 5 || scope[4] != "aws4_request" {
		return body, fmt.Errorf("bad credential %q", fields["Credential"])
	}
	if scope[0] != creds.AccessKeyID {
		return body, fmt.Errorf("access key ID %q is not the real one", scope[0])
	}
	if r.Header.Get("X-Amz-Security-Token") != creds.SessionToken {
		return body, fmt.Errorf("session token %q is not the real one", r.Header.Get("X-Amz-Security-Token"))
	}
	date := r.Header.Get("X-Amz-Date")
	if len(date) < 8 || date[:8] != scope[1] {
		return body, fmt.Errorf("X-Amz-Date %q does not match the scope date %s", date, scope[1])
	}
	service := scope[3]
	signed := strings.Split(fields["SignedHeaders"], ";")
	if !sort.StringsAreSorted(signed) || !contains(signed, "host") {
		return body, errors.New("SignedHeaders must be sorted and include host")
	}
	var ch strings.Builder
	for _, name := range signed {
		var vals []string
		switch name {
		case "host":
			vals = []string{r.Host}
		case "content-length":
			vals = []string{strconv.FormatInt(r.ContentLength, 10)}
		default:
			vals = r.Header.Values(name)
		}
		if len(vals) == 0 {
			return body, fmt.Errorf("signed header %s is missing", name)
		}
		for i, v := range vals {
			vals[i] = strings.Join(strings.Fields(v), " ")
		}
		ch.WriteString(name + ":" + strings.Join(vals, ",") + "\n")
	}
	for name := range r.Header {
		if l := strings.ToLower(name); strings.HasPrefix(l, "x-amz-") && !contains(signed, l) {
			return body, fmt.Errorf("header %s is not signed", l)
		}
	}
	payload := r.Header.Get("X-Amz-Content-Sha256")
	if payload == "" {
		sum := sha256.Sum256(body)
		payload = hex.EncodeToString(sum[:])
	}
	path := r.URL.EscapedPath()
	if !strings.HasPrefix(service, "s3") {
		path = uriEncode(path, false)
	}
	canonical := strings.Join([]string{r.Method, path, canonicalQuery(r.URL.RawQuery), ch.String(), fields["SignedHeaders"], payload}, "\n")
	sum := sha256.Sum256([]byte(canonical))
	toSign := "AWS4-HMAC-SHA256\n" + date + "\n" + strings.Join(scope[1:], "/") + "\n" + hex.EncodeToString(sum[:])
	key := []byte("AWS4" + creds.SecretAccessKey)
	for _, part := range scope[1:] {
		key = mac(key, part)
	}
	if want := hex.EncodeToString(mac(key, toSign)); fields["Signature"] != want {
		return body, fmt.Errorf("signature does not match; canonical request:\n%s", canonical)
	}
	return body, nil
}

func canonicalQuery(raw string) string {
	q, _ := url.ParseQuery(raw)
	var pairs []string
	for k, vs := range q {
		for _, v := range vs {
			pairs = append(pairs, uriEncode(k, true)+"="+uriEncode(v, true))
		}
	}
	sort.Strings(pairs)
	return strings.Join(pairs, "&")
}

// uriEncode is AWS's UriEncode: every byte but A-Z a-z 0-9 - _ . ~ is
// percent-encoded, and so is / when encodeSlash is set.
func uriEncode(s string, encodeSlash bool) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_', c == '.', c == '~':
			b.WriteByte(c)
		case c == '/' && !encodeSlash:
			b.WriteByte(c)
		default:
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

func mac(key []byte, data string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(data))
	return h.Sum(nil)
}

func contains(xs []string, x string) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}
