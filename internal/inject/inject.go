// Package inject swaps placeholders for real credentials on the way out,
// only in the auth locations a provider declares and only for that
// provider's own secrets and those of the providers it lists in
// secrets_from, and swaps real values back to placeholders in responses
// (docs/ARCHITECTURE.md §8.4).
package inject

import (
	"encoding/base64"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/rakeshnitb23/opfence/internal/catalog"
	"github.com/rakeshnitb23/opfence/internal/secrets"
)

// Result says what Request did.
type Result struct {
	Injected []string // provider/name of each secret swapped in
	// Foreign lists placeholders for another provider found in this
	// request's auth locations; they are left alone, so the API rejects
	// them.
	Foreign []string
}

// swapper returns the function that swaps one placeholder of prov's (or of
// a provider it takes secrets from) for its value, recording what it did.
func swapper(prov *catalog.Provider, set *secrets.Set, res *Result) func(string) (string, bool) {
	return func(token string) (string, bool) {
		s := set.ByPlaceholder(token)
		if s == nil {
			return token, false
		}
		if s.Provider != prov.ID && !slices.Contains(prov.SecretsFrom, s.Provider) {
			res.Foreign = append(res.Foreign, s.Provider+"/"+s.Name)
			return token, false
		}
		res.Injected = append(res.Injected, s.Provider+"/"+s.Name)
		return s.Value, true
	}
}

// Form swaps placeholders in the fields of a form-encoded body that prov
// declares as auth locations (auth: form), such as an OAuth token request's
// refresh_token, and returns the new body, or nil when nothing changed. Only
// a body Opfence can read whole and that is not compressed is changed; any
// other is sent as it is, with its placeholders, which the API rejects.
func Form(prov *catalog.Provider, contentType, contentEncoding string, body []byte, set *secrets.Set) ([]byte, Result) {
	var res Result
	if prov == nil || set.Len() == 0 || len(body) == 0 {
		return nil, res
	}
	if ct, _, _ := strings.Cut(contentType, ";"); !strings.EqualFold(strings.TrimSpace(ct), "application/x-www-form-urlencoded") {
		return nil, res
	}
	if ce := strings.TrimSpace(contentEncoding); ce != "" && !strings.EqualFold(ce, "identity") {
		return nil, res
	}
	swap := swapper(prov, set, &res)
	out := string(body)
	for _, a := range prov.Auth {
		if a.Form != "" {
			out = swapQuery(out, a.Form, swap)
		}
	}
	if len(res.Injected) == 0 {
		return nil, res
	}
	return []byte(out), res
}

// Request swaps placeholders in h and rawQuery for prov's request and
// returns the new query string.
func Request(prov *catalog.Provider, h http.Header, rawQuery string, set *secrets.Set) (string, Result) {
	var res Result
	if prov == nil || set.Len() == 0 {
		return rawQuery, res
	}
	swap := swapper(prov, set, &res)
	basicDone := false
	for _, a := range prov.Auth {
		switch {
		case a.Header != "":
			vals := h.Values(a.Header)
			for i, v := range vals {
				vals[i] = swapHeader(v, a.Scheme, swap)
			}
		case a.Query != "":
			rawQuery = swapQuery(rawQuery, a.Query, swap)
		case a.Basic != "" && !basicDone:
			basicDone = true
			vals := h.Values("Authorization")
			for i, v := range vals {
				vals[i] = swapBasic(v, swap)
			}
		}
	}
	return rawQuery, res
}

// swapHeader replaces the token in a header value: "<scheme> <token>" when
// the provider declares a scheme, otherwise the value's last word (which
// covers "Bearer x", "token x" and a bare token). A token that is not a
// placeholder itself has each colon-separated part swapped, for
// "<id>:<token>" values such as PlanetScale's service tokens.
func swapHeader(v, scheme string, swap func(string) (string, bool)) string {
	prefix, token := "", v
	if scheme != "" {
		if len(v) <= len(scheme) || !strings.EqualFold(v[:len(scheme)], scheme) || v[len(scheme)] != ' ' {
			return v
		}
		prefix, token = v[:len(scheme)+1], v[len(scheme)+1:]
	} else if i := strings.LastIndexByte(v, ' '); i >= 0 {
		prefix, token = v[:i+1], v[i+1:]
	}
	if out, ok := swap(token); ok {
		return prefix + out
	}
	if !strings.Contains(token, ":") {
		return v
	}
	parts := strings.Split(token, ":")
	swapped := false
	for i, p := range parts {
		if out, ok := swap(p); ok {
			parts[i], swapped = out, true
		}
	}
	if swapped {
		return prefix + strings.Join(parts, ":")
	}
	return v
}

// swapQuery replaces the value of every name= pair, leaving the rest of the
// query string byte for byte.
func swapQuery(raw, name string, swap func(string) (string, bool)) string {
	parts := strings.Split(raw, "&")
	for i, p := range parts {
		k, v, ok := strings.Cut(p, "=")
		if !ok {
			continue
		}
		if dk, err := url.QueryUnescape(k); err != nil || dk != name {
			continue
		}
		dv, err := url.QueryUnescape(v)
		if err != nil {
			continue
		}
		if out, ok := swap(dv); ok {
			parts[i] = k + "=" + url.QueryEscape(out)
		}
	}
	return strings.Join(parts, "&")
}

func swapBasic(v string, swap func(string) (string, bool)) string {
	const prefix = "Basic "
	if len(v) <= len(prefix) || !strings.EqualFold(v[:len(prefix)], prefix) {
		return v
	}
	dec, err := base64.StdEncoding.DecodeString(strings.TrimSpace(v[len(prefix):]))
	if err != nil {
		return v
	}
	user, pass, ok := strings.Cut(string(dec), ":")
	if !ok {
		return v
	}
	nu, okU := swap(user)
	np, okP := swap(pass)
	if !okU && !okP {
		return v
	}
	return v[:len(prefix)] + base64.StdEncoding.EncodeToString([]byte(nu+":"+np))
}
