package request

import (
	"net/url"
	"strings"
)

// NormalizePath splits a raw path into segments after collapsing repeated
// slashes, dropping "." segments and a trailing slash, and resolving "..".
// It reports false for a path that escapes the root or is not absolute.
func NormalizePath(rawPath string) ([]string, bool) {
	if !strings.HasPrefix(rawPath, "/") {
		return nil, false
	}
	var out []string
	for _, s := range strings.Split(rawPath, "/") {
		// Unescape only to recognise dot segments; keep the raw form.
		dec, err := url.PathUnescape(s)
		if err != nil {
			return nil, false
		}
		switch dec {
		case "", ".":
			continue
		case "..":
			if len(out) == 0 {
				return nil, false
			}
			out = out[:len(out)-1]
			continue
		}
		out = append(out, s)
	}
	return out, true
}
