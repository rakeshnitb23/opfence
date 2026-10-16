package request

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// Meta is the "# key: value" header block of a fixture file.
type Meta map[string]string

// ParseFixture parses a .http fixture: optional "# key: value" comment
// lines, then an HTTP/1.1 request as it appears on the wire. The body is
// everything after the blank line that ends the headers, minus one trailing
// newline; Content-Length is ignored so fixtures can be edited by hand.
func ParseFixture(data []byte) (*Request, Meta, error) {
	meta := Meta{}
	rest := data
	for len(rest) > 0 {
		line, after, _ := bytes.Cut(rest, []byte("\n"))
		trimmed := strings.TrimSpace(string(line))
		if trimmed == "" {
			rest = after
			continue
		}
		if !strings.HasPrefix(trimmed, "#") {
			break
		}
		if k, v, ok := strings.Cut(strings.TrimSpace(trimmed[1:]), ":"); ok {
			meta[strings.ToLower(strings.TrimSpace(k))] = strings.TrimSpace(v)
		}
		rest = after
	}
	if len(rest) == 0 {
		return nil, nil, fmt.Errorf("fixture has no request")
	}

	head, body := splitHead(rest)
	hr, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(head)))
	if err != nil {
		return nil, nil, fmt.Errorf("fixture request: %w", err)
	}
	r, err := fromHead(hr)
	if err != nil {
		return nil, nil, err
	}
	body = bytes.TrimSuffix(body, []byte("\n"))
	body = bytes.TrimSuffix(body, []byte("\r"))
	if len(body) > MaxBody {
		r.BodyErr = ErrBodyTooLarge
	} else if b, err := Decode(body, r.Header.Get("Content-Encoding")); err != nil {
		r.BodyErr = err
	} else {
		r.Body = b
	}
	return r, meta, nil
}

// splitHead returns the request line and headers, including the blank line
// that ends them, and the body after it. LF and CRLF line endings both work.
func splitHead(b []byte) (head, body []byte) {
	for i := 0; i < len(b); {
		j := bytes.IndexByte(b[i:], '\n')
		if j < 0 {
			return append(append([]byte{}, b...), "\r\n\r\n"...), nil
		}
		line := b[i : i+j]
		if len(bytes.TrimRight(line, "\r")) == 0 && i > 0 {
			return b[:i+j+1], b[i+j+1:]
		}
		i += j + 1
	}
	return append(append([]byte{}, b...), "\r\n"...), nil
}

// fromHead builds a Request from a parsed request head; the body is set by
// the caller.
func fromHead(hr *http.Request) (*Request, error) {
	target := hr.RequestURI
	var rawPath, rawQuery, hostport string
	switch {
	case strings.HasPrefix(target, "/"):
		rawPath, rawQuery, _ = strings.Cut(target, "?")
		hostport = hr.Host
	default:
		u, err := url.Parse(target)
		if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
			return nil, fmt.Errorf("unsupported request target %q", target)
		}
		rawPath, rawQuery = u.EscapedPath(), u.RawQuery
		hostport = u.Host
	}
	if rawPath == "" {
		rawPath = "/"
	}
	if i := strings.IndexByte(rawPath, '#'); i >= 0 {
		rawPath = rawPath[:i]
	}
	if hostport == "" {
		return nil, fmt.Errorf("request has no Host header")
	}
	q, err := url.ParseQuery(rawQuery)
	if err != nil {
		return nil, fmt.Errorf("query string: %w", err)
	}
	host, port := SplitHostPort(hostport)
	if host == "" {
		return nil, fmt.Errorf("request has an empty host")
	}
	if !validMethod(hr.Method) {
		return nil, fmt.Errorf("unsupported method %q", hr.Method)
	}
	h := hr.Header.Clone()
	h.Del("Content-Length")
	return &Request{
		Method: strings.ToUpper(hr.Method),
		Host:   host,
		Port:   port,
		Path:   rawPath,
		Query:  q,
		Header: h,
	}, nil
}

// FromHTTP builds a Request from a live server-side request. It reads at
// most MaxBody+1 bytes of the body and returns them as raw, still encoded, so
// the caller can forward the body unchanged with
// io.MultiReader(bytes.NewReader(raw), hr.Body).
func FromHTTP(hr *http.Request) (r *Request, raw []byte, err error) {
	r, err = fromHead(hr)
	if err != nil {
		return nil, nil, err
	}
	if hr.Body == nil || hr.Body == http.NoBody {
		return r, nil, nil
	}
	raw, err = io.ReadAll(io.LimitReader(hr.Body, MaxBody+1))
	switch {
	case err != nil:
		r.BodyErr = fmt.Errorf("reading body: %w", err)
	case len(raw) > MaxBody:
		r.BodyErr = ErrBodyTooLarge
	default:
		if b, derr := Decode(raw, r.Header.Get("Content-Encoding")); derr != nil {
			r.BodyErr = derr
		} else {
			r.Body = b
		}
	}
	return r, raw, nil
}

// validMethod accepts method names made of letters only, which covers every
// registered HTTP method and rejects junk request lines.
func validMethod(m string) bool {
	if m == "" || len(m) > 20 {
		return false
	}
	for _, c := range m {
		if (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') {
			return false
		}
	}
	return true
}
