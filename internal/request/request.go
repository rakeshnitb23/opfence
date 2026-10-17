// Package request holds Opfence's view of one HTTP request: the parts the
// decoders need, with the body decompressed and size-limited.
//
// The same type is built from saved fixtures (.http files) and, in the
// runner, from live intercepted requests, so both paths decode identically.
package request

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
)

// MaxBody is the largest body, after decompression, that decoders inspect.
// Larger bodies set BodyErr and decoders fail closed.
const MaxBody = 64 << 10

// ErrBodyTooLarge is reported in BodyErr when a body exceeds MaxBody.
var ErrBodyTooLarge = errors.New("request body larger than 64 KiB")

// Request is a decoded HTTP request.
type Request struct {
	Method string
	Host   string // lower case, without port
	Port   string // empty for the scheme's default port
	Path   string // raw (still escaped) path, without query
	Query  url.Values
	Header http.Header
	Body   []byte // decompressed; nil when BodyErr is set
	// BodyErr is set when the body could not be fully read: too large,
	// truncated, or in an encoding Opfence does not decode.
	BodyErr error
	// Prefix holds the first MaxBody bytes of a body too large to read
	// whole, still encoded, for decoders that only need its start (git's
	// ref updates come before the pack).
	Prefix []byte
}

// ContentType returns the media type of the body, lower case, without
// parameters.
func (r *Request) ContentType() string {
	ct := r.Header.Get("Content-Type")
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = ct[:i]
	}
	return strings.ToLower(strings.TrimSpace(ct))
}

// SplitHostPort normalises a Host header or URL host: lower case, IPv6
// brackets removed, and the port dropped when it is the default for https.
func SplitHostPort(hostport string) (host, port string) {
	hostport = strings.ToLower(strings.TrimSpace(hostport))
	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		host, port = strings.Trim(hostport, "[]"), ""
	}
	host = strings.TrimSuffix(host, ".")
	if port == "443" {
		port = ""
	}
	return host, port
}

// ReadBody reads at most MaxBody bytes of a body and undoes its
// Content-Encoding. It returns the body, or nil and an error saying why the
// body cannot be inspected; callers keep that error in BodyErr.
func ReadBody(body io.Reader, contentEncoding string) ([]byte, error) {
	raw, err := io.ReadAll(io.LimitReader(body, MaxBody+1))
	if err != nil {
		return nil, fmt.Errorf("reading body: %w", err)
	}
	if len(raw) > MaxBody {
		return nil, ErrBodyTooLarge
	}
	return Decode(raw, contentEncoding)
}

// Decode undoes a Content-Encoding header value (a comma-separated list,
// applied in order) on an already-read body. gzip, deflate and identity are
// supported; anything else is an error.
func Decode(raw []byte, contentEncoding string) ([]byte, error) {
	encs := strings.Split(contentEncoding, ",")
	data := raw
	for i := len(encs) - 1; i >= 0; i-- {
		enc := strings.ToLower(strings.TrimSpace(encs[i]))
		var rd io.Reader
		switch enc {
		case "", "identity":
			continue
		case "gzip", "x-gzip":
			zr, err := gzip.NewReader(bytes.NewReader(data))
			if err != nil {
				return nil, fmt.Errorf("gzip body: %w", err)
			}
			rd = zr
		case "deflate":
			// RFC 9110 says deflate is zlib-wrapped; some clients send raw
			// deflate. Accept both.
			if zr, err := zlib.NewReader(bytes.NewReader(data)); err == nil {
				rd = zr
			} else {
				rd = flate.NewReader(bytes.NewReader(data))
			}
		default:
			return nil, fmt.Errorf("unsupported Content-Encoding %q", enc)
		}
		out, err := io.ReadAll(io.LimitReader(rd, MaxBody+1))
		if err != nil {
			return nil, fmt.Errorf("%s body: %w", enc, err)
		}
		if len(out) > MaxBody {
			return nil, ErrBodyTooLarge
		}
		data = out
	}
	return data, nil
}
