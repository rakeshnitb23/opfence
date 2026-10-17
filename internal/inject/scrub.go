package inject

import (
	"bytes"
	"encoding/base64"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/rakeshnitb23/opfence/internal/secrets"
)

// Scrubber replaces real secret values with their placeholders. Values and
// placeholders have the same length, so lengths never change.
type Scrubber struct {
	pairs  [][2][]byte
	maxLen int
}

// minEncoded is the shortest encoded form of a secret worth scrubbing;
// shorter strings could match unrelated text.
const minEncoded = 12

// NewScrubber scrubs every secret in set; nil when there is nothing to do.
// Besides the value itself it scrubs the value base64-encoded at each of the
// three alignments it can have inside a longer encoded string (an echoed
// Basic Authorization header, a base64 file body) and URL-encoded, wherever
// the placeholder's encoding has the same length. Up to two bytes at each end
// of a base64-encoded value share characters with their neighbours and stay.
func NewScrubber(set *secrets.Set) *Scrubber {
	if set.Len() == 0 {
		return nil
	}
	s := &Scrubber{}
	add := func(v, p string) {
		if len(v) < minEncoded || len(v) != len(p) || v == p {
			return
		}
		for _, x := range s.pairs {
			if string(x[0]) == v {
				return
			}
		}
		s.pairs = append(s.pairs, [2][]byte{[]byte(v), []byte(p)})
		s.maxLen = max(s.maxLen, len(v))
	}
	for _, sec := range set.All() {
		v, p := sec.Value, sec.Placeholder
		s.pairs = append(s.pairs, [2][]byte{[]byte(v), []byte(p)})
		s.maxLen = max(s.maxLen, len(v))
		if len(v) != len(p) {
			continue
		}
		for off := range 3 {
			// Bytes from off on that fill whole 3-byte groups encode to the
			// same characters wherever the value sits in the encoded data.
			end := off + (len(v)-off)/3*3
			for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.URLEncoding} {
				add(enc.EncodeToString([]byte(v[off:end])), enc.EncodeToString([]byte(p[off:end])))
			}
		}
		add(url.QueryEscape(v), url.QueryEscape(p))
		add(url.PathEscape(v), url.PathEscape(p))
	}
	return s
}

// Header scrubs every header value in place.
func (s *Scrubber) Header(h http.Header) {
	for k, vs := range h {
		for i, v := range vs {
			for _, p := range s.pairs {
				v = strings.ReplaceAll(v, string(p[0]), string(p[1]))
			}
			h[k][i] = v
		}
	}
}

// Reader wraps r so secret values never come out of it, including values
// split across reads. atEOF, when set, runs once r is fully read, before the
// last bytes are returned: an HTTP response's trailers arrive then.
func (s *Scrubber) Reader(r io.ReadCloser, atEOF func()) io.ReadCloser {
	return &scrubReader{s: s, src: r, atEOF: atEOF}
}

type scrubReader struct {
	s       *Scrubber
	src     io.ReadCloser
	atEOF   func()
	pending []byte // read from src, not yet returned
	ready   int    // pending[:ready] is scrubbed and safe to return
	eof     bool
	err     error
}

func (r *scrubReader) Read(p []byte) (int, error) {
	for r.ready == 0 {
		if r.eof {
			if len(r.pending) == 0 {
				return 0, r.err
			}
			r.scrub()
			r.ready = len(r.pending)
			break
		}
		buf := make([]byte, max(32<<10, 2*r.s.maxLen))
		n, err := r.src.Read(buf)
		r.pending = append(r.pending, buf[:n]...)
		if err != nil {
			r.eof = true
			if r.atEOF != nil {
				r.atEOF()
			}
			if err != io.EOF {
				r.err = err
			} else {
				r.err = io.EOF
			}
			continue
		}
		// Everything but the last maxLen-1 bytes is final: a value that
		// starts there would have to end beyond what was read.
		if keep := r.s.maxLen - 1; len(r.pending) > keep {
			r.scrub()
			r.ready = len(r.pending) - keep
		}
	}
	n := copy(p, r.pending[:r.ready])
	r.pending = r.pending[n:]
	r.ready -= n
	return n, nil
}

func (r *scrubReader) scrub() {
	for _, p := range r.s.pairs {
		if bytes.Contains(r.pending, p[0]) {
			r.pending = bytes.ReplaceAll(r.pending, p[0], p[1])
		}
	}
}

func (r *scrubReader) Close() error { return r.src.Close() }
