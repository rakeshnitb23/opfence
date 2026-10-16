package inject

import (
	"bytes"
	"io"
	"net/http"
	"strings"

	"github.com/rakeshnitb23/opfence/internal/secrets"
)

// Scrubber replaces real secret values with their placeholders. Values and
// placeholders have the same length, so lengths never change.
type Scrubber struct {
	pairs  [][2][]byte
	maxLen int
}

// NewScrubber scrubs every secret in set; nil when there is nothing to do.
func NewScrubber(set *secrets.Set) *Scrubber {
	if set.Len() == 0 {
		return nil
	}
	s := &Scrubber{}
	for _, sec := range set.All() {
		s.pairs = append(s.pairs, [2][]byte{[]byte(sec.Value), []byte(sec.Placeholder)})
		s.maxLen = max(s.maxLen, len(sec.Value))
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
// split across reads.
func (s *Scrubber) Reader(r io.ReadCloser) io.ReadCloser {
	return &scrubReader{s: s, src: r}
}

type scrubReader struct {
	s       *Scrubber
	src     io.ReadCloser
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
