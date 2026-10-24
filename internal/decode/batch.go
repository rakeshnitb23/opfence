package decode

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/textproto"
	"net/url"
	"strconv"
	"strings"

	"github.com/rakeshnitb23/opfence/internal/request"
)

// decodeBatch reads a Google API batch request (stage 27b): a POST to a
// batch path (/batch/compute/v1) whose multipart/mixed body carries one
// HTTP request per part, each sent as if on its own. gcloud compute sends
// one whenever a command makes more than one request (deleting two VMs),
// and the client libraries batch Cloud Storage calls. Every inner request
// is decoded as REST against the same provider, so it gets the rules a
// request of its own would, and the batch gets the strictest decision.
//
// It fails closed: a body Opfence cannot read, a part that is not
// application/http or is encoded, an inner request line or header block
// that does not parse, a target that is not a path, an inner Host that is
// not the batch's host, a nested batch, and a Content-Length that does not
// match the part's body are unknown.
func decodeBatch(r *request.Request, batchPaths []string) []Operation {
	fail := func(msg string) []Operation {
		return []Operation{failed(r, REST, "batch request: "+msg)}
	}
	if r.BodyErr != nil {
		return fail(r.BodyErr.Error())
	}
	mt, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mt != "multipart/mixed" || params["boundary"] == "" {
		return fail("the body is not multipart/mixed with a boundary")
	}
	mr := multipart.NewReader(bytes.NewReader(r.Body), params["boundary"])
	var ops []Operation
	for n := 0; ; n++ {
		p, err := mr.NextRawPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fail(err.Error())
		}
		if n >= maxParts {
			return fail(fmt.Sprintf("more than %d parts", maxParts))
		}
		if pt, _, err := mime.ParseMediaType(p.Header.Get("Content-Type")); err != nil || pt != "application/http" {
			return fail(fmt.Sprintf("part %d is not application/http", n+1))
		}
		switch cte := strings.ToLower(strings.TrimSpace(p.Header.Get("Content-Transfer-Encoding"))); cte {
		case "", "7bit", "8bit", "binary":
		default:
			return fail(fmt.Sprintf("part %d is encoded with %s", n+1, cte))
		}
		data, err := io.ReadAll(p)
		if err != nil {
			return fail(err.Error())
		}
		inner, err := parseBatchPart(data, r)
		if err != nil {
			return fail(fmt.Sprintf("part %d: %v", n+1, err))
		}
		if isBatchPath(inner.Path, batchPaths) {
			return fail(fmt.Sprintf("part %d is itself a batch", n+1))
		}
		ops = append(ops, decodeREST(inner)...)
		if len(ops) > MaxOperations {
			return fail(fmt.Sprintf("more than %d operations", MaxOperations))
		}
	}
	if len(ops) == 0 {
		return fail("no requests in the batch")
	}
	return ops
}

// parseBatchPart reads one part's HTTP request: a request line
// ("DELETE /compute/v1/projects/p/zones/z/instances/vm HTTP/1.1"), headers,
// a blank line and the body, which is the rest of the part.
func parseBatchPart(data []byte, outer *request.Request) (*request.Request, error) {
	tr := textproto.NewReader(bufio.NewReader(bytes.NewReader(data)))
	line, err := tr.ReadLine()
	for err == nil && strings.TrimSpace(line) == "" {
		line, err = tr.ReadLine() // blank lines before the request line
	}
	if err != nil {
		return nil, errors.New("no request line")
	}
	fields := strings.Fields(line)
	if len(fields) < 2 || len(fields) > 3 || (len(fields) == 3 && !strings.HasPrefix(fields[2], "HTTP/")) {
		return nil, fmt.Errorf("request line %q does not parse", line)
	}
	method, target := strings.ToUpper(fields[0]), fields[1]
	if !lettersOnly(method) {
		return nil, fmt.Errorf("method %q", fields[0])
	}
	if !strings.HasPrefix(target, "/") {
		return nil, fmt.Errorf("target %q is not a path", target)
	}
	hdr, err := tr.ReadMIMEHeader()
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		return nil, fmt.Errorf("headers: %v", err) // a part may end after its headers
	}
	rawPath, rawQuery, _ := strings.Cut(target, "?")
	if i := strings.IndexByte(rawPath, '#'); i >= 0 {
		rawPath = rawPath[:i]
	}
	q, err := url.ParseQuery(rawQuery)
	if err != nil {
		return nil, fmt.Errorf("query string: %v", err)
	}
	if hosts := hdr.Values("Host"); len(hosts) > 0 {
		for _, h := range hosts {
			if host, port := request.SplitHostPort(h); host != outer.Host || port != outer.Port {
				return nil, fmt.Errorf("the inner Host %q is not the batch's host", h)
			}
		}
	}
	if hdr.Get("Transfer-Encoding") != "" {
		return nil, errors.New("a Transfer-Encoding inside a part is not supported")
	}
	// What is left is the body. The textproto reader buffered it.
	body, err := io.ReadAll(tr.R)
	if err != nil {
		return nil, err
	}
	if cl := hdr.Values("Content-Length"); len(cl) > 0 {
		n, err := strconv.Atoi(strings.TrimSpace(cl[0]))
		trimmed := bytes.TrimRight(body, "\r\n")
		switch {
		case len(cl) > 1 || err != nil || n < 0:
			return nil, fmt.Errorf("bad Content-Length %q", strings.Join(cl, ", "))
		case n == len(body):
		case n == len(trimmed):
			body = trimmed
		default:
			return nil, fmt.Errorf("the Content-Length %d does not match the %d-byte body", n, len(body))
		}
	}
	h := make(map[string][]string, len(hdr))
	for k, v := range hdr {
		if k != "Content-Length" {
			h[k] = v
		}
	}
	inner := &request.Request{Method: method, Host: outer.Host, Port: outer.Port, Path: rawPath, Query: q, Header: h}
	if len(body) > 0 {
		if b, err := request.Decode(body, hdr.Get("Content-Encoding")); err != nil {
			inner.BodyErr = err
		} else {
			inner.Body = b
		}
	}
	return inner, nil
}

// isBatchPath reports whether a path is one of a provider's batch paths,
// compared segment by segment after dot segments are resolved, as GraphQL
// paths are.
func isBatchPath(rawPath string, paths []string) bool {
	return isGraphQLPath(rawPath, paths)
}

// lettersOnly accepts method names made of letters, as the request package
// does for the requests it reads.
func lettersOnly(m string) bool {
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
