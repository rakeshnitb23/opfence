package proxy

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/rakeshnitb23/opfence/internal/audit"
	"github.com/rakeshnitb23/opfence/internal/classes"
	"github.com/rakeshnitb23/opfence/internal/decode"
	"github.com/rakeshnitb23/opfence/internal/engine"
	"github.com/rakeshnitb23/opfence/internal/inject"
	"github.com/rakeshnitb23/opfence/internal/request"
)

// maxAuditPath bounds the path written to the audit log.
const maxAuditPath = 512

type fwdKey struct{}

// fwd carries a forwarded request's evaluated target and its audit entry
// from the handler to the reverse proxy's callbacks.
type fwd struct {
	host, path, rawPath, rawQuery string
	entry                         audit.Entry
}

// serveIntercepted evaluates one request on an intercepted connection and
// forwards, holds for approval, or blocks it.
func (s *Server) serveIntercepted(w http.ResponseWriter, r *http.Request) {
	host := strings.TrimSuffix(strings.ToLower(r.TLS.ServerName), ".")
	entry := audit.Entry{Event: "request", Host: host, Method: r.Method}
	req, raw, err := request.FromHTTP(r)
	if err != nil {
		entry.Path = auditPath(r.URL.EscapedPath())
		s.block(w, nil, nil, entry, http.StatusBadRequest, "Opfence could not read this request: "+err.Error())
		return
	}
	entry.Path = auditPath(req.Path)
	if req.Host != host || req.Port != "" {
		// HTTP/2 clients may reuse a connection for another host; 421 makes
		// them open a new one, which gets its own decision.
		entry.Outcome, entry.Status, entry.Reason = "refused", http.StatusMisdirectedRequest, "Host "+r.Host+" does not match the TLS server name"
		s.record(entry)
		http.Error(w, "Opfence: this connection is for "+host, http.StatusMisdirectedRequest)
		return
	}
	if r.Header.Get("Upgrade") != "" {
		s.block(w, req, nil, entry, http.StatusForbidden, "Opfence does not inspect WebSocket or other protocol upgrades on API hosts yet, so it blocks them.")
		return
	}

	if h := endToEndConnectionHeader(r.Header); h != "" {
		// The reverse proxy drops headers named in Connection, so the API
		// would see a different request from the one decided.
		s.block(w, req, nil, entry, http.StatusBadRequest, "Opfence blocks requests whose Connection header names "+strconv.Quote(h)+", because it would remove that header before forwarding.")
		return
	}

	res := s.cfg.Engine.Evaluate(req)
	entry.Decision = res.Decision.String()
	for _, ev := range res.Evaluations {
		op := audit.Operation{Class: string(ev.Class), Environment: ev.Environment, Decision: ev.Decision.String(), Card: ev.Card}
		if ev.Rule != nil {
			op.Rule = ev.Rule.ID
		}
		entry.Operations = append(entry.Operations, op)
	}

	switch res.Decision {
	case classes.Allow:
		entry.Outcome = "forwarded"
	case classes.Ask, classes.Confirm:
		entry.Hash = hex.EncodeToString(res.Hash[:])
		a := s.cfg.Approver.Approve(r.Context(), Pending{Result: &res, Method: req.Method, Host: host, Path: req.Path, Via: s.cfg.Via})
		if !a.Approved {
			entry.Approver = a.Channel
			s.block(w, req, &res, entry, http.StatusForbidden, a.Reason)
			return
		}
		entry.Outcome, entry.Approver = "approved", a.Channel
	default:
		s.block(w, req, &res, entry, http.StatusForbidden, "Your Opfence policy denies this. Change the policy if it should be allowed.")
		return
	}

	// Forward exactly the path that was evaluated.
	path, err := url.PathUnescape(req.Path)
	if u := (url.URL{Path: path, RawPath: req.Path}); err != nil || u.EscapedPath() != req.Path {
		s.block(w, req, &res, entry, http.StatusBadRequest, "Opfence could not forward this path unchanged, so it blocks it.")
		return
	}
	rawQuery, inj := inject.Request(res.Provider, r.Header, r.URL.RawQuery, s.cfg.Secrets)
	entry.Credentials = inj.Injected
	if len(inj.Foreign) > 0 {
		entry.Reason = fmt.Sprintf("placeholder for %s sent to %s; not swapped in", strings.Join(inj.Foreign, ", "), host)
	}
	sigV4 := res.Provider != nil && res.Provider.SigV4
	if s.scrubber != nil {
		// Let the transport ask for gzip and decode it, so responses can be
		// scrubbed.
		r.Header.Del("Accept-Encoding")
		if !sigV4 {
			// A key split across two ranged reads would not be scrubbed in
			// either. AWS keeps Range: S3 downloads in parts depend on it.
			r.Header.Del("Range")
			r.Header.Del("If-Range")
		}
	}
	var whole []byte
	if sigV4 {
		if len(raw) > request.MaxBody && r.Header.Get("X-Amz-Content-Sha256") == "" {
			// Re-signing may read up to MaxSignedBody into memory; a few at a
			// time.
			select {
			case s.resign <- struct{}{}:
				defer func() { <-s.resign }()
			case <-r.Context().Done():
				s.block(w, req, &res, entry, http.StatusServiceUnavailable, "the request was cancelled while waiting for other large AWS uploads")
				return
			}
		}
		// After every header change, so the new signature covers what is
		// sent.
		signed, body, err := inject.SigV4(res.Provider, inject.AWSRequest{
			Method: req.Method, Host: host, Path: path, RawPath: req.Path, RawQuery: rawQuery,
			Header: r.Header, ContentLength: r.ContentLength,
			Body: raw, BodyComplete: len(raw) <= request.MaxBody, Rest: r.Body,
		}, s.cfg.Secrets)
		if err != nil {
			s.block(w, req, &res, entry, http.StatusForbidden, err.Error())
			return
		}
		entry.Credentials = append(entry.Credentials, signed.Injected...)
		if len(signed.Foreign) > 0 {
			entry.Reason = fmt.Sprintf("placeholder for %s sent to %s; not swapped in", strings.Join(signed.Foreign, ", "), host)
		}
		whole = body
	}
	f := &fwd{host: host, path: path, rawPath: req.Path, rawQuery: rawQuery, entry: entry}
	if r.Body != nil && r.Body != http.NoBody {
		var rd io.Reader = io.MultiReader(bytes.NewReader(raw), r.Body)
		if whole != nil {
			rd = bytes.NewReader(whole)
		}
		r.Body = struct {
			io.Reader
			io.Closer
		}{rd, r.Body}
	}
	var rw http.ResponseWriter = w
	if s.scrubber != nil {
		rw = scrubWriter{w, s}
	}
	s.rp.ServeHTTP(rw, r.WithContext(contextWith(r, f)))
}

// scrubWriter scrubs the headers of informational (1xx) responses, which the
// reverse proxy forwards as they arrive, before modifyResponse runs.
type scrubWriter struct {
	http.ResponseWriter
	s *Server
}

func (w scrubWriter) WriteHeader(code int) {
	if code < 200 {
		w.s.scrubber.Header(w.Header())
	}
	w.ResponseWriter.WriteHeader(code)
}

// Unwrap lets http.ResponseController flush streamed responses.
func (w scrubWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func rewriteIntercepted(pr *httputil.ProxyRequest) {
	f := pr.In.Context().Value(fwdKey{}).(*fwd)
	pr.Out.URL.Scheme = "https"
	pr.Out.URL.Host = f.host
	pr.Out.URL.Path = f.path
	pr.Out.URL.RawPath = f.rawPath
	pr.Out.URL.RawQuery = f.rawQuery
	pr.Out.Host = f.host
}

// modifyResponse scrubs secrets from the response and writes the audit
// entry once the upstream's response headers arrive, before any body
// streams, so a long stream is logged immediately. A response in an
// encoding Opfence cannot read is refused when there are secrets to scrub.
func (s *Server) modifyResponse(resp *http.Response) error {
	if s.scrubber != nil {
		if ce := strings.TrimSpace(resp.Header.Get("Content-Encoding")); ce != "" && !strings.EqualFold(ce, "identity") {
			return fmt.Errorf("the response is encoded with %s, which Opfence cannot scrub for credentials", ce)
		}
		s.scrubber.Header(resp.Header)
		resp.Body = s.scrubber.Reader(resp.Body, func() { s.scrubber.Header(resp.Trailer) })
	}
	if f, ok := resp.Request.Context().Value(fwdKey{}).(*fwd); ok {
		f.entry.Status = resp.StatusCode
		s.record(f.entry)
	}
	return nil
}

func (s *Server) upstreamError(w http.ResponseWriter, r *http.Request, err error) {
	if f, ok := r.Context().Value(fwdKey{}).(*fwd); ok {
		f.entry.Outcome, f.entry.Status, f.entry.Reason = "error", http.StatusBadGateway, err.Error()
		s.record(f.entry)
	}
	http.Error(w, "Opfence could not reach the API: "+err.Error(), http.StatusBadGateway)
}

// block answers a request that will not be forwarded. MCP clients get a
// JSON-RPC error, which agents show to the model as the tool's result;
// everything else gets a 403 with a JSON body. Either way the message says
// what was blocked and why, from the decoded request only.
func (s *Server) block(w http.ResponseWriter, req *request.Request, res *engine.Result, entry audit.Entry, status int, reason string) {
	entry.Outcome, entry.Status, entry.Reason = "blocked", status, reason
	msg := "Blocked by Opfence. " + reason
	detail := map[string]any{}
	if res != nil && len(res.Evaluations) > 0 {
		ev := strictest(res)
		msg = fmt.Sprintf("Blocked by Opfence: %s (%s, %s). %s", ev.Card, ev.Class, ev.Environment, reason)
		detail = map[string]any{"decision": res.Decision.String(), "class": ev.Class, "environment": ev.Environment, "card": ev.Card}
		if ev.Rule != nil {
			detail["rule"] = ev.Rule.ID
		}
	}
	w.Header().Set("X-Opfence-Decision", "blocked")
	if report, ok := gitPushReport(req, res, msg); ok {
		// git shows a rejected ref with its reason, which a 403 would hide
		// behind "RPC failed".
		entry.Status = http.StatusOK
		s.record(entry)
		w.Header().Set("Content-Type", "application/x-git-receive-pack-result")
		_, _ = w.Write(report)
		return
	}
	if id, ok := jsonRPCID(req, res); ok {
		entry.Status = http.StatusOK
		s.record(entry)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"jsonrpc": "2.0",
			"id":      id,
			"error":   map[string]any{"code": -32001, "message": msg, "data": detail},
		})
		return
	}
	s.record(entry)
	detail["message"] = msg
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": detail})
}

// strictest returns the evaluation that produced the request's decision.
func strictest(res *engine.Result) engine.Evaluation {
	for _, ev := range res.Evaluations {
		if ev.Decision == res.Decision {
			return ev
		}
	}
	return res.Evaluations[0]
}

// gitPushReport answers a blocked git push with git's own report-status,
// rejecting every ref with msg, so git prints "[remote rejected] (msg)".
func gitPushReport(req *request.Request, res *engine.Result, msg string) ([]byte, bool) {
	if req == nil || res == nil || len(res.Evaluations) == 0 {
		return nil, false
	}
	var refs []string
	for _, ev := range res.Evaluations {
		ref, _ := ev.Op.Args["ref"].(string)
		if ev.Op.Protocol != decode.Git || ev.Op.Service != decode.GitReceivePack || ev.Op.Error != "" || ref == "" {
			return nil, false
		}
		refs = append(refs, ref)
	}
	msg = strings.Join(strings.Fields(msg), " ")
	var report bytes.Buffer
	pktLine(&report, "unpack ok\n")
	for _, ref := range refs {
		pktLine(&report, "ng "+ref+" "+msg+"\n")
	}
	report.WriteString("0000")
	caps := decode.GitPushCapabilities(req)
	if !slices.Contains(caps, "side-band-64k") && !slices.Contains(caps, "side-band") {
		return report.Bytes(), true
	}
	// With side-band the report travels in band 1, in packets small enough
	// for plain side-band (1000 bytes).
	var out bytes.Buffer
	data := report.Bytes()
	for len(data) > 0 {
		n := min(len(data), 995)
		pktLine(&out, "\x01"+string(data[:n]))
		data = data[n:]
	}
	out.WriteString("0000")
	return out.Bytes(), true
}

func pktLine(b *bytes.Buffer, s string) {
	fmt.Fprintf(b, "%04x%s", len(s)+4, s)
}

// jsonRPCID returns the id of a single MCP JSON-RPC request.
func jsonRPCID(req *request.Request, res *engine.Result) (json.RawMessage, bool) {
	if req == nil || res == nil || len(res.Evaluations) == 0 || res.Evaluations[0].Op.Protocol != decode.MCP {
		return nil, false
	}
	var msg struct {
		ID     json.RawMessage `json:"id"`
		Method string          `json:"method"`
	}
	if json.Unmarshal(req.Body, &msg) != nil || msg.Method == "" || len(msg.ID) == 0 || string(msg.ID) == "null" {
		return nil, false
	}
	return msg.ID, true
}

// connectionTokens are the Connection header values clients normally send.
var connectionTokens = map[string]bool{"close": true, "keep-alive": true, "te": true, "upgrade": true}

// endToEndConnectionHeader returns the first header the Connection header
// names other than the usual hop-by-hop tokens.
func endToEndConnectionHeader(h http.Header) string {
	for _, v := range h.Values("Connection") {
		for _, tok := range strings.Split(v, ",") {
			if tok = strings.ToLower(strings.TrimSpace(tok)); tok != "" && !connectionTokens[tok] {
				return tok
			}
		}
	}
	return ""
}

func auditPath(p string) string {
	if len(p) > maxAuditPath {
		return p[:maxAuditPath] + "…"
	}
	return p
}

func contextWith(r *http.Request, f *fwd) context.Context {
	return context.WithValue(r.Context(), fwdKey{}, f)
}
