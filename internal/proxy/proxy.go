// Package proxy is the runner's data path (docs/ARCHITECTURE.md §8.1, §8.2):
// HTTP CONNECT and SOCKS5 listeners that intercept TLS to catalog hosts,
// evaluate every request with the engine before it leaves the machine, and
// tunnel or refuse everything else.
package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rakeshnitb23/opfence/internal/audit"
	"github.com/rakeshnitb23/opfence/internal/ca"
	"github.com/rakeshnitb23/opfence/internal/engine"
	"github.com/rakeshnitb23/opfence/internal/inject"
	"github.com/rakeshnitb23/opfence/internal/policy"
	"github.com/rakeshnitb23/opfence/internal/request"
	"github.com/rakeshnitb23/opfence/internal/secrets"
)

// Recorder receives audit entries.
type Recorder interface {
	Record(audit.Entry) error
}

// Approver decides requests the policy says to ask about.
type Approver interface {
	Approve(ctx context.Context, p Pending) Approval
}

// Pending is a request waiting for a human.
type Pending struct {
	Result *engine.Result
	Method string
	Host   string
	Path   string
	Via    string // the listener's label, so cards can say a session is unsandboxed
}

// Approval is a human's answer.
type Approval struct {
	Approved bool
	Channel  string // which channel answered, for the audit log
	Reason   string // why it was not approved
}

// NoApprover denies everything that needs approval. It is the default until
// an approval channel is running.
type NoApprover struct{}

// Approve implements Approver.
func (NoApprover) Approve(context.Context, Pending) Approval {
	return Approval{Reason: "Opfence needs a human to approve this, and no approval channel is running."}
}

// Config configures a Server.
type Config struct {
	Engine *engine.Engine
	CA     *ca.CA
	// Audit receives one entry per request, tunnel and refusal; nil disables
	// the log.
	Audit Recorder
	// Secrets are swapped in for their placeholders on the way out and
	// scrubbed from responses; nil means none.
	Secrets *secrets.Set
	// Approver answers ask and confirm decisions; nil means NoApprover.
	Approver Approver
	Session  string
	// Via labels this server's listeners in the audit log and approval cards:
	// sandbox, agent, srt or weak.
	Via string
	// Mode is strict or open; empty takes the policy's mode.
	Mode string
	// PrivateTunnels lets tunnels (not intercepted requests) reach private
	// addresses. It is for the agent listener, whose clients run outside the
	// sandbox and could connect to those addresses directly anyway.
	PrivateTunnels bool
	// Passthrough lists hosts tunnelled without inspection (exact names or
	// *.suffix); nil takes the policy's list.
	Passthrough []string
	// AgentHosts are the backend hosts of the agent the session runs (its
	// model API and sign-in), tunnelled without inspection like the built-in
	// passthrough hosts: on port 443, with the TLS server name checked, and
	// never to private addresses.
	AgentHosts []string
	// DialContext dials upstream connections. Nil uses a dialer that refuses
	// loopback, private and link-local addresses (tests replace it).
	DialContext func(ctx context.Context, network, addr string) (net.Conn, error)
	// Upstream, when set, is a proxy every upstream connection goes
	// through (a corporate proxy). The private-address check then covers IP
	// literals only, since the upstream proxy resolves names.
	Upstream *Upstream
	// UpstreamRootCAs verifies upstream servers; nil uses the system roots.
	UpstreamRootCAs *x509.CertPool
	// Logf reports errors that have no client to go to; nil uses log.Printf.
	Logf func(format string, args ...any)
}

// Server is a running proxy. One Server can serve several listeners.
type Server struct {
	cfg       Config
	scrubber  *inject.Scrubber
	resign    chan struct{} // slots for AWS re-signing that buffers a body
	minted    atomic.Int64  // numbers minted credentials' names
	transport *http.Transport
	rp        *httputil.ReverseProxy
	plainRP   *httputil.ReverseProxy
	inner     *http.Server // serves intercepted TLS connections
	conns     *chanListener

	mu        sync.Mutex
	listeners []net.Listener
	outer     []*http.Server
	closed    bool
}

// New starts a Server. Call Close to stop it.
func New(cfg Config) (*Server, error) {
	if cfg.Engine == nil || cfg.CA == nil {
		return nil, errors.New("proxy: Engine and CA are required")
	}
	if cfg.Approver == nil {
		cfg.Approver = NoApprover{}
	}
	if cfg.Mode == "" {
		cfg.Mode = cfg.Engine.Policy.Mode
	}
	if cfg.Mode != "strict" && cfg.Mode != "open" {
		return nil, fmt.Errorf("proxy: mode %q must be strict or open", cfg.Mode)
	}
	if cfg.Passthrough == nil {
		cfg.Passthrough = cfg.Engine.Policy.Passthrough
	}
	if cfg.Logf == nil {
		cfg.Logf = log.Printf
	}
	if cfg.Secrets == nil {
		cfg.Secrets = secrets.NewSet(nil) // responses can still mint some
	}
	// Rules' response transforms count only where they are applied.
	eng := *cfg.Engine
	eng.TransformsResponses = true
	cfg.Engine = &eng
	scrubber := inject.NewScrubber(cfg.Secrets)
	if scrubber == nil {
		scrubber = &inject.Scrubber{}
	}
	s := &Server{cfg: cfg, conns: newChanListener(), scrubber: scrubber, resign: make(chan struct{}, maxResigning)}
	s.transport = &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return s.dial(ctx, network, addr, false)
		},
		TLSClientConfig:       &tls.Config{RootCAs: cfg.UpstreamRootCAs, MinVersion: tls.VersionTLS12},
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   15 * time.Second,
		ExpectContinueTimeout: time.Second,
	}
	s.rp = &httputil.ReverseProxy{
		Rewrite:        rewriteIntercepted,
		Transport:      s.transport,
		FlushInterval:  -1, // stream server-sent events (MCP) as they arrive
		ModifyResponse: s.modifyResponse,
		ErrorHandler:   s.upstreamError,
		ErrorLog:       log.New(io.Discard, "", 0),
	}
	s.plainRP = &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL = pr.In.URL
			pr.Out.Host = pr.In.URL.Host
		},
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				host, _ := request.SplitHostPort(addr)
				return s.dial(ctx, network, addr, s.allowPrivate(host))
			},
			IdleConnTimeout: 90 * time.Second,
		},
		ErrorLog: log.New(io.Discard, "", 0),
	}
	s.inner = &http.Server{
		Handler:           http.HandlerFunc(s.serveIntercepted),
		ReadHeaderTimeout: 30 * time.Second,
		IdleTimeout:       2 * time.Minute,
		ErrorLog:          log.New(io.Discard, "", 0),
	}
	go func() { _ = s.inner.Serve(s.conns) }()
	return s, nil
}

// maxResigning is how many AWS requests may buffer a body to re-sign it at
// once, each up to inject.MaxSignedBody.
const maxResigning = 4

// ServeHTTPProxy serves HTTP proxy clients (CONNECT and plain HTTP) on l
// until Close.
func (s *Server) ServeHTTPProxy(l net.Listener) error {
	srv := &http.Server{
		Handler:           http.HandlerFunc(s.serveProxy),
		ReadHeaderTimeout: 30 * time.Second,
		ErrorLog:          log.New(io.Discard, "", 0),
	}
	if !s.track(l, srv) {
		_ = l.Close()
		return net.ErrClosed
	}
	err := srv.Serve(l)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// ServeSOCKS serves SOCKS5 clients on l until Close.
func (s *Server) ServeSOCKS(l net.Listener) error {
	if !s.track(l, nil) {
		if l != nil {
			_ = l.Close()
		}
		return net.ErrClosed
	}
	for {
		c, err := l.Accept()
		if err != nil {
			if s.isClosed() {
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return err
		}
		go s.serveSOCKSConn(c)
	}
}

func (s *Server) track(l net.Listener, srv *http.Server) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false
	}
	s.listeners = append(s.listeners, l)
	if srv != nil {
		s.outer = append(s.outer, srv)
	}
	return true
}

func (s *Server) isClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

// Close stops every listener and the intercepting server. Tunnels already
// open are not interrupted.
func (s *Server) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	ls, outer := s.listeners, s.outer
	s.mu.Unlock()
	for _, srv := range outer {
		_ = srv.Close()
	}
	for _, l := range ls {
		_ = l.Close()
	}
	_ = s.inner.Close()
	s.transport.CloseIdleConnections()
	return nil
}

func (s *Server) record(e audit.Entry) {
	if s.cfg.Audit == nil {
		return
	}
	e.Session, e.Via = s.cfg.Session, s.cfg.Via
	if err := s.cfg.Audit.Record(e); err != nil {
		s.cfg.Logf("opfence: writing the audit log: %v", err)
	}
}

// isCatalogHost reports whether the proxy intercepts host.
func (s *Server) isCatalogHost(host string) bool {
	return s.cfg.Engine.Catalog.ProviderForHost(host) != nil
}

// databasePort reports whether port is one where host's provider speaks a
// database's own protocol, which Opfence cannot read.
func (s *Server) databasePort(host, port string) bool {
	p := s.cfg.Engine.Catalog.ProviderForHost(host)
	if p == nil {
		return false
	}
	n, err := strconv.Atoi(port)
	return err == nil && slices.Contains(p.DatabasePorts, n)
}

// passthrough reports whether host is on the passthrough list or is one of
// the agent's backend hosts.
func (s *Server) passthrough(host string) bool {
	return hostIn(host, s.cfg.Passthrough) || hostIn(host, s.cfg.AgentHosts)
}

// hostIn reports whether host matches one of patterns (exact names or
// *.suffix).
func hostIn(host string, patterns []string) bool {
	for _, p := range patterns {
		if host == p || (strings.HasPrefix(p, "*.") && strings.HasSuffix(host, p[1:])) {
			return true
		}
	}
	return false
}

// userPassthrough reports whether host is on the passthrough list through
// an entry other than the built-in defaults.
func (s *Server) userPassthrough(host string) bool {
	for _, p := range s.cfg.Passthrough {
		if slices.Contains(policy.DefaultPassthrough, p) {
			continue
		}
		if host == p || (strings.HasPrefix(p, "*.") && strings.HasSuffix(host, p[1:])) {
			return true
		}
	}
	return false
}

// allowPrivate reports whether a tunnel to host may reach a private
// address: on the agent listener (PrivateTunnels), or when the user listed
// host by exact name (an internal registry). Patterns and the built-in
// defaults never do.
func (s *Server) allowPrivate(host string) bool {
	if s.cfg.PrivateTunnels {
		return true
	}
	for _, p := range s.cfg.Passthrough {
		if host == p && !slices.Contains(policy.DefaultPassthrough, p) {
			return true
		}
	}
	return false
}

// chanListener is a net.Listener fed with connections from a channel, so one
// http.Server can serve every intercepted TLS connection.
type chanListener struct {
	ch   chan net.Conn
	done chan struct{}
	once sync.Once
}

func newChanListener() *chanListener {
	return &chanListener{ch: make(chan net.Conn), done: make(chan struct{})}
}

func (l *chanListener) push(c net.Conn) {
	select {
	case l.ch <- c:
	case <-l.done:
		_ = c.Close()
	}
}

func (l *chanListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.ch:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *chanListener) Close() error {
	l.once.Do(func() { close(l.done) })
	return nil
}

func (l *chanListener) Addr() net.Addr { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)} }
