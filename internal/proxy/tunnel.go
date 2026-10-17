package proxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/rakeshnitb23/opfence/internal/audit"
)

const (
	helloTimeout = 10 * time.Second
	dialTimeout  = 15 * time.Second
)

// handshake lets the HTTP CONNECT and SOCKS5 front ends share one routing
// path: accept tells the client the tunnel is open, refuse that it is not.
type handshake struct {
	accept func() error
	refuse func(reason string) error
}

// serveProxy is the HTTP proxy front end.
func (s *Server) serveProxy(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		host, port := splitTarget(r.Host)
		hj, ok := w.(http.Hijacker)
		if !ok || host == "" {
			http.Error(w, "Opfence: bad CONNECT request", http.StatusBadRequest)
			return
		}
		conn, brw, err := hj.Hijack()
		if err != nil {
			return
		}
		// The client may send its TLS ClientHello right behind the CONNECT
		// request; keep whatever the server already buffered.
		c := &prefixConn{Conn: conn, r: io.MultiReader(brw.Reader, conn)}
		s.routeTunnel(c, host, port, handshake{
			accept: func() error {
				_, err := io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")
				return err
			},
			refuse: func(reason string) error {
				body := "Opfence refused this connection: " + reason + "\n"
				_, err := fmt.Fprintf(conn, "HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body)
				return err
			},
		})
		return
	}
	if !r.URL.IsAbs() || r.URL.Scheme != "http" {
		http.Error(w, "Opfence is a proxy: send absolute http:// URLs or use CONNECT", http.StatusBadRequest)
		return
	}
	host, port := splitTarget(r.URL.Host)
	if port == "" {
		port = "80"
	}
	if host == ProbeHost {
		s.serveProbe(w)
		return
	}
	if s.isCatalogHost(host) {
		s.refused(host, port, "plain HTTP to an API host; Opfence only allows HTTPS")
		http.Error(w, "Opfence: use https:// for "+host, http.StatusForbidden)
		return
	}
	if ok, why := s.tunnelAllowed(host); !ok {
		s.refused(host, port, why)
		http.Error(w, "Opfence refused this request: "+why, http.StatusForbidden)
		return
	}
	s.record(audit.Entry{Event: "tunnel", Host: host, Port: port, Method: r.Method, Outcome: "tunneled", Reason: "plain HTTP; " + s.tunnelReason(host)})
	s.plainRP.ServeHTTP(w, r)
}

// ProbeHost answers plain-HTTP requests sent through any Opfence listener
// without dialling anything, so a client (opfence doctor --probe) can prove
// that its proxy is Opfence. The .invalid name can never resolve.
const ProbeHost = "probe.opfence.invalid"

// Probe is the probe endpoint's answer.
type Probe struct {
	Opfence bool   `json:"opfence"`
	Session string `json:"session"`
	Via     string `json:"via"`
	Mode    string `json:"mode"`
}

func (s *Server) serveProbe(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(Probe{Opfence: true, Session: s.cfg.Session, Via: s.cfg.Via, Mode: s.cfg.Mode})
}

// splitTarget splits a CONNECT or URL host, keeping the port ("443" when
// absent, for CONNECT).
func splitTarget(hostport string) (host, port string) {
	h, p, err := net.SplitHostPort(hostport)
	if err != nil {
		h, p = hostport, "443"
	}
	h = strings.TrimSuffix(strings.ToLower(strings.Trim(h, "[]")), ".")
	return h, p
}

// tunnelAllowed reports whether a host that is not intercepted may be
// tunnelled, and if not, why.
func (s *Server) tunnelAllowed(host string) (bool, string) {
	switch {
	case s.passthrough(host):
		return true, ""
	case s.cfg.Mode == "open":
		return true, ""
	default:
		return false, host + " is not an API in the Opfence catalog or on your passthrough list (strict mode)"
	}
}

func (s *Server) tunnelReason(host string) string {
	if s.passthrough(host) {
		return "passthrough"
	}
	return "open mode"
}

func (s *Server) refused(host, port, reason string) {
	s.record(audit.Entry{Event: "refused", Host: host, Port: port, Outcome: "refused", Reason: reason})
}

// routeTunnel decides what happens to a tunnel request: intercept (catalog
// hosts, TLS on 443), tunnel (passthrough, or anything in open mode) or
// refuse.
//
// Every tunnel on port 443 must be TLS, and its ClientHello is read before
// anything is dialled. A server name that differs from the CONNECT host is
// refused, so a tunnel opened for a passthrough host cannot carry a TLS
// session for an API (on a shared CDN that would reach the API uninspected),
// and a tunnel to an IP address is decided by its server name and dials that
// name. Other ports are tunnelled by name without inspection.
func (s *Server) routeTunnel(c net.Conn, host, port string, hs handshake) {
	defer c.Close()
	isIP := net.ParseIP(host) != nil
	catalog := !isIP && s.isCatalogHost(host)
	refuse := func(reason string) {
		s.refused(host, port, reason)
		_ = hs.refuse(reason)
	}
	if catalog && port != "443" {
		refuse(fmt.Sprintf("%s is an API in the Opfence catalog; Opfence only inspects it over HTTPS on port 443", host))
		return
	}
	if !catalog && !isIP {
		if ok, why := s.tunnelAllowed(host); !ok {
			refuse(why)
			return
		}
	}
	if port != "443" {
		if ok, why := s.tunnelAllowed(host); !ok {
			refuse(why)
			return
		}
		up, err := s.dial(context.Background(), "tcp", net.JoinHostPort(host, port), s.allowPrivate(host))
		if err != nil {
			refuse(err.Error())
			return
		}
		defer up.Close()
		if hs.accept() != nil {
			return
		}
		s.record(audit.Entry{Event: "tunnel", Host: host, Port: port, Outcome: "tunneled", Reason: s.tunnelReason(host)})
		splice(c, up)
		return
	}

	if hs.accept() != nil {
		return
	}
	_ = c.SetReadDeadline(time.Now().Add(helloTimeout))
	sni, peeked, err := peekServerName(c)
	_ = c.SetReadDeadline(time.Time{})
	name := sni
	switch {
	case err != nil:
		s.refused(host, port, "not a TLS connection: "+err.Error())
		return
	case sni == "" && isIP:
		s.refused(host, port, "TLS ClientHello to an IP address has no server name")
		return
	case sni == "":
		name = host
	case !isIP && sni != host:
		s.refused(host, port, fmt.Sprintf("TLS server name %s does not match the tunnel host", sni))
		return
	}
	pc := &prefixConn{Conn: c, r: io.MultiReader(bytes.NewReader(peeked), c)}
	if s.isCatalogHost(name) {
		if !s.cfg.CA.Permits(name) {
			s.refused(name, port, "the Opfence certificate authority does not cover "+name+"; regenerate it with opfence trust")
			return
		}
		s.intercept(pc, name)
		return
	}
	if ok, why := s.tunnelAllowed(name); !ok {
		s.refused(name, port, why)
		return
	}
	up, err := s.dial(context.Background(), "tcp", net.JoinHostPort(name, port), s.allowPrivate(name))
	if err != nil {
		s.refused(name, port, err.Error())
		return
	}
	defer up.Close()
	s.record(audit.Entry{Event: "tunnel", Host: name, Port: port, Outcome: "tunneled", Reason: s.tunnelReason(name)})
	splice(pc, up)
}

// intercept terminates TLS with a leaf for host and hands the connection to
// the inner HTTP server, which negotiates HTTP/2 or HTTP/1.1.
func (s *Server) intercept(c net.Conn, host string) {
	done := make(chan struct{})
	tc := tls.Server(&closeNotifyConn{Conn: c, done: done}, &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"h2", "http/1.1"},
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			return s.cfg.CA.Leaf(host)
		},
	})
	s.conns.push(tc)
	<-done // routeTunnel's deferred Close must wait until the server is done
}

// closeNotifyConn reports when the inner server closes the connection.
type closeNotifyConn struct {
	net.Conn
	done chan struct{}
	once sync.Once
}

func (c *closeNotifyConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { close(c.done) })
	return err
}

// errHelloRead stops the throwaway TLS handshake once the ClientHello is in.
var errHelloRead = errors.New("hello read")

// peekServerName reads the TLS ClientHello from c and returns its server
// name and the bytes read, which must be replayed to whoever handles the
// connection next. It uses crypto/tls's own parser on a connection that
// records reads and refuses writes.
func peekServerName(c net.Conn) (string, []byte, error) {
	var buf bytes.Buffer
	var sni string
	err := tls.Server(readOnlyConn{r: io.TeeReader(c, &buf)}, &tls.Config{
		GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
			sni = strings.TrimSuffix(strings.ToLower(h.ServerName), ".")
			return nil, errHelloRead
		},
	}).Handshake()
	if !errors.Is(err, errHelloRead) {
		if err == nil {
			err = errors.New("unexpected handshake result")
		}
		return "", nil, err
	}
	return sni, buf.Bytes(), nil
}

type readOnlyConn struct{ r io.Reader }

func (c readOnlyConn) Read(p []byte) (int, error)          { return c.r.Read(p) }
func (readOnlyConn) Write([]byte) (int, error)             { return 0, io.ErrClosedPipe }
func (readOnlyConn) Close() error                          { return nil }
func (readOnlyConn) LocalAddr() net.Addr                   { return nil }
func (readOnlyConn) RemoteAddr() net.Addr                  { return nil }
func (readOnlyConn) SetDeadline(time.Time) error           { return nil }
func (readOnlyConn) SetReadDeadline(time.Time) error       { return nil }
func (readOnlyConn) SetWriteDeadline(time.Time) error      { return nil }
func (c readOnlyConn) ReadFrom(r io.Reader) (int64, error) { return 0, io.ErrClosedPipe }

// prefixConn reads from r (buffered bytes, then the connection) instead of
// the connection directly.
type prefixConn struct {
	net.Conn
	r io.Reader
}

func (c *prefixConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// splice copies both ways until both directions finish.
func splice(a, b net.Conn) {
	var wg sync.WaitGroup
	cp := func(dst, src net.Conn) {
		defer wg.Done()
		_, _ = io.Copy(dst, src)
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		} else {
			_ = dst.Close()
		}
	}
	wg.Add(2)
	go cp(a, b)
	go cp(b, a)
	wg.Wait()
}

// dial connects upstream. The default dialer refuses loopback, private,
// link-local and other non-public addresses after DNS resolution (so a
// public name that resolves to 127.0.0.1 is refused too), unless
// allowPrivate is set for a host the user listed by name.
func (s *Server) dial(ctx context.Context, network, addr string, allowPrivate bool) (net.Conn, error) {
	if s.cfg.DialContext != nil {
		return s.cfg.DialContext(ctx, network, addr)
	}
	d := &net.Dialer{Timeout: dialTimeout}
	if !allowPrivate {
		d.Control = func(_, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return err
			}
			if ip := net.ParseIP(host); ip == nil || !PublicIP(ip) {
				return fmt.Errorf("%s is not a public address; list the host by name under passthrough in your user config to allow it", host)
			}
			return nil
		}
	}
	return d.DialContext(ctx, network, addr)
}

var cgnat = &net.IPNet{IP: net.IPv4(100, 64, 0, 0), Mask: net.CIDRMask(10, 32)}

// PublicIP reports whether ip is a globally routable unicast address.
func PublicIP(ip net.IP) bool {
	return !(ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() || ip.IsUnspecified() || ip.IsInterfaceLocalMulticast() || cgnat.Contains(ip))
}
