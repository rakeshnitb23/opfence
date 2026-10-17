package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Upstream is a proxy Opfence must itself go through, such as a corporate
// proxy on a network that allows no direct connections. Every upstream
// connection, intercepted or tunnelled, is opened with CONNECT through it,
// except to hosts NoProxy lists.
type Upstream struct {
	URL     *url.URL // http:// or https://, optionally with user:password
	NoProxy string   // comma-separated, as in NO_PROXY
}

// UpstreamFromEnv reads the proxy Opfence was started behind:
// HTTPS_PROXY, then HTTP_PROXY (either case), and NO_PROXY. It returns nil
// when none is set. Run it before Opfence sets those variables for a child.
func UpstreamFromEnv(getenv func(string) string) (*Upstream, error) {
	first := func(names ...string) string {
		for _, n := range names {
			if v := strings.TrimSpace(getenv(n)); v != "" {
				return v
			}
		}
		return ""
	}
	raw := first("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy")
	if raw == "" {
		return nil, nil
	}
	if !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("upstream proxy %q: %w", Redact(raw), err)
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return nil, fmt.Errorf("upstream proxy %s: only http:// and https:// proxies are supported", Redact(raw))
	}
	return &Upstream{URL: u, NoProxy: first("NO_PROXY", "no_proxy")}, nil
}

// Redact hides a proxy URL's password.
func Redact(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.User == nil {
		return raw
	}
	return u.Redacted()
}

// Bypass reports whether host (no port) is reached directly, per NoProxy:
// "*", an exact name, a domain suffix ("example.com" and ".example.com"
// both cover sub.example.com), an IP address or a CIDR range.
func (u *Upstream) Bypass(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	ip := net.ParseIP(host)
	for _, e := range strings.Split(u.NoProxy, ",") {
		e = strings.ToLower(strings.TrimSpace(e))
		if e == "" {
			continue
		}
		if e == "*" {
			return true
		}
		if h, _, err := net.SplitHostPort(e); err == nil {
			e = h
		}
		e = strings.Trim(e, "[]")
		if _, cidr, err := net.ParseCIDR(e); err == nil {
			if ip != nil && cidr.Contains(ip) {
				return true
			}
			continue
		}
		if eip := net.ParseIP(e); eip != nil {
			if ip != nil && eip.Equal(ip) {
				return true
			}
			continue
		}
		e = strings.TrimPrefix(strings.TrimPrefix(e, "*"), ".")
		if host == e || strings.HasSuffix(host, "."+e) {
			return true
		}
	}
	return false
}

// connect opens a tunnel to addr through the upstream proxy, using dial to
// reach the proxy itself.
func (u *Upstream) connect(ctx context.Context, dial func(ctx context.Context, network, addr string) (net.Conn, error), addr string) (net.Conn, error) {
	port := u.URL.Port()
	if port == "" {
		port = map[string]string{"http": "80", "https": "443"}[u.URL.Scheme]
	}
	c, err := dial(ctx, "tcp", net.JoinHostPort(u.URL.Hostname(), port))
	if err != nil {
		return nil, fmt.Errorf("reaching the upstream proxy %s: %w", u.URL.Host, err)
	}
	deadline := time.Now().Add(dialTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = c.SetDeadline(deadline)
	if u.URL.Scheme == "https" {
		tc := tls.Client(c, &tls.Config{ServerName: u.URL.Hostname(), MinVersion: tls.VersionTLS12})
		if err := tc.HandshakeContext(ctx); err != nil {
			c.Close()
			return nil, fmt.Errorf("upstream proxy %s: %w", u.URL.Host, err)
		}
		c = tc
	}
	req := &http.Request{Method: "CONNECT", URL: &url.URL{Opaque: addr}, Host: addr, Header: http.Header{}}
	if u.URL.User != nil {
		pass, _ := u.URL.User.Password()
		req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(u.URL.User.Username()+":"+pass)))
	}
	if err := req.Write(c); err != nil {
		c.Close()
		return nil, fmt.Errorf("upstream proxy %s: %w", u.URL.Host, err)
	}
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		c.Close()
		return nil, fmt.Errorf("upstream proxy %s: %w", u.URL.Host, err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		c.Close()
		return nil, fmt.Errorf("upstream proxy %s refused CONNECT %s: %s", u.URL.Host, addr, resp.Status)
	}
	_ = c.SetDeadline(time.Time{})
	if br.Buffered() > 0 {
		return &prefixConn{Conn: c, r: br}, nil
	}
	return c, nil
}
