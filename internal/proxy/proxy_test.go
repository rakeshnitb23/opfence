package proxy

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rakeshnitb23/opfence/internal/audit"
	"github.com/rakeshnitb23/opfence/internal/ca"
	"github.com/rakeshnitb23/opfence/internal/catalog"
	"github.com/rakeshnitb23/opfence/internal/engine"
	"github.com/rakeshnitb23/opfence/internal/policy"
	"github.com/rakeshnitb23/opfence/internal/secrets"
)

// env is a proxy wired to fake upstreams: an HTTPS API server answering for
// every catalog host, and a TCP echo server for tunnels.
type env struct {
	t         *testing.T
	ca        *ca.CA
	srv       *Server
	httpAddr  string
	socksAddr string
	auditPath string

	hits     atomic.Int32
	mu       sync.Mutex
	upstream []*http.Request // requests the API server received
	bodies   []string
	echoAddr string // plain TCP echo
	tlsEcho  string // TLS echo, certificate from upPool (a separate CA)
	upPool   *x509.CertPool
}

type opts struct {
	mode        string
	defaultDial bool // use the real dialer with its private-address guard
	secrets     *secrets.Set
	via         string
	private     bool // PrivateTunnels
	// respond, when set, answers upstream requests instead of the default.
	respond func(w http.ResponseWriter, r *http.Request)
}

func newEnv(t *testing.T, o opts) *env {
	t.Helper()
	cat, err := catalog.Embedded()
	if err != nil {
		t.Fatal(err)
	}
	var hosts []string
	for _, p := range cat.Providers {
		hosts = append(hosts, p.Hosts...)
	}
	e := &env{t: t}
	if e.ca, err = ca.New("test", ca.PermittedDomains(hosts)); err != nil {
		t.Fatal(err)
	}

	// The fake API: its certificate comes from a separate CA that only the
	// proxy's upstream transport trusts.
	upCA, err := ca.New("upstream", ca.PermittedDomains(hosts))
	if err != nil {
		t.Fatal(err)
	}
	api := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		e.hits.Add(1)
		body, _ := io.ReadAll(r.Body)
		e.mu.Lock()
		e.upstream = append(e.upstream, r)
		e.bodies = append(e.bodies, string(body))
		e.mu.Unlock()
		r.Body = io.NopCloser(bytes.NewReader(body))
		if o.respond != nil {
			o.respond(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"data":{"ok":true},"proto":%q}`, r.Proto)
	}))
	api.EnableHTTP2 = true
	api.TLS = &tls.Config{GetCertificate: func(h *tls.ClientHelloInfo) (*tls.Certificate, error) { return upCA.Leaf(h.ServerName) }}
	api.StartTLS()
	t.Cleanup(api.Close)

	echoCA, err := ca.New("echo", []string{"registry.npmjs.org", "example.com", "backboard.railway.com"})
	if err != nil {
		t.Fatal(err)
	}
	e.upPool = echoCA.Pool()
	serveEcho := func(l net.Listener) string {
		t.Cleanup(func() { l.Close() })
		go func() {
			for {
				c, err := l.Accept()
				if err != nil {
					return
				}
				go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
			}
		}()
		return l.Addr().String()
	}
	plain, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	e.echoAddr = serveEcho(plain)
	tl, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	e.tlsEcho = serveEcho(tls.NewListener(tl, &tls.Config{GetCertificate: func(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
		return echoCA.Leaf(h.ServerName)
	}}))

	e.auditPath = filepath.Join(t.TempDir(), "audit.jsonl")
	log, err := audit.Open(e.auditPath)
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{
		Engine:          engine.New(cat, policy.Resolve(nil, nil)),
		CA:              e.ca,
		Audit:           log,
		Session:         "test",
		Mode:            o.mode,
		Via:             o.via,
		PrivateTunnels:  o.private,
		Secrets:         o.secrets,
		UpstreamRootCAs: upCA.Pool(),
		Logf:            t.Logf,
	}
	if !o.defaultDial {
		cfg.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, _ := net.SplitHostPort(addr)
			target := e.echoAddr
			switch {
			case cat.ProviderForHost(host) != nil:
				target = api.Listener.Addr().String()
			case port == "443":
				target = e.tlsEcho
			}
			return (&net.Dialer{}).DialContext(ctx, network, target)
		}
	}
	if e.srv, err = New(cfg); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.srv.Close() })
	hl, _ := net.Listen("tcp", "127.0.0.1:0")
	sl, _ := net.Listen("tcp", "127.0.0.1:0")
	e.httpAddr, e.socksAddr = hl.Addr().String(), sl.Addr().String()
	go e.srv.ServeHTTPProxy(hl)
	go e.srv.ServeSOCKS(sl)
	return e
}

// client is an HTTP client using the proxy and trusting the Opfence CA.
func (e *env) client(h2 bool) *http.Client {
	tr := &http.Transport{
		Proxy:             http.ProxyURL(&url.URL{Scheme: "http", Host: e.httpAddr}),
		TLSClientConfig:   &tls.Config{RootCAs: e.ca.Pool()},
		ForceAttemptHTTP2: h2,
	}
	if !h2 {
		tr.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
	}
	e.t.Cleanup(tr.CloseIdleConnections)
	return &http.Client{Transport: tr, Timeout: 10 * time.Second}
}

func (e *env) entries() []audit.Entry {
	e.t.Helper()
	data, err := os.ReadFile(e.auditPath)
	if err != nil {
		e.t.Fatal(err)
	}
	if _, err := audit.Verify(bytes.NewReader(data)); err != nil {
		e.t.Fatal(err)
	}
	es, err := audit.Read(bytes.NewReader(data))
	if err != nil {
		e.t.Fatal(err)
	}
	return es
}

func post(t *testing.T, c *http.Client, u, body string, hdr ...string) (*http.Response, string) {
	t.Helper()
	req, _ := http.NewRequest("POST", u, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

const pocketOS = `{"query":"mutation VolumeDelete($volumeId: String!) { volumeDelete(volumeId: $volumeId) }","variables":{"volumeId":"vol-pg-data"}}`

// The stage 6 exit criterion: the PocketOS call is stopped before it leaves
// the machine.
func TestPocketOSNeverReachesUpstream(t *testing.T) {
	e := newEnv(t, opts{})
	for _, h2 := range []bool{true, false} {
		resp, body := post(t, e.client(h2), "https://backboard.railway.com/graphql/v2", pocketOS, "Authorization", "Bearer opf_railway_EXAMPLE")
		if resp.StatusCode != http.StatusForbidden || !strings.Contains(body, "volumeDelete") && !strings.Contains(body, "vol-pg-data") {
			t.Fatalf("h2=%v: %d %s", h2, resp.StatusCode, body)
		}
		var out struct{ Error map[string]any }
		if err := json.Unmarshal([]byte(body), &out); err != nil || out.Error["decision"] != "confirm" || out.Error["rule"] != "railway.volume.delete" {
			t.Fatalf("h2=%v: body %s", h2, body)
		}
	}
	if n := e.hits.Load(); n != 0 {
		t.Fatalf("upstream was contacted %d times", n)
	}
	es := e.entries()
	last := es[len(es)-1]
	if last.Outcome != "blocked" || last.Decision != "confirm" || last.Hash == "" || last.Operations[0].Rule != "railway.volume.delete" || last.Operations[0].Environment != "production" {
		t.Fatalf("audit entry %+v", last)
	}
	if strings.Contains(fmt.Sprint(es), "opf_railway_EXAMPLE") {
		t.Fatal("credential written to the audit log")
	}
}

func TestAllowedRequestReachesUpstream(t *testing.T) {
	e := newEnv(t, opts{})
	query := `{"query":"query { me { id email } }"}`
	for _, h2 := range []bool{true, false} {
		resp, body := post(t, e.client(h2), "https://backboard.railway.com/graphql/v2?x=%2F1", query,
			"Authorization", "Bearer opf_railway_EXAMPLE", "Proxy-Authorization", "Basic c2VjcmV0", "X-Forwarded-For", "10.0.0.1")
		if resp.StatusCode != 200 || !strings.Contains(body, `"ok":true`) {
			t.Fatalf("h2=%v: %d %s", h2, resp.StatusCode, body)
		}
		if wantProto := map[bool]string{true: "HTTP/2.0", false: "HTTP/1.1"}[h2]; resp.Proto != wantProto {
			t.Fatalf("client protocol %s, want %s", resp.Proto, wantProto)
		}
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.upstream) != 2 {
		t.Fatalf("upstream saw %d requests", len(e.upstream))
	}
	r := e.upstream[0]
	if r.Host != "backboard.railway.com" || r.URL.RequestURI() != "/graphql/v2?x=%2F1" || r.Header.Get("Authorization") != "Bearer opf_railway_EXAMPLE" ||
		r.Header.Get("Proxy-Authorization") != "" || r.Header.Get("X-Forwarded-For") != "" || e.bodies[0] != query || r.ProtoMajor != 2 {
		t.Fatalf("upstream request %s %s %s %v body %q", r.Proto, r.Host, r.URL.RequestURI(), r.Header, e.bodies[0])
	}
	es := e.entries()
	if es[len(es)-1].Outcome != "forwarded" || es[len(es)-1].Status != 200 {
		t.Fatalf("audit %+v", es[len(es)-1])
	}
}

func TestOversizedBodyIsNotForwarded(t *testing.T) {
	e := newEnv(t, opts{})
	big := `{"query":"query { me { id } }","pad":"` + strings.Repeat("a", 70<<10) + `"}`
	resp, body := post(t, e.client(true), "https://backboard.railway.com/graphql/v2", big)
	if resp.StatusCode != http.StatusForbidden || e.hits.Load() != 0 {
		t.Fatalf("%d %s, upstream hits %d", resp.StatusCode, body, e.hits.Load())
	}
}

func TestMCPGetsJSONRPCError(t *testing.T) {
	e := newEnv(t, opts{})
	resp, body := post(t, e.client(true), "https://mcp.supabase.com/mcp",
		`{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"delete_branch","arguments":{"branch_id":"br-develop"}}}`,
		"Accept", "application/json, text/event-stream")
	var out struct {
		ID    int
		Error struct {
			Code    int
			Message string
		}
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil || resp.StatusCode != 200 || out.ID != 7 || out.Error.Code != -32001 ||
		!strings.Contains(out.Error.Message, "br-develop") || e.hits.Load() != 0 {
		t.Fatalf("%d %s", resp.StatusCode, body)
	}
	// A read tool goes through.
	resp, _ = post(t, e.client(true), "https://mcp.supabase.com/mcp",
		`{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"list_tables","arguments":{"project_id":"p1"}}}`)
	if resp.StatusCode != 200 || e.hits.Load() != 1 {
		t.Fatalf("read tool: %d, hits %d", resp.StatusCode, e.hits.Load())
	}
}

// socksDial opens a tunnel through the SOCKS5 listener.
func socksDial(proxyAddr, host string, port int) (net.Conn, error) {
	c, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		return nil, err
	}
	req := []byte{5, 1, 0}
	req = append(req, 5, 1, 0, 3, byte(len(host)))
	req = append(req, host...)
	req = binary.BigEndian.AppendUint16(req, uint16(port))
	if _, err := c.Write(req); err != nil {
		return nil, err
	}
	var resp [12]byte
	if _, err := io.ReadFull(c, resp[:12]); err != nil {
		c.Close()
		return nil, err
	}
	if resp[0] != 5 || resp[1] != 0 || resp[3] != 0 {
		c.Close()
		return nil, fmt.Errorf("method reply %v, connect reply code %d", resp[:2], resp[3])
	}
	return c, nil
}

func TestSOCKS5(t *testing.T) {
	e := newEnv(t, opts{})
	tr := &http.Transport{
		DialContext: func(_ context.Context, _, addr string) (net.Conn, error) {
			host, port, _ := net.SplitHostPort(addr)
			p, _ := strconv.Atoi(port)
			return socksDial(e.socksAddr, host, p)
		},
		TLSClientConfig:   &tls.Config{RootCAs: e.ca.Pool()},
		ForceAttemptHTTP2: true,
	}
	defer tr.CloseIdleConnections()
	c := &http.Client{Transport: tr, Timeout: 10 * time.Second}
	resp, body := post(t, c, "https://backboard.railway.com/graphql/v2", pocketOS)
	if resp.StatusCode != http.StatusForbidden || e.hits.Load() != 0 {
		t.Fatalf("PocketOS over SOCKS: %d %s", resp.StatusCode, body)
	}
	resp, _ = post(t, c, "https://backboard.railway.com/graphql/v2", `{"query":"{ me { id } }"}`)
	if resp.StatusCode != 200 || e.hits.Load() != 1 {
		t.Fatalf("query over SOCKS: %d", resp.StatusCode)
	}
	if _, err := socksDial(e.socksAddr, "example.com", 443); err == nil {
		t.Fatal("strict mode let SOCKS reach example.com")
	}
}

// connect opens a CONNECT tunnel and returns the connection and status.
func connect(t *testing.T, proxyAddr, target string) (net.Conn, int) {
	t.Helper()
	c, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatal(err)
	}
	return c, resp.StatusCode
}

func echoes(c net.Conn) bool {
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	msg := "GET / HTTP/1.1\r\n" // long enough to show it is not TLS
	if _, err := c.Write([]byte(msg)); err != nil {
		return false
	}
	buf := make([]byte, len(msg))
	_, err := io.ReadFull(c, buf)
	return err == nil && string(buf) == msg
}

// tlsEchoes runs TLS for name over a tunnel and checks the echo.
func (e *env) tlsEchoes(c net.Conn, name string) bool {
	tc := tls.Client(c, &tls.Config{ServerName: name, RootCAs: e.upPool})
	return echoes(tc)
}

func TestStrictOpenAndPassthrough(t *testing.T) {
	strict := newEnv(t, opts{})
	if c, code := connect(t, strict.httpAddr, "example.com:443"); code != http.StatusForbidden {
		t.Fatalf("strict: example.com got %d", code)
	} else {
		c.Close()
	}
	c, code := connect(t, strict.httpAddr, "registry.npmjs.org:443")
	if code != 200 || !strict.tlsEchoes(c, "registry.npmjs.org") {
		t.Fatalf("passthrough: %d", code)
	}
	c.Close()
	// Other ports are tunnelled by name without inspection.
	c, code = connect(t, strict.httpAddr, "github.com:22")
	if code != 200 || !echoes(c) {
		t.Fatalf("passthrough on port 22: %d", code)
	}
	c.Close()
	// Port 443 must be TLS, even to a passthrough host.
	c, code = connect(t, strict.httpAddr, "registry.npmjs.org:443")
	if code != 200 || echoes(c) {
		t.Fatalf("plain bytes on 443 were tunnelled (%d)", code)
	}
	c.Close()
	// A passthrough tunnel cannot carry TLS for an API (CDN fronting).
	c, _ = connect(t, strict.httpAddr, "registry.npmjs.org:443")
	if strict.tlsEchoes(c, "backboard.railway.com") {
		t.Fatal("TLS for an API host was tunnelled under a passthrough name")
	}
	c.Close()
	if c, code := connect(t, strict.httpAddr, "backboard.railway.com:8443"); code != http.StatusForbidden {
		t.Fatalf("catalog host on another port got %d", code)
	} else {
		c.Close()
	}

	open := newEnv(t, opts{mode: "open"})
	c, code = connect(t, open.httpAddr, "example.com:443")
	if code != 200 || !open.tlsEchoes(c, "example.com") {
		t.Fatalf("open: example.com got %d", code)
	}
	c.Close()

	var reasons []string
	for _, e := range strict.entries() {
		reasons = append(reasons, e.Outcome+": "+e.Host+": "+e.Reason)
	}
	got := strings.Join(reasons, "\n")
	for _, want := range []string{"refused: example.com", "tunneled: registry.npmjs.org: passthrough", "refused: backboard.railway.com: backboard.railway.com is an API in the Opfence catalog",
		"refused: registry.npmjs.org: not a TLS connection", "refused: registry.npmjs.org: TLS server name backboard.railway.com does not match"} {
		if !strings.Contains(got, want) {
			t.Errorf("audit missing %q in:\n%s", want, got)
		}
	}
}

func TestServerNameChecks(t *testing.T) {
	e := newEnv(t, opts{})
	// A tunnel opened for one catalog host cannot be used for another.
	c, code := connect(t, e.httpAddr, "backboard.railway.com:443")
	if code != 200 {
		t.Fatalf("CONNECT got %d", code)
	}
	tc := tls.Client(c, &tls.Config{ServerName: "api.github.com", RootCAs: e.ca.Pool()})
	_ = tc.SetDeadline(time.Now().Add(5 * time.Second))
	if err := tc.Handshake(); err == nil {
		t.Fatal("handshake for a different server name succeeded")
	}
	c.Close()

	// A tunnel to an IP address is decided by the server name and reaches
	// that name, inspected.
	c, code = connect(t, e.httpAddr, "203.0.113.9:443")
	if code != 200 {
		t.Fatalf("CONNECT to IP got %d", code)
	}
	tc = tls.Client(c, &tls.Config{ServerName: "backboard.railway.com", RootCAs: e.ca.Pool(), NextProtos: []string{"http/1.1"}})
	fmt.Fprintf(tc, "POST /graphql/v2 HTTP/1.1\r\nHost: backboard.railway.com\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s", len(pocketOS), pocketOS)
	resp, err := http.ReadResponse(bufio.NewReader(tc), nil)
	if err != nil || resp.StatusCode != http.StatusForbidden {
		t.Fatalf("PocketOS via IP tunnel: %v %v", resp, err)
	}
	tc.Close()

	// A request whose Host differs from the TLS server name gets 421.
	c, _ = connect(t, e.httpAddr, "backboard.railway.com:443")
	tc = tls.Client(c, &tls.Config{ServerName: "backboard.railway.com", RootCAs: e.ca.Pool(), NextProtos: []string{"http/1.1"}})
	fmt.Fprintf(tc, "GET /user HTTP/1.1\r\nHost: api.github.com\r\n\r\n")
	resp, err = http.ReadResponse(bufio.NewReader(tc), nil)
	if err != nil || resp.StatusCode != http.StatusMisdirectedRequest {
		t.Fatalf("Host mismatch: %v %v", resp, err)
	}
	tc.Close()
	if e.hits.Load() != 0 {
		t.Fatalf("upstream contacted %d times", e.hits.Load())
	}
}

func TestPlainHTTPToAPIRefused(t *testing.T) {
	e := newEnv(t, opts{})
	resp, err := e.client(false).Get("http://backboard.railway.com/graphql/v2")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("got %d", resp.StatusCode)
	}
}

func TestPrivateAddressesRefused(t *testing.T) {
	e := newEnv(t, opts{mode: "open", defaultDial: true})
	c, code := connect(t, e.httpAddr, e.echoAddr)
	c.Close()
	if code != http.StatusForbidden {
		t.Fatalf("open mode reached a loopback address: %d", code)
	}
	if es := e.entries(); !strings.Contains(es[len(es)-1].Reason, "not a public address") {
		t.Fatalf("reason %q", es[len(es)-1].Reason)
	}
	for ip, public := range map[string]bool{"8.8.8.8": true, "2606:4700::1111": true, "127.0.0.1": false, "10.1.2.3": false, "169.254.169.254": false, "100.64.0.1": false, "::1": false, "fe80::1": false, "0.0.0.0": false, "fd00::1": false} {
		if PublicIP(net.ParseIP(ip)) != public {
			t.Errorf("PublicIP(%s) != %v", ip, public)
		}
	}
}

// The agent listener tunnels to private addresses (its clients run outside
// the sandbox and could connect directly) and labels its audit entries.
func TestAgentListenerPrivateTunnels(t *testing.T) {
	e := newEnv(t, opts{mode: "open", defaultDial: true, private: true, via: "agent"})
	c, code := connect(t, e.httpAddr, e.echoAddr)
	defer c.Close()
	if code != http.StatusOK || !echoes(c) {
		t.Fatalf("agent listener refused a private tunnel: %d", code)
	}
	if es := e.entries(); es[len(es)-1].Via != "agent" || es[len(es)-1].Outcome != "tunneled" {
		t.Fatalf("audit %+v", es[len(es)-1])
	}
}

func TestProbeEndpoint(t *testing.T) {
	e := newEnv(t, opts{via: "sandbox"})
	u, _ := url.Parse("http://" + e.httpAddr)
	c := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(u)}}
	resp, err := c.Get("http://" + ProbeHost + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var p Probe
	if err := json.NewDecoder(resp.Body).Decode(&p); err != nil || !p.Opfence || p.Session != "test" || p.Via != "sandbox" || p.Mode != "strict" {
		t.Fatalf("%+v %v", p, err)
	}
	if e.hits.Load() != 0 {
		t.Fatal("the probe reached an upstream")
	}
}

type approveAll struct{ calls atomic.Int32 }

func (a *approveAll) Approve(context.Context, Pending) Approval {
	a.calls.Add(1)
	return Approval{Approved: true, Channel: "test"}
}

func TestApproverIsConsulted(t *testing.T) {
	e := newEnv(t, opts{})
	a := &approveAll{}
	e.srv.cfg.Approver = a
	resp, _ := post(t, e.client(true), "https://backboard.railway.com/graphql/v2", pocketOS)
	if resp.StatusCode != 200 || a.calls.Load() != 1 || e.hits.Load() != 1 {
		t.Fatalf("status %d, approver calls %d, hits %d", resp.StatusCode, a.calls.Load(), e.hits.Load())
	}
	es := e.entries()
	if l := es[len(es)-1]; l.Outcome != "approved" || l.Approver != "test" {
		t.Fatalf("audit %+v", l)
	}
}

func TestCloseStopsListeners(t *testing.T) {
	e := newEnv(t, opts{})
	e.srv.Close()
	// The Serve goroutines may start after Close; they close their
	// listener then.
	deadline := time.Now().Add(2 * time.Second)
	for {
		c, err := net.DialTimeout("tcp", e.httpAddr, time.Second)
		if err != nil {
			break
		}
		c.Close()
		if time.Now().After(deadline) {
			t.Fatal("listener still accepting")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := e.srv.ServeSOCKS(nil); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("serve after close: %v", err)
	}
}

var (
	railwaySecret = &secrets.Secret{Provider: "railway", Name: "RAILWAY_TOKEN", Value: "4f1c2a7e-9b3d-4c8e-a1f2-0d9e8b7c6a5f", Placeholder: "0a9b8c7d-6e5f-4a3b-b2c1-d0e9f8a7b6c5"}
	vercelSecret  = &secrets.Secret{Provider: "vercel", Name: "VERCEL_TOKEN", Value: "vcp_AbCdEfGhIjKlMnOpQrStUvWx", Placeholder: "vcp_ZyXwVuTsRqPoNmLkJiHgFeDc"}
)

// The stage 7 exit criteria: a placeholder is only swapped in for its own
// provider, and real values echoed back are scrubbed.
func TestInjectAndScrub(t *testing.T) {
	set := secrets.NewSet([]*secrets.Secret{railwaySecret, vercelSecret})
	e := newEnv(t, opts{secrets: set, respond: func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		w.Header().Set("X-Echo", auth)
		w.Header().Set("X-AE", r.Header.Get("Accept-Encoding"))
		body := fmt.Sprintf(`{"auth":%q,"env":{"RAILWAY_TOKEN":%q}}`, auth, railwaySecret.Value)
		switch {
		case r.URL.Path == "/br":
			w.Header().Set("Content-Encoding", "br")
			_, _ = w.Write([]byte("not really brotli"))
		case strings.Contains(r.Header.Get("Accept-Encoding"), "gzip"):
			w.Header().Set("Content-Encoding", "gzip")
			zw := gzip.NewWriter(w)
			_, _ = zw.Write([]byte(body))
			_ = zw.Close()
		default:
			_, _ = w.Write([]byte(body))
		}
	}})
	c := e.client(true)
	get := func(u, auth string) (*http.Response, string) {
		req, _ := http.NewRequest("GET", u, nil)
		req.Header.Set("Authorization", "Bearer "+auth)
		req.Header.Set("Accept-Encoding", "gzip") // explicit: the client does not decode
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp, string(b)
	}

	// Vercel's placeholder to Vercel: the API gets the real token, the
	// client never sees it, even inside a gzip response.
	resp, body := get("https://api.vercel.com/v2/user", vercelSecret.Placeholder)
	e.mu.Lock()
	upstreamAuth := e.upstream[len(e.upstream)-1].Header.Get("Authorization")
	e.mu.Unlock()
	if upstreamAuth != "Bearer "+vercelSecret.Value {
		t.Fatalf("upstream got %q", upstreamAuth)
	}
	if resp.StatusCode != 200 || strings.Contains(body, vercelSecret.Value) || strings.Contains(body, railwaySecret.Value) ||
		!strings.Contains(body, vercelSecret.Placeholder) || !strings.Contains(body, railwaySecret.Placeholder) ||
		strings.Contains(resp.Header.Get("X-Echo"), vercelSecret.Value) || resp.Header.Get("Content-Encoding") != "" {
		t.Fatalf("response leaked a secret: %d %v %s", resp.StatusCode, resp.Header, body)
	}

	// Railway's placeholder sent to Vercel is not swapped in.
	_, _ = get("https://api.vercel.com/v2/user", railwaySecret.Placeholder)
	e.mu.Lock()
	upstreamAuth = e.upstream[len(e.upstream)-1].Header.Get("Authorization")
	e.mu.Unlock()
	if upstreamAuth != "Bearer "+railwaySecret.Placeholder {
		t.Fatalf("foreign placeholder became %q", upstreamAuth)
	}
	es := e.entries()
	if last := es[len(es)-1]; !strings.Contains(last.Reason, "placeholder for railway/RAILWAY_TOKEN sent to api.vercel.com") || len(last.Credentials) != 0 {
		t.Fatalf("audit %+v", last)
	}
	if prev := es[len(es)-2]; len(prev.Credentials) != 1 || prev.Credentials[0] != "vercel/VERCEL_TOKEN" {
		t.Fatalf("audit %+v", prev)
	}
	data, _ := os.ReadFile(e.auditPath)
	if bytes.Contains(data, []byte(vercelSecret.Value)) || bytes.Contains(data, []byte(railwaySecret.Value)) {
		t.Fatal("secret value in the audit log")
	}

	// A response Opfence cannot decode is refused rather than passed on.
	if resp, body := get("https://api.vercel.com/br", vercelSecret.Placeholder); resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("br response: %d %s", resp.StatusCode, body)
	}
}
