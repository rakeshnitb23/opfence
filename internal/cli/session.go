package cli

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"

	"github.com/rakeshnitb23/opfence/internal/approve"
	"github.com/rakeshnitb23/opfence/internal/audit"
	"github.com/rakeshnitb23/opfence/internal/ca"
	"github.com/rakeshnitb23/opfence/internal/engine"
	"github.com/rakeshnitb23/opfence/internal/launch"
	"github.com/rakeshnitb23/opfence/internal/proxy"
	"github.com/rakeshnitb23/opfence/internal/secrets"
)

// session is everything one proxy run shares between its listeners: the
// engine, audit log, credentials, CA and approvals.
type session struct {
	id           string
	eng          *engine.Engine
	audit        *audit.Log
	stored       []*secrets.Secret // from the keychain
	extra        []*secrets.Secret // held for this session only
	vault        *secrets.Vault
	ca           *ca.CA
	persistentCA bool
	caFiles      launch.CAFiles
	broker       *approve.Broker
	ctl          *approve.Control
	stopPhone    context.CancelFunc
	approvals    string // how approvals reach the user, for banners
	upstream     *proxy.Upstream
	logf         func(format string, args ...any)

	servers []*proxy.Server
	errc    chan error
}

// sessionOptions configures openSession.
type sessionOptions struct {
	auditPath string
	// socket is the control socket; "" means control-<session>.sock in the
	// state folder, so several sessions can run at once.
	socket string
	// warn receives problems found while starting.
	warn io.Writer
	// logf receives problems while running; nil writes to warn.
	logf func(format string, args ...any)
}

func openSession(g *globalOptions, o sessionOptions) (*session, error) {
	eng, err := g.lazyEngine()
	if err != nil {
		return nil, err
	}
	for _, w := range eng.Policy.Warnings {
		fmt.Fprintln(o.warn, "warning:", w)
	}
	s := &session{id: sessionID(), eng: eng, errc: make(chan error, 8), logf: o.logf}
	// The proxy Opfence itself was started behind, before any child's
	// variables point at Opfence.
	if s.upstream, err = proxy.UpstreamFromEnv(os.Getenv); err != nil {
		return nil, err
	}
	if s.logf == nil {
		s.logf = func(f string, a ...any) { fmt.Fprintf(o.warn, f+"\n", a...) }
	}
	if o.auditPath == "" {
		if o.auditPath, err = audit.DefaultPath(); err != nil {
			return nil, err
		}
	}
	if s.audit, err = audit.Open(o.auditPath); err != nil {
		return nil, err
	}
	var set *secrets.Set
	set, s.vault = loadSecrets(o.warn)
	s.stored = set.All()
	if s.ca, s.persistentCA, err = loadCA(o.warn, eng, s.vault); err != nil {
		return nil, err
	}
	certDir, err := launch.CertDir()
	if err != nil {
		return nil, err
	}
	if s.caFiles, err = launch.WriteCAFiles(certDir, s.ca.CertPEM(), launch.BaseBundle(certDir)); err != nil {
		return nil, err
	}
	socket := o.socket
	if socket == "" {
		dir, err := audit.StateDir()
		if err != nil {
			return nil, err
		}
		socket = filepath.Join(dir, "control-"+s.id+".sock")
	}
	var phone *approve.Phone
	if s.broker, s.ctl, phone, s.approvals, err = startApprovals(o.warn, eng.Policy, socket, s.logf); err != nil {
		return nil, err
	}
	if s.ctl != nil {
		go func() { _ = s.ctl.Serve(s.broker) }()
	}
	if phone != nil {
		var ctx context.Context
		ctx, s.stopPhone = context.WithCancel(context.Background())
		go phone.Listen(ctx, s.broker)
	}
	return s, nil
}

// listenSpec describes one proxy server and its listeners.
type listenSpec struct {
	via  string // audit and card label
	mode string // "" takes the policy's mode
	// privateTunnels lets tunnels reach private addresses (agent listener).
	privateTunnels bool
	http, socks    string // listen addresses; socks "" means no SOCKS listener
	// agentHosts are the sandboxed agent's backend hosts, tunnelled on 443.
	agentHosts []string
}

// listen starts a proxy server for spec and returns its addresses.
func (s *session) listen(spec listenSpec) (httpAddr, socksAddr string, err error) {
	srv, err := proxy.New(proxy.Config{
		Engine: s.eng, CA: s.ca, Audit: s.audit, Session: s.id, Via: spec.via, Mode: spec.mode,
		PrivateTunnels: spec.privateTunnels, AgentHosts: spec.agentHosts, Secrets: secrets.NewSet(append(append([]*secrets.Secret{}, s.stored...), s.extra...)),
		Approver: s.broker, Logf: s.logf, Upstream: s.upstream,
	})
	if err != nil {
		return "", "", err
	}
	s.servers = append(s.servers, srv)
	hl, err := net.Listen("tcp", spec.http)
	if err != nil {
		return "", "", err
	}
	go func() { s.errc <- srv.ServeHTTPProxy(hl) }()
	if spec.socks == "" {
		return hl.Addr().String(), "", nil
	}
	sl, err := net.Listen("tcp", spec.socks)
	if err != nil {
		return "", "", err
	}
	go func() { s.errc <- srv.ServeSOCKS(sl) }()
	return hl.Addr().String(), sl.Addr().String(), nil
}

// credentials is the number of secrets the session can inject.
func (s *session) credentials() int { return len(s.stored) + len(s.extra) }

func (s *session) Close() {
	for _, srv := range s.servers {
		_ = srv.Close()
	}
	if s.ctl != nil {
		_ = s.ctl.Close()
	}
	if s.stopPhone != nil {
		s.stopPhone()
	}
}
