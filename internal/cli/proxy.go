package cli

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/rakeshnitb23/opfence/internal/audit"
	"github.com/rakeshnitb23/opfence/internal/ca"
	"github.com/rakeshnitb23/opfence/internal/engine"
	"github.com/rakeshnitb23/opfence/internal/proxy"
)

func newProxyCmd(g *globalOptions) *cobra.Command {
	var httpAddr, socksAddr, mode, auditPath string
	cmd := &cobra.Command{
		Use:   "proxy",
		Short: "Run the enforcing proxy on its own (opfence run will start it for you)",
		Long: `Starts Opfence's HTTP and SOCKS5 proxies on loopback. HTTPS to APIs in the
catalog is intercepted and every request is decided before it leaves the
machine; passthrough hosts are tunnelled; anything else is refused in strict
mode. Requests that need approval are blocked until approvals arrive.

The certificate authority is generated for this run only and its certificate
is written to the state folder; point your client at it, for example
  curl --proxy http://127.0.0.1:PORT --cacert CA_FILE https://...`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			for _, a := range []string{httpAddr, socksAddr} {
				if err := loopbackOnly(a); err != nil {
					return err
				}
			}
			eng, err := g.engine()
			if err != nil {
				return err
			}
			for _, w := range eng.Policy.Warnings {
				fmt.Fprintln(cmd.ErrOrStderr(), "warning:", w)
			}
			if auditPath == "" {
				if auditPath, err = audit.DefaultPath(); err != nil {
					return err
				}
			}
			log, err := audit.Open(auditPath)
			if err != nil {
				return err
			}
			authority, err := newSessionCA(eng)
			if err != nil {
				return err
			}
			caFile := filepath.Join(filepath.Dir(auditPath), "ca.pem")
			if err := os.WriteFile(caFile, authority.CertPEM(), 0o644); err != nil {
				return err
			}
			srv, err := proxy.New(proxy.Config{
				Engine: eng, CA: authority, Audit: log, Session: sessionID(), Mode: mode,
				Logf: func(f string, a ...any) { fmt.Fprintf(cmd.ErrOrStderr(), f+"\n", a...) },
			})
			if err != nil {
				return err
			}
			defer srv.Close()
			hl, err := net.Listen("tcp", httpAddr)
			if err != nil {
				return err
			}
			sl, err := net.Listen("tcp", socksAddr)
			if err != nil {
				hl.Close()
				return err
			}
			errc := make(chan error, 2)
			go func() { errc <- srv.ServeHTTPProxy(hl) }()
			go func() { errc <- srv.ServeSOCKS(sl) }()
			effMode := mode
			if effMode == "" {
				effMode = eng.Policy.Mode
			}
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "Opfence proxy running (%s mode). Press Ctrl-C to stop.\n", effMode)
			fmt.Fprintf(out, "  HTTP proxy:      http://%s\n", hl.Addr())
			fmt.Fprintf(out, "  SOCKS5 proxy:    %s\n", sl.Addr())
			fmt.Fprintf(out, "  CA certificate:  %s (this run only)\n", caFile)
			fmt.Fprintf(out, "  Audit log:       %s\n", auditPath)

			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			select {
			case <-ctx.Done():
				return nil
			case err := <-errc:
				return err
			}
		},
	}
	cmd.Flags().StringVar(&httpAddr, "http", "127.0.0.1:0", "HTTP proxy listen address (loopback only)")
	cmd.Flags().StringVar(&socksAddr, "socks", "127.0.0.1:0", "SOCKS5 proxy listen address (loopback only)")
	cmd.Flags().StringVar(&mode, "mode", "", "strict or open (default from your policy, strict)")
	cmd.Flags().StringVar(&auditPath, "audit", "", "audit log file (default ~/.local/state/opfence/audit.jsonl)")
	return cmd
}

// loopbackOnly refuses listen addresses other machines could reach: the
// proxy acts with the user's authority.
func loopbackOnly(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("listen address %q: %w", addr, err)
	}
	if host == "localhost" {
		return nil
	}
	if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("listen address %q: Opfence only listens on loopback (127.0.0.1 or ::1)", addr)
	}
	return nil
}

// newSessionCA creates a CA constrained to the catalog's hosts.
func newSessionCA(eng *engine.Engine) (*ca.CA, error) {
	var hosts []string
	for _, p := range eng.Catalog.Providers {
		hosts = append(hosts, p.Hosts...)
	}
	machine, _ := os.Hostname()
	return ca.New(machine, ca.PermittedDomains(hosts))
}

func sessionID() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func newLogCmd() *cobra.Command {
	var auditPath string
	var verify, asJSON bool
	var last int
	cmd := &cobra.Command{
		Use:   "log",
		Short: "Show or verify the audit log",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if auditPath == "" {
				p, err := audit.DefaultPath()
				if err != nil {
					return err
				}
				auditPath = p
			}
			data, err := os.ReadFile(auditPath)
			if errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("no audit log at %s yet", auditPath)
			}
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			if verify {
				n, err := audit.Verify(bytes.NewReader(data))
				if err != nil {
					fmt.Fprintf(out, "%s: %v\n", auditPath, err)
					return failError{err.Error()}
				}
				fmt.Fprintf(out, "%s: chain intact, %d entries\n", auditPath, n)
				return nil
			}
			entries, err := audit.Read(bytes.NewReader(data))
			if err != nil {
				return err
			}
			if last > 0 && len(entries) > last {
				entries = entries[len(entries)-last:]
			}
			if asJSON {
				enc := json.NewEncoder(out)
				for _, e := range entries {
					if err := enc.Encode(e); err != nil {
						return err
					}
				}
				return nil
			}
			return printLog(out, entries)
		},
	}
	cmd.Flags().StringVar(&auditPath, "audit", "", "audit log file (default ~/.local/state/opfence/audit.jsonl)")
	cmd.Flags().BoolVar(&verify, "verify", false, "check the hash chain instead of printing")
	cmd.Flags().BoolVar(&asJSON, "json", false, "print entries as JSON lines")
	cmd.Flags().IntVarP(&last, "last", "n", 50, "show only the last N entries (0 for all)")
	return cmd
}

func printLog(w io.Writer, entries []audit.Entry) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "TIME\tOUTCOME\tDECISION\tREQUEST\tWHAT")
	for _, e := range entries {
		target := e.Host
		if e.Port != "" && e.Port != "443" {
			target += ":" + e.Port
		}
		if e.Method != "" {
			target = e.Method + " " + target + e.Path
		}
		what := e.Reason
		if len(e.Operations) > 0 {
			var cards []string
			for _, op := range e.Operations {
				cards = append(cards, op.Card)
			}
			what = strings.Join(cards, "; ")
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", e.Time.Local().Format("2006-01-02 15:04:05"), e.Outcome, e.Decision, target, what)
	}
	return tw.Flush()
}
