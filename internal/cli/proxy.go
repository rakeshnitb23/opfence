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
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/rakeshnitb23/opfence/internal/approve"
	"github.com/rakeshnitb23/opfence/internal/audit"
	"github.com/rakeshnitb23/opfence/internal/engine"
)

func newProxyCmd(g *globalOptions) *cobra.Command {
	var httpAddr, socksAddr, mode, auditPath, controlSocket string
	cmd := &cobra.Command{
		Use:   "proxy",
		Short: "Run the enforcing proxy on its own (opfence run will start it for you)",
		Long: `Starts Opfence's HTTP and SOCKS5 proxies on loopback. HTTPS to APIs in the
catalog is intercepted and every request is decided before it leaves the
machine; passthrough hosts are tunnelled; anything else is refused in strict
mode. Requests that need approval wait for you to answer in a desktop dialog
or with "opfence approve" in another terminal, and are denied if nobody does.

The certificate authority's key is kept in your keychain (or, if the keychain
is unavailable, made for this run only) and its certificate is written to the
state folder; point your client at it, for example
  curl --proxy http://127.0.0.1:PORT --cacert CA_FILE https://...`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			for _, a := range []string{httpAddr, socksAddr} {
				if err := loopbackOnly(a); err != nil {
					return err
				}
			}
			s, err := openSession(g, sessionOptions{auditPath: auditPath, socket: controlSocket, warn: cmd.ErrOrStderr()})
			if err != nil {
				return err
			}
			defer s.Close()
			h, so, err := s.listen(listenSpec{mode: mode, http: httpAddr, socks: socksAddr})
			if err != nil {
				return err
			}
			effMode := mode
			if effMode == "" {
				effMode = s.eng.Policy.Mode
			}
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "Opfence proxy running (%s mode). Press Ctrl-C to stop.\n", effMode)
			fmt.Fprintf(out, "  HTTP proxy:      http://%s\n", h)
			fmt.Fprintf(out, "  SOCKS5 proxy:    %s\n", so)
			lifetime := "this run only"
			if s.persistentCA {
				lifetime = "key kept in your keychain"
			}
			fmt.Fprintf(out, "  CA certificate:  %s (%s)\n", s.caFiles.CA, lifetime)
			fmt.Fprintf(out, "  Credentials:     %d from your keychain\n", s.credentials())
			fmt.Fprintf(out, "  Audit log:       %s\n", s.audit.Path())
			fmt.Fprintf(out, "  Approvals:       %s\n", s.approvals)
			if s.upstream != nil {
				fmt.Fprintf(out, "  Upstream proxy:  %s\n", s.upstream.URL.Redacted())
			}

			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			select {
			case <-ctx.Done():
				return nil
			case err := <-s.errc:
				return err
			}
		},
	}
	cmd.Flags().StringVar(&httpAddr, "http", "127.0.0.1:0", "HTTP proxy listen address (loopback only)")
	cmd.Flags().StringVar(&socksAddr, "socks", "127.0.0.1:0", "SOCKS5 proxy listen address (loopback only)")
	cmd.Flags().StringVar(&mode, "mode", "", "strict or open (default from your policy, strict)")
	cmd.Flags().StringVar(&auditPath, "audit", "", "audit log file (default ~/.local/state/opfence/audit.jsonl)")
	cmd.Flags().StringVar(&controlSocket, "socket", "", "control socket for opfence approve (default: one per session in the state folder)")
	return cmd
}

// startApprovals builds the approval broker from the policy's channels.
func startApprovals(w io.Writer, channels []string, timeout time.Duration, socket string) (*approve.Broker, *approve.Control, string, error) {
	var chans []approve.Channel
	var how []string
	var ctl *approve.Control
	for _, name := range channels {
		switch name {
		case "desktop":
			if d := approve.NewDesktop(); d != nil {
				chans = append(chans, d)
				how = append(how, "desktop dialogs")
			} else {
				fmt.Fprintln(w, "warning: no desktop dialog available (needs osascript, or zenity or kdialog with a display)")
			}
		case "cli":
			var err error
			if ctl, err = approve.ListenControl(socket); err != nil {
				return nil, nil, "", err
			}
			chans = append(chans, ctl)
			how = append(how, "opfence approve in another terminal")
		case "ntfy":
			fmt.Fprintln(w, "warning: the ntfy approval channel is not available yet")
		}
	}
	if len(how) == 0 {
		how = []string{"none; requests that need approval are denied"}
	}
	return approve.NewBroker(timeout, chans...), ctl, strings.Join(how, ", ") + fmt.Sprintf(" (denied after %s)", timeout), nil
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
		outcome := e.Outcome
		if e.Approver != "" {
			outcome += " (" + e.Approver + ")"
		}
		// Hosts, paths and reasons come from requests; terminal escapes in
		// them could hide or forge lines.
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", e.Time.Local().Format("2006-01-02 15:04:05"),
			engine.Sanitize(outcome, 80), engine.Sanitize(e.Decision, 16), engine.Sanitize(target, 600), engine.Sanitize(what, 2000))
	}
	return tw.Flush()
}
