package cli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"rsc.io/qr"

	"github.com/rakeshnitb23/opfence/internal/approve"
	"github.com/rakeshnitb23/opfence/internal/secrets"
)

func newPhoneCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "phone",
		Short: "Approve requests from your phone with the ntfy app",
		Long: `Phone approvals send each request that needs approval to the ntfy app
(https://ntfy.sh, free, Android, iOS and web) as a push with Approve and Deny
buttons. Requests that need confirming can only be denied from the phone:
confirming means typing the resource's name, which a push cannot take.

With no subcommand, phone says whether phone approvals are set up.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := approve.LoadPhone(openStore())
			if errors.Is(err, secrets.ErrNotFound) {
				fmt.Fprintln(cmd.OutOrStdout(), "Phone approvals are not set up. Run opfence phone setup.")
				return nil
			}
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Phone approvals are set up, through %s.\nSubscribe another phone with %s\n(never on the computer the agent runs on: it could read the topic there)\n", cfg.Server, cfg.SubscribeURL())
			return nil
		},
	}
	cmd.AddCommand(newPhoneSetupCmd(), newPhoneTestCmd(), newPhoneOffCmd())
	return cmd
}

func newPhoneSetupCmd() *cobra.Command {
	var server string
	var tokenStdin, buttonTokenStdin, noTest, newTopics bool
	cmd := &cobra.Command{
		Use:   "setup",
		Short: "Set up phone approvals and check that they work",
		Long: `Setup makes two random topics on an ntfy server: one your phone subscribes
to, and one its buttons answer on, which only Opfence reads. They are kept in
your OS keychain, never in a file an agent can read: anyone who knows the
first topic could answer requests. Setup then shows a QR code to subscribe
with, sends a test push and waits for you to tap its button.

Running setup again keeps the same topics (so your phone stays subscribed)
unless the server changes or --new-topics is given.

A self-hosted ntfy server that needs a login takes an access token
(ntfy token add), read from standard input with --token-stdin. The buttons
need a token to answer, and a push carries the token its buttons use, so
give the buttons their own with --button-token-stdin (read on the next
line): a token of a user that may only write the reply topic
(ntfy access <user> <reply topic> write-only). Without one the buttons use
the access token, which then travels in every push.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			out := cmd.OutOrStdout()
			store := openStore()
			cfg := approve.PhoneConfig{Server: strings.TrimSuffix(server, "/")}
			old, err := approve.LoadPhone(store)
			switch {
			case err == nil && old.Server == cfg.Server && !newTopics:
				cfg = old
			case err != nil && !errors.Is(err, secrets.ErrNotFound):
				return err
			}
			if cfg.Topic == "" {
				cfg.Topic, cfg.Reply = approve.NewTopic(), approve.NewTopic()
			}
			in := bufio.NewReader(cmd.InOrStdin())
			readLine := func() (string, error) {
				line, err := in.ReadString('\n')
				if err != nil && err != io.EOF {
					return "", err
				}
				return strings.TrimSpace(line), nil
			}
			if tokenStdin {
				if cfg.Token, err = readLine(); err != nil {
					return err
				}
			}
			if buttonTokenStdin {
				if cfg.ButtonToken, err = readLine(); err != nil {
					return err
				}
			}
			if err := approve.SavePhone(store, cfg); err != nil {
				return err
			}
			if _, err := approve.LoadPhone(store); err != nil {
				return fmt.Errorf("reading the settings back from the keychain: %w", err)
			}
			link := cfg.SubscribeURL()
			fmt.Fprintln(out, "Install the ntfy app on your phone, then subscribe to your Opfence topic.")
			fmt.Fprintln(out, "\nAndroid: scan this code, or open the link on your phone:")
			if err := printQR(out, link); err != nil {
				return err
			}
			fmt.Fprintf(out, "%s\n\niPhone or another device: in the ntfy app, add a subscription to the topic\n  %s\n", link, cfg.Topic)
			if cfg.Server != "https://ntfy.sh" {
				fmt.Fprintf(out, "on the server %s (\"use another server\").\n", cfg.Server)
			}
			fmt.Fprintln(out, "\nKeep the topic to yourself: anyone who knows it can answer requests. Subscribe on your phone only,\nnot in a browser or ntfy client on the computer the agent runs on, where it could read the topic.")
			if noTest {
				fmt.Fprintln(out, "\nSaved. Check it with opfence phone test.")
				return nil
			}
			return phoneTest(cmd, cfg)
		},
	}
	cmd.Flags().StringVar(&server, "server", "https://ntfy.sh", "ntfy server")
	cmd.Flags().BoolVar(&tokenStdin, "token-stdin", false, "read an ntfy access token from standard input")
	cmd.Flags().BoolVar(&buttonTokenStdin, "button-token-stdin", false, "read a token for the buttons, which may only write the reply topic, from the next line of standard input")
	cmd.Flags().BoolVar(&noTest, "no-test", false, "save without sending a test push")
	cmd.Flags().BoolVar(&newTopics, "new-topics", false, "make new topics (unsubscribes every device)")
	return cmd
}

func newPhoneTestCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "test",
		Short: "Send a test push and wait for its button to be tapped",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := approve.LoadPhone(openStore())
			if errors.Is(err, secrets.ErrNotFound) {
				return errors.New("phone approvals are not set up; run opfence phone setup")
			}
			if err != nil {
				return err
			}
			return phoneTest(cmd, cfg)
		},
	}
}

// phoneTestWait is how long phone test waits for the tap.
var phoneTestWait = 3 * time.Minute

func phoneTest(cmd *cobra.Command, cfg approve.PhoneConfig) error {
	out := cmd.OutOrStdout()
	fmt.Fprintln(out, "\nSent a test push. Tap \"It works\" on your phone (Ctrl-C to stop)...")
	ctx, stop := signal.NotifyContext(cmd.Context(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, phoneTestWait)
	defer cancel()
	if err := approve.NewPhone(cfg, nil).Test(ctx); err != nil {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			return errors.New("no answer from your phone; check that it is subscribed to the topic, then run opfence phone test")
		}
		return fmt.Errorf("phone test: %w", err)
	}
	fmt.Fprintln(out, "Your phone's answer reached Opfence. Phone approvals are on for every opfence run\n(unless your config's approvals.channels leaves out ntfy).")
	return nil
}

func newPhoneOffCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "off",
		Short: "Turn phone approvals off and forget the topics",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			err := approve.DeletePhone(openStore())
			if err != nil && !errors.Is(err, secrets.ErrNotFound) {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), "Phone approvals are off. You can remove the subscription from the ntfy app.")
			return nil
		},
	}
}

// printQR draws a QR code with half-height blocks, light modules as
// blocks, which suits terminals with dark backgrounds; phone cameras read
// the inverted code on light ones too.
func printQR(w io.Writer, text string) error {
	c, err := qr.Encode(text, qr.M)
	if err != nil {
		return err
	}
	const quiet = 2
	dark := func(x, y int) bool {
		if x < 0 || y < 0 || x >= c.Size || y >= c.Size {
			return false
		}
		return c.Black(x, y)
	}
	var b strings.Builder
	for y := -quiet; y < c.Size+quiet; y += 2 {
		for x := -quiet; x < c.Size+quiet; x++ {
			top, bottom := !dark(x, y), !dark(x, y+1)
			switch {
			case top && bottom:
				b.WriteString("█")
			case top:
				b.WriteString("▀")
			case bottom:
				b.WriteString("▄")
			default:
				b.WriteString(" ")
			}
		}
		b.WriteString("\n")
	}
	_, err = io.WriteString(w, b.String())
	return err
}
