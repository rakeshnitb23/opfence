package cli

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/rakeshnitb23/opfence/internal/approve"
	"github.com/rakeshnitb23/opfence/internal/audit"
)

// controlPath is the control socket in the state folder.
func controlPath(override string) (string, error) {
	if override != "" {
		return override, nil
	}
	dir, err := audit.StateDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "control.sock"), nil
}

func newApproveCmd() *cobra.Command {
	var socket, typed string
	var list, yes, deny bool
	var scope time.Duration
	var max int
	cmd := &cobra.Command{
		Use:   "approve [ID]",
		Short: "Answer requests the proxy is holding for approval",
		Long: `With no arguments, approve watches the running proxy and asks you about each
request that needs approval, in this terminal (not the agent's). Requests
that need confirmation ask you to type the resource's name.

  opfence approve --list               show waiting requests
  opfence approve ID --yes             approve one
  opfence approve ID --yes --typed X   approve one that needs confirmation
  opfence approve ID --yes --for 10m   also approve the same operation on the
                                       same resource for 10 minutes
  opfence approve ID --deny            deny one`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path, err := controlPath(socket)
			if err != nil {
				return err
			}
			c, err := approve.Dial(path)
			if err != nil {
				return err
			}
			defer c.Close()
			out := cmd.OutOrStdout()
			switch {
			case list:
				views, err := c.List()
				if err != nil {
					return err
				}
				if len(views) == 0 {
					fmt.Fprintln(out, "Nothing is waiting for approval.")
					return nil
				}
				tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
				fmt.Fprintln(tw, "ID\tDECISION\tWHAT\tWHERE\tEXPIRES")
				for _, v := range views {
					fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", v.ID, v.Decision, strings.Join(v.Cards, "; "), v.Environment+" "+v.Host, time.Until(v.Expires).Round(time.Second))
				}
				return tw.Flush()
			case len(args) == 1:
				if yes == deny {
					return errors.New("say --yes or --deny")
				}
				if err := c.Answer(approve.Answer{ID: args[0], Approve: yes, Typed: typed, Scope: scope}); err != nil {
					return err
				}
				if yes {
					fmt.Fprintln(out, "approved")
				} else {
					fmt.Fprintln(out, "denied")
				}
				return nil
			}
			return interactive(cmd, path, c, max)
		},
	}
	cmd.Flags().StringVar(&socket, "socket", "", "control socket (default in the state folder)")
	cmd.Flags().BoolVar(&list, "list", false, "list waiting requests")
	cmd.Flags().BoolVar(&yes, "yes", false, "approve the request ID")
	cmd.Flags().BoolVar(&deny, "deny", false, "deny the request ID")
	cmd.Flags().StringVar(&typed, "typed", "", "the confirmation text, for requests that need it")
	cmd.Flags().DurationVar(&scope, "for", 0, "also approve the same operation on the same resource for this long (at most 1h)")
	cmd.Flags().IntVar(&max, "max", 0, "stop after answering this many requests (0: keep watching)")
	_ = cmd.Flags().MarkHidden("max")
	return cmd
}

// interactive watches for requests and asks about each in turn.
func interactive(cmd *cobra.Command, path string, answers *approve.Client, max int) error {
	watcher, err := approve.Dial(path)
	if err != nil {
		return err
	}
	defer watcher.Close()
	out := cmd.OutOrStdout()
	in := bufio.NewReader(cmd.InOrStdin())
	queue := make(chan approve.View, 64)
	go func() {
		_ = watcher.Watch(func(v approve.View) bool { queue <- v; return true })
		close(queue)
	}()
	fmt.Fprintln(out, "Watching for requests that need approval. Ctrl-C to stop.")
	answered := 0
	for v := range queue {
		if time.Now().After(v.Expires) {
			continue
		}
		a, err := askInTerminal(out, in, v)
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		if err := answers.Answer(a); err != nil {
			fmt.Fprintf(out, "  not applied: %v\n", err)
			continue
		}
		answered++
		if max > 0 && answered >= max {
			return nil
		}
	}
	return nil
}

func askInTerminal(out io.Writer, in *bufio.Reader, v approve.View) (approve.Answer, error) {
	fmt.Fprintf(out, "\n%s request %s (%s %s%s, %s)\n", strings.ToUpper(v.Decision), v.Hash, v.Method, v.Host, v.Path, v.Environment)
	for _, c := range v.Cards {
		fmt.Fprintf(out, "  %s\n", c)
	}
	a := approve.Answer{ID: v.ID}
	if v.ConfirmText != "" {
		fmt.Fprintf(out, "Type %s to confirm, or press Enter to deny: ", v.ConfirmText)
		line, err := in.ReadString('\n')
		if err != nil && line == "" {
			return a, err
		}
		a.Typed = strings.TrimSpace(line)
		a.Approve = a.Typed != ""
		return a, nil
	}
	prompt := "Approve? [y]es, [N]o"
	if v.Scopable {
		prompt += ", [t]en minutes for this operation on this resource"
	}
	fmt.Fprint(out, prompt+": ")
	line, err := in.ReadString('\n')
	if err != nil && line == "" {
		return a, err
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		a.Approve = true
	case "t":
		if v.Scopable {
			a.Approve, a.Scope = true, approve.ScopeOffer
		}
	}
	return a, nil
}
