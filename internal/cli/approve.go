package cli

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/rakeshnitb23/opfence/internal/approve"
	"github.com/rakeshnitb23/opfence/internal/audit"
)

// controlSockets returns the control sockets to talk to: the one given, or
// every session's socket in the state folder that answers.
func controlSockets(override string) ([]string, error) {
	if override != "" {
		c, err := approve.Dial(override)
		if err != nil {
			return nil, err
		}
		c.Close()
		return []string{override}, nil
	}
	dir, err := audit.StateDir()
	if err != nil {
		return nil, err
	}
	matches, _ := filepath.Glob(filepath.Join(dir, "control*.sock"))
	var live []string
	for _, m := range matches {
		if c, err := net.DialTimeout("unix", m, time.Second); err == nil {
			c.Close()
			live = append(live, m)
		}
	}
	if len(live) == 0 {
		return nil, fmt.Errorf("no Opfence proxy is running (no control socket answers in %s)", dir)
	}
	return live, nil
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
			out := cmd.OutOrStdout()
			if len(args) == 0 && !list {
				return interactive(cmd, socket, max)
			}
			paths, err := controlSockets(socket)
			if err != nil {
				return err
			}
			switch {
			case list:
				var views []approve.View
				for _, p := range paths {
					c, err := approve.Dial(p)
					if err != nil {
						continue // the session ended
					}
					vs, err := c.List()
					c.Close()
					if err != nil {
						return err
					}
					views = append(views, vs...)
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
			default:
				if yes == deny {
					return errors.New("say --yes or --deny")
				}
				a := approve.Answer{ID: args[0], Approve: yes, Typed: typed, Scope: scope}
				for _, p := range paths {
					c, err := approve.Dial(p)
					if err != nil {
						continue
					}
					err = c.Answer(a)
					c.Close()
					if errors.Is(err, approve.ErrUnknown) {
						continue
					}
					if err != nil {
						return err
					}
					if yes {
						fmt.Fprintln(out, "approved")
					} else {
						fmt.Fprintln(out, "denied")
					}
					return nil
				}
				return approve.ErrUnknown
			}
		},
	}
	cmd.Flags().StringVar(&socket, "socket", "", "control socket (default: every running session)")
	cmd.Flags().BoolVar(&list, "list", false, "list waiting requests")
	cmd.Flags().BoolVar(&yes, "yes", false, "approve the request ID")
	cmd.Flags().BoolVar(&deny, "deny", false, "deny the request ID")
	cmd.Flags().StringVar(&typed, "typed", "", "the confirmation text, for requests that need it")
	cmd.Flags().DurationVar(&scope, "for", 0, "also approve the same operation on the same resource for this long (at most 1h)")
	cmd.Flags().IntVar(&max, "max", 0, "stop after answering this many requests (0: keep watching)")
	_ = cmd.Flags().MarkHidden("max")
	return cmd
}

// interactive watches every running session (and sessions that start
// later) and asks about each request in turn.
func interactive(cmd *cobra.Command, socket string, max int) error {
	out := cmd.OutOrStdout()
	in := bufio.NewReader(cmd.InOrStdin())
	type item struct {
		v    approve.View
		path string
	}
	queue := make(chan item, 64)
	var mu sync.Mutex
	watching := map[string]bool{}
	watch := func() error {
		paths, err := controlSockets(socket)
		if err != nil {
			return err
		}
		mu.Lock()
		defer mu.Unlock()
		for _, p := range paths {
			if watching[p] {
				continue
			}
			w, err := approve.Dial(p)
			if err != nil {
				continue
			}
			watching[p] = true
			go func(p string) {
				_ = w.Watch(func(v approve.View) bool { queue <- item{v, p}; return true })
				w.Close()
				mu.Lock()
				delete(watching, p)
				mu.Unlock()
			}(p)
		}
		return nil
	}
	if err := watch(); err != nil {
		return err
	}
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		t := time.NewTicker(2 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				_ = watch()
			case <-stop:
				return
			}
		}
	}()
	fmt.Fprintln(out, "Watching for requests that need approval. Ctrl-C to stop.")
	answered := 0
	for it := range queue {
		if time.Now().After(it.v.Expires) {
			continue
		}
		a, err := askInTerminal(out, in, it.v)
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		c, err := approve.Dial(it.path)
		if err == nil {
			err = c.Answer(a)
			c.Close()
		}
		if err != nil {
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
	if n := approve.ViaNote(v.Via); n != "" {
		fmt.Fprintf(out, "  %s\n", n)
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
