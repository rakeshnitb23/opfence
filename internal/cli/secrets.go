package cli

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/rakeshnitb23/opfence/internal/ca"
	"github.com/rakeshnitb23/opfence/internal/engine"
	"github.com/rakeshnitb23/opfence/internal/secrets"
)

// openStore returns the secret store; tests replace it.
var openStore = func() secrets.Store { return secrets.Keychain{} }

func newInitCmd(g *globalOptions) *cobra.Command {
	var dir string
	var yes, undo bool
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Move API keys from .env and MCP config files into your keychain",
		Long: `Init finds credentials for APIs in the catalog in .env files and in MCP and
Claude Code config files (.mcp.json, .cursor/mcp.json, .vscode/mcp.json,
.claude/settings*.json), stores the real values in your OS keychain, and
writes placeholders of the same length and shape in their place. Agents then
only ever see placeholders; the Opfence proxy swaps the real key back in for
requests to that key's own API.

Every value is stored and read back from the keychain before any file is
changed. "opfence init --undo" writes the real values back.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := g.loadCatalog()
			if err != nil {
				return err
			}
			root, err := filepath.Abs(dir)
			if err != nil {
				return err
			}
			vault := &secrets.Vault{Store: openStore()}
			existing, err := vault.List()
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			if undo {
				changed, err := secrets.Undo(existing)
				for _, f := range changed {
					fmt.Fprintf(out, "restored real values in %s\n", rel(root, f))
				}
				if err == nil && len(changed) == 0 {
					fmt.Fprintln(out, "No placeholders to restore.")
				}
				return err
			}
			findings, err := secrets.Discover(root, c, secrets.NewSet(existing))
			if err != nil {
				return err
			}
			moves, protected := 0, 0
			tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
			for _, f := range findings {
				loc := rel(root, f.File)
				if f.Line > 0 {
					loc = fmt.Sprintf("%s:%d", loc, f.Line)
				}
				switch {
				case f.Skip == "":
					moves++
					fmt.Fprintf(tw, "  move\t%s\t%s\t%s\n", loc, f.Where, f.Provider)
				case strings.HasPrefix(f.Skip, "already"):
					protected++
				default:
					fmt.Fprintf(tw, "  skip\t%s\t%s\t%s\n", loc, f.Where, f.Skip)
				}
			}
			_ = tw.Flush()
			if protected > 0 {
				fmt.Fprintf(out, "%d already protected by Opfence.\n", protected)
			}
			if moves == 0 {
				fmt.Fprintln(out, "Nothing to move.")
				return nil
			}
			if !yes {
				ok, asked := confirm(cmd, fmt.Sprintf("Move %d credential(s) into your keychain and write placeholders? [y/N] ", moves))
				if !asked {
					fmt.Fprintln(out, "Run again with --yes to move them.")
					return nil
				}
				if !ok {
					fmt.Fprintln(out, "Nothing changed.")
					return nil
				}
			}
			changed, err := secrets.Apply(findings, c, vault)
			for _, f := range changed {
				fmt.Fprintf(out, "wrote placeholders to %s\n", rel(root, f))
			}
			if err != nil {
				return err
			}
			fmt.Fprintln(out, "Done. Agents now see placeholders, and only requests through the Opfence proxy get the real keys:")
			fmt.Fprintln(out, "  opfence run -- claude          Claude Code and its MCP servers")
			fmt.Fprintln(out, "  opfence run --weak -- COMMAND  your own tools, such as a dev server")
			fmt.Fprintln(out, "MCP servers must honour HTTPS_PROXY (Node 22.21 or later, most Python and Go clients).")
			fmt.Fprintln(out, "opfence init --undo puts the real values back.")
			return nil
		},
	}
	cmd.Flags().StringVar(&dir, "dir", ".", "repository to scan")
	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "move without asking")
	cmd.Flags().BoolVar(&undo, "undo", false, "write the real values back over the placeholders")
	return cmd
}

// confirm asks on a terminal; asked is false when stdin is not one.
func confirm(cmd *cobra.Command, prompt string) (ok, asked bool) {
	f, isFile := cmd.InOrStdin().(*os.File)
	if !isFile {
		return false, false
	}
	if info, err := f.Stat(); err != nil || info.Mode()&os.ModeCharDevice == 0 {
		return false, false
	}
	fmt.Fprint(cmd.OutOrStdout(), prompt)
	line, _ := bufio.NewReader(f).ReadString('\n')
	a := strings.ToLower(strings.TrimSpace(line))
	return a == "y" || a == "yes", true
}

func rel(root, path string) string {
	if r, err := filepath.Rel(root, path); err == nil && !strings.HasPrefix(r, "..") {
		return filepath.ToSlash(r)
	}
	return path
}

func newSecretsCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "secrets", Short: "List or remove the credentials Opfence holds"}
	cmd.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List credentials (never their values)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			list, err := (&secrets.Vault{Store: openStore()}).List()
			if err != nil {
				return err
			}
			if len(list) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "No credentials yet; run opfence init.")
				return nil
			}
			tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "SECRET\tPLACEHOLDER\tFOUND IN")
			for _, s := range list {
				fmt.Fprintf(tw, "%s/%s\t%s\t%s\n", s.Provider, s.Name, s.Placeholder, strings.Join(s.Sources, ", "))
			}
			return tw.Flush()
		},
	})
	var force bool
	rm := &cobra.Command{
		Use:   "rm PROVIDER/NAME",
		Short: "Remove a credential from the keychain",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			provider, name, ok := strings.Cut(args[0], "/")
			if !ok {
				return errors.New("name the secret as PROVIDER/NAME, as opfence secrets list shows it")
			}
			v := &secrets.Vault{Store: openStore()}
			list, err := v.List()
			if err != nil {
				return err
			}
			for _, s := range list {
				if s.Provider != provider || s.Name != name || force {
					continue
				}
				for _, f := range s.Sources {
					if data, err := os.ReadFile(f); err == nil && bytes.Contains(data, []byte(s.Placeholder)) {
						return fmt.Errorf("%s still holds this secret's placeholder; run opfence init --undo first, or use --force", f)
					}
				}
			}
			if err := v.Remove(provider, name); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "removed %s/%s\n", provider, name)
			return nil
		},
	}
	rm.Flags().BoolVar(&force, "force", false, "remove even if files still hold the placeholder")
	cmd.AddCommand(rm)
	return cmd
}

// loadSecrets returns the secrets for the proxy, or an empty set and a
// warning when the keychain cannot be read.
func loadSecrets(w io.Writer) (*secrets.Set, *secrets.Vault) {
	v := &secrets.Vault{Store: openStore()}
	list, err := v.List()
	if err != nil {
		fmt.Fprintf(w, "warning: running without credential injection: %v\n", err)
		return secrets.NewSet(nil), nil
	}
	return secrets.NewSet(list), v
}

// loadCA returns the keychain's CA when it covers every catalog host,
// otherwise a new one, stored when the keychain is available.
func loadCA(w io.Writer, eng *engine.Engine, v *secrets.Vault) (authority *ca.CA, persistent bool, err error) {
	var hosts []string
	for _, p := range eng.Catalog.Providers {
		hosts = append(hosts, p.Hosts...)
	}
	permitted := ca.PermittedDomains(hosts)
	if v != nil {
		certPEM, keyPEM, err := v.CA()
		switch {
		case err == nil:
			if c, lerr := ca.Load(certPEM, keyPEM); lerr == nil && covers(c, permitted) {
				return c, true, nil
			}
			fmt.Fprintln(w, "warning: the stored Opfence CA does not cover every API in the catalog; making a new one (trust it again with opfence trust)")
		case !errors.Is(err, secrets.ErrNotFound):
			fmt.Fprintf(w, "warning: using a CA for this run only: %v\n", err)
			v = nil
		}
	}
	machine, _ := os.Hostname()
	authority, err = ca.New(machine, permitted)
	if err != nil || v == nil {
		return authority, false, err
	}
	keyPEM, err := authority.KeyPEM()
	if err != nil {
		return nil, false, err
	}
	if err := v.SetCA(authority.CertPEM(), keyPEM); err != nil {
		fmt.Fprintf(w, "warning: using a CA for this run only: %v\n", err)
		return authority, false, nil
	}
	return authority, true, nil
}

func covers(c *ca.CA, permitted []string) bool {
	for _, d := range permitted {
		if !c.Permits(d) {
			return false
		}
	}
	return true
}
