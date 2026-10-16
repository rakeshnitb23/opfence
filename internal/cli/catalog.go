package cli

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/rakeshnitb23/opfence/internal/catalog"
	"github.com/rakeshnitb23/opfence/internal/classes"
)

// globalOptions are flags shared by every command.
type globalOptions struct {
	catalogDir string
}

// loadCatalog returns the catalog from --catalog, or the embedded snapshot.
func (g *globalOptions) loadCatalog() (*catalog.Catalog, error) {
	if g.catalogDir == "" {
		return catalog.Embedded()
	}
	info, err := os.Stat(g.catalogDir)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("--catalog %s is not a folder", g.catalogDir)
	}
	return catalog.Load(os.DirFS(g.catalogDir))
}

func newCatalogCmd(g *globalOptions) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "catalog",
		Short: "Inspect and validate the operation catalog",
	}
	cmd.AddCommand(newCatalogValidateCmd(g), newCatalogListCmd(g), newCatalogProvidersCmd(g))
	return cmd
}

func newCatalogValidateCmd(g *globalOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "validate",
		Short: "Check every catalog file (use --catalog DIR for a checkout)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := g.loadCatalog()
			var ve *catalog.ValidationError
			if errors.As(err, &ve) {
				for _, p := range ve.Problems {
					fmt.Fprintln(cmd.ErrOrStderr(), p.String())
				}
				return failError{fmt.Sprintf("%d problems", len(ve.Problems))}
			}
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "catalog OK: %d providers, %d rules\n", len(c.Providers), len(c.Rules()))
			return nil
		},
	}
}

func newCatalogListCmd(g *globalOptions) *cobra.Command {
	var provider, class string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List catalog rules",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := g.loadCatalog()
			if err != nil {
				return err
			}
			if class != "" {
				if _, err := classes.ParseClass(class); err != nil {
					return err
				}
			}
			if provider != "" && c.Provider(provider) == nil {
				return fmt.Errorf("no provider %q in the catalog", provider)
			}
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "RULE\tCLASS\tSTATUS\tMATCH")
			for _, r := range c.Rules() {
				if provider != "" && r.Provider.ID != provider {
					continue
				}
				if class != "" && !hasClass(r, classes.Class(class)) {
					continue
				}
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", r.ID, classSummary(r), r.Status, describeMatch(r.Match))
			}
			return w.Flush()
		},
	}
	cmd.Flags().StringVar(&provider, "provider", "", "only rules for this provider")
	cmd.Flags().StringVar(&class, "class", "", "only rules that can produce this class")
	return cmd
}

func newCatalogProvidersCmd(g *globalOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "providers",
		Short: "List catalog providers",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := g.loadCatalog()
			if err != nil {
				return err
			}
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "PROVIDER\tTITLE\tRULES\tHOSTS")
			for _, p := range c.Providers {
				hosts := strings.Join(p.Hosts, ", ")
				if p.MCP != nil && hosts == "" {
					hosts = "(local MCP server)"
				}
				fmt.Fprintf(w, "%s\t%s\t%d\t%s\n", p.ID, p.Title, len(p.Rules), hosts)
			}
			return w.Flush()
		},
	}
}

func hasClass(r *catalog.Rule, c classes.Class) bool {
	for _, k := range r.PossibleClasses() {
		if k == c {
			return true
		}
	}
	return false
}

func classSummary(r *catalog.Rule) string {
	cs := r.PossibleClasses()
	if len(cs) == 1 {
		return string(cs[0])
	}
	if r.Classify != nil {
		return string(r.Class) + " (by " + r.Classify.SQL + ")"
	}
	names := make([]string, len(cs))
	for i, c := range cs {
		names[i] = string(c)
	}
	return strings.Join(names, "|")
}

func describeMatch(m catalog.Match) string {
	switch {
	case m.REST != nil:
		return m.REST.Method + " " + m.REST.Path
	case m.GraphQL != nil:
		return "graphql " + m.GraphQL.Type + " " + m.GraphQL.Field
	case m.MCP != nil:
		return "mcp tool " + m.MCP.Tool
	case m.AWS != nil:
		return "aws " + m.AWS.Service + ":" + m.AWS.Action
	case m.CLI != nil:
		return "cli " + m.CLI.Command
	}
	return ""
}
