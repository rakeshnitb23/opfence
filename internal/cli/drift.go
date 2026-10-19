package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/rakeshnitb23/opfence/internal/drift"
)

func newCatalogCheckSourcesCmd(g *globalOptions) *cobra.Command {
	var providers []string
	var verbose bool
	cmd := &cobra.Command{
		Use:   "check-sources",
		Short: "Compare rules with the providers' published schemas (needs network)",
		Long: `Check-sources downloads the schemas each provider lists under "schemas" and
compares them with its rules. A rule whose operation is no longer in the
schema is stale. An operation that is not a read and that no rule matches is
uncovered; it fails the check unless the schema is marked coverage: partial.
OpenAPI operations whose own servers are on hosts the provider does not list
are skipped. Rules marked "unlisted" are skipped, and reported once the schema
has them.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := g.loadCatalog()
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			reports := drift.Check(cmd.Context(), c, drift.HTTPFetcher(), providers)
			if len(reports) == 0 {
				return fmt.Errorf("no provider to check: none of them lists schemas")
			}
			failed, stale, uncovered := 0, 0, 0
			for _, r := range reports {
				status := "ok"
				if r.Failed() {
					status, failed = "FAIL", failed+1
				}
				if r.Err != nil {
					fmt.Fprintf(out, "%-4s %s: %v\n", status, r.Provider.ID, r.Err)
					continue
				}
				partial := 0
				for _, f := range r.Uncovered {
					if f.Partial {
						partial++
					}
				}
				fmt.Fprintf(out, "%-4s %s: %d rules compared with %d operations in %d schemas; %d stale, %d uncovered",
					status, r.Provider.ID, r.Compared, r.Ops, r.Schemas, len(r.Stale), len(r.Uncovered)-partial)
				if partial > 0 {
					fmt.Fprintf(out, " (%d more not covered by design)", partial)
				}
				if r.Foreign > 0 {
					fmt.Fprintf(out, "; %d served on other hosts skipped", r.Foreign)
				}
				fmt.Fprintln(out)
				for _, f := range r.Stale {
					stale++
					fmt.Fprintf(out, "       stale      %s: %s\n", f.Rule.ID, f.Note)
				}
				for _, f := range r.Uncovered {
					if f.Partial && !verbose {
						continue
					}
					if !f.Partial {
						uncovered++
					}
					if f.Note != "" {
						fmt.Fprintf(out, "       uncovered  %s (%s)\n", f.Op, f.Note)
					} else {
						fmt.Fprintf(out, "       uncovered  %s\n", f.Op)
					}
				}
				for _, f := range r.Listed {
					fmt.Fprintf(out, "       listed     %s is marked unlisted, but %s\n", f.Rule.ID, f.Note)
				}
			}
			if failed > 0 {
				return failError{fmt.Sprintf("%d of %d providers drifted: %d stale rules, %d uncovered operations", failed, len(reports), stale, uncovered)}
			}
			return nil
		},
	}
	cmd.Flags().StringSliceVar(&providers, "provider", nil, "check only these providers")
	cmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "also list uncovered operations of partial schemas")
	return cmd
}
