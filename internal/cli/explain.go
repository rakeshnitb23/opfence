package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/rakeshnitb23/opfence/internal/classes"
	"github.com/rakeshnitb23/opfence/internal/engine"
	"github.com/rakeshnitb23/opfence/internal/fixture"
	"github.com/rakeshnitb23/opfence/internal/policy"
	"github.com/rakeshnitb23/opfence/internal/request"
)

// loadPolicy reads the user config and the repository policy named by the
// flags. The repository file defaults to ./opfence.yaml when it exists.
func (g *globalOptions) loadPolicy() (*policy.Effective, error) {
	userPath := g.userConfig
	if userPath == "" {
		userPath = policy.UserConfigPath()
	}
	var user, repo *policy.File
	var err error
	if userPath != "" {
		if user, err = policy.Load(userPath); err != nil {
			return nil, err
		}
	}
	repoPath := g.policyFile
	explicit := repoPath != ""
	if !explicit {
		repoPath = "opfence.yaml"
	}
	if repo, err = policy.Load(repoPath); err != nil {
		return nil, err
	}
	if repo == nil && explicit {
		return nil, fmt.Errorf("policy file %s not found", repoPath)
	}
	return policy.Resolve(user, repo), nil
}

func (g *globalOptions) engine() (*engine.Engine, error) {
	c, err := g.loadCatalog()
	if err != nil {
		return nil, err
	}
	p, err := g.loadPolicy()
	if err != nil {
		return nil, err
	}
	return engine.New(c, p), nil
}

func newExplainCmd(g *globalOptions) *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "explain <request.http>...",
		Short: "Show how Opfence classifies and decides a saved request",
		Long: `Explain decodes saved HTTP requests (raw HTTP/1.1, as mitmproxy's "Copy as
raw request" produces, or a catalog fixture), matches each operation against
the catalog and shows the decision your policy gives it. Use "-" to read a
request from standard input.`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			eng, err := g.engine()
			if err != nil {
				return err
			}
			for _, w := range eng.Policy.Warnings {
				fmt.Fprintln(cmd.ErrOrStderr(), "warning:", w)
			}
			var results []jsonResult
			for i, name := range args {
				data, err := readInput(cmd.InOrStdin(), name)
				if err != nil {
					return err
				}
				req, _, err := request.ParseFixture(data)
				if err != nil {
					return fmt.Errorf("%s: %w", name, err)
				}
				res := eng.Evaluate(req)
				if asJSON {
					results = append(results, toJSON(name, req, res))
					continue
				}
				if i > 0 {
					fmt.Fprintln(cmd.OutOrStdout())
				}
				printResult(cmd.OutOrStdout(), name, req, res)
			}
			if asJSON {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(results)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "print machine-readable JSON")
	return cmd
}

func readInput(stdin io.Reader, name string) ([]byte, error) {
	if name == "-" {
		return io.ReadAll(io.LimitReader(stdin, 4<<20))
	}
	return os.ReadFile(name)
}

func printResult(w io.Writer, name string, req *request.Request, res engine.Result) {
	fmt.Fprintf(w, "%s\n  %s %s%s\n", name, req.Method, req.Host, req.Path)
	if res.UnknownHost() {
		fmt.Fprintf(w, "  host        not in the catalog (the runner refuses it in strict mode)\n")
	}
	for _, ev := range res.Evaluations {
		fmt.Fprintf(w, "  operation   %s\n", describeOp(ev))
		if ev.Rule != nil {
			fmt.Fprintf(w, "  rule        %s (%s)\n", ev.Rule.ID, ev.Rule.Status)
		}
		classNames := make([]string, len(ev.Classes))
		for i, c := range ev.Classes {
			classNames[i] = string(c)
		}
		fmt.Fprintf(w, "  class       %s (%s)\n", strings.Join(classNames, ", "), ev.ClassSource)
		fmt.Fprintf(w, "  environment %s (%s)\n", ev.Environment, ev.EnvSource)
		fmt.Fprintf(w, "  decision    %s (%s)\n", strings.ToUpper(ev.Decision.String()), ev.DecisionSource)
		fmt.Fprintf(w, "  card        %s\n", ev.Card)
	}
	if len(res.Evaluations) > 1 {
		fmt.Fprintf(w, "  request     %s (strictest of %d operations)\n", strings.ToUpper(res.Decision.String()), len(res.Evaluations))
	}
}

func describeOp(ev engine.Evaluation) string {
	op := ev.Op
	var s string
	switch {
	case op.Field != "":
		s = "graphql " + op.GraphQLType + " " + op.Field
	case op.Tool != "":
		s = "mcp tool " + op.Tool
	case op.MCPMethod != "":
		s = "mcp " + op.MCPMethod
	case op.Action != "":
		s = "aws " + op.Service + ":" + op.Action
	case op.Protocol == "aws":
		s = "aws " + op.Service + " " + op.Method + " " + op.Path
	default:
		s = op.Method + " " + op.Path
	}
	if op.Error != "" {
		s += " (could not decode: " + op.Error + ")"
	}
	return engine.Sanitize(s, 200)
}

type jsonEval struct {
	Operation      string   `json:"operation"`
	Rule           string   `json:"rule,omitempty"`
	Classes        []string `json:"classes"`
	ClassSource    string   `json:"class_source"`
	Environment    string   `json:"environment"`
	EnvSource      string   `json:"environment_source"`
	Decision       string   `json:"decision"`
	DecisionSource string   `json:"decision_source"`
	Resource       string   `json:"resource,omitempty"`
	Card           string   `json:"card"`
}

type jsonResult struct {
	File        string     `json:"file"`
	Method      string     `json:"method"`
	Host        string     `json:"host"`
	Path        string     `json:"path"`
	Provider    string     `json:"provider,omitempty"`
	Decision    string     `json:"decision"`
	Hash        string     `json:"hash"`
	Evaluations []jsonEval `json:"operations"`
}

func toJSON(name string, req *request.Request, res engine.Result) jsonResult {
	out := jsonResult{File: name, Method: req.Method, Host: req.Host, Path: req.Path, Decision: res.Decision.String(), Hash: fmt.Sprintf("%x", res.Hash)}
	if res.Provider != nil {
		out.Provider = res.Provider.ID
	}
	for _, ev := range res.Evaluations {
		je := jsonEval{Operation: describeOp(ev), ClassSource: ev.ClassSource, Environment: ev.Environment, EnvSource: ev.EnvSource,
			Decision: ev.Decision.String(), DecisionSource: ev.DecisionSource, Resource: ev.Resource, Card: ev.Card}
		if ev.Rule != nil {
			je.Rule = ev.Rule.ID
		}
		for _, c := range ev.Classes {
			je.Classes = append(je.Classes, string(c))
		}
		out.Evaluations = append(out.Evaluations, je)
	}
	return out
}

func newTestCmd(g *globalOptions) *cobra.Command {
	var verbose bool
	cmd := &cobra.Command{
		Use:   "test",
		Short: "Replay every catalog fixture and fail if any rule misses",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := g.loadCatalog()
			if err != nil {
				return err
			}
			rep := fixture.Run(c)
			for _, o := range rep.Outcomes {
				switch {
				case !o.Pass:
					fmt.Fprintf(cmd.OutOrStdout(), "FAIL  %s  %s: %s\n", o.Rule.ID, o.Fixture, o.Problem)
				case verbose:
					fmt.Fprintf(cmd.OutOrStdout(), "ok    %s  %s\n", o.Rule.ID, o.Fixture)
				}
			}
			untested := 0
			for _, r := range c.Rules() {
				if len(r.Tests) == 0 && r.Match.CLI == nil {
					untested++
				}
			}
			fmt.Fprintf(cmd.OutOrStdout(), "%d fixtures, %d failed; %d rules without fixtures\n", len(rep.Outcomes), rep.Failed, untested)
			if rep.Failed > 0 {
				return failError{fmt.Sprintf("%d fixtures failed", rep.Failed)}
			}
			return nil
		},
	}
	cmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "list passing fixtures too")
	return cmd
}

func newPolicyCmd(g *globalOptions) *cobra.Command {
	cmd := &cobra.Command{Use: "policy", Short: "Check policy files"}
	cmd.AddCommand(&cobra.Command{
		Use:   "check",
		Short: "Validate opfence.yaml and your user config, and show the effective defaults",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			eff, err := g.loadPolicy()
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			for _, w := range eff.Warnings {
				fmt.Fprintln(out, "warning:", w)
			}
			fmt.Fprintf(out, "default environment: %s\nmode: %s\napproval timeout: %s\n\n", eff.DefaultEnvironment, eff.Mode, eff.ApprovalTimeout)
			fmt.Fprintf(out, "%-14s %-12s %-12s %-12s\n", "CLASS", policy.Development, policy.Staging, policy.Production)
			for _, c := range classes.All {
				row := []string{}
				for _, env := range []string{policy.Development, policy.Staging, policy.Production} {
					d, _ := eff.Decide("", c, env)
					row = append(row, d.String())
				}
				fmt.Fprintf(out, "%-14s %-12s %-12s %-12s\n", c, row[0], row[1], row[2])
			}
			return nil
		},
	})
	return cmd
}
