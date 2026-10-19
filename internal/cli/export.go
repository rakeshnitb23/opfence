package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/rakeshnitb23/opfence/internal/engine"
	"github.com/rakeshnitb23/opfence/internal/export"
	"github.com/rakeshnitb23/opfence/internal/hook"
	"github.com/rakeshnitb23/opfence/internal/policy"
)

func newExportCmd(g *globalOptions) *cobra.Command {
	var target, env, output, hookCmd string
	cmd := &cobra.Command{
		Use:   "export --target openshell|claude-code|mcp-annotations",
		Short: "Compile the catalog and your policy into another tool's configuration",
		Long: `Export writes configuration for other engines from the catalog and your
policy:

  openshell        OpenShell network policies (one per provider) for one
                   environment, --environment (default production)
  claude-code      a Claude Code settings fragment: the PreToolUse hook that
                   decides MCP tool calls, plus deny and ask rules for tools
                   that are gated whatever their arguments
  mcp-annotations  MCP tool annotations (readOnlyHint, destructiveHint) for
                   every MCP tool in the catalog

Exports cannot see a call's arguments, so wherever the answer depends on them
they write the stricter outcome.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := g.loadCatalog()
			if err != nil {
				return err
			}
			p, err := g.loadPolicy()
			if err != nil {
				return err
			}
			for _, w := range p.Warnings {
				fmt.Fprintln(cmd.ErrOrStderr(), "warning:", w)
			}
			var out []byte
			switch target {
			case "openshell":
				if !validEnv(env) {
					return fmt.Errorf("--environment must be development, staging or production")
				}
				out, err = export.OpenShell(c, p, env)
			case "claude-code":
				out, err = export.ClaudeCode(c, p, export.ClaudeCodeOptions{HookCommand: hookCmd})
			case "mcp-annotations":
				out, err = export.MCPAnnotations(c, p)
			case "":
				return fmt.Errorf("--target is required (openshell, claude-code or mcp-annotations)")
			default:
				return fmt.Errorf("unknown target %q (want openshell, claude-code or mcp-annotations)", target)
			}
			if err != nil {
				return err
			}
			if output == "" || output == "-" {
				_, err = cmd.OutOrStdout().Write(out)
				return err
			}
			return os.WriteFile(output, out, 0o644)
		},
	}
	cmd.Flags().StringVar(&target, "target", "", "openshell, claude-code or mcp-annotations")
	cmd.Flags().StringVar(&env, "environment", policy.Production, "environment whose decisions an OpenShell export uses")
	cmd.Flags().StringVarP(&output, "output", "o", "", "write to this file instead of standard output")
	cmd.Flags().StringVar(&hookCmd, "hook-command", "", `command Claude Code runs for the hook (default "opfence hook claude-code")`)
	return cmd
}

func validEnv(e string) bool {
	for _, x := range policy.Environments {
		if e == x {
			return true
		}
	}
	return false
}

func newHookCmd(g *globalOptions) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "hook",
		Short: "Agent hooks that decide tool calls (run by the agent, not by you)",
	}
	cmd.AddCommand(&cobra.Command{
		Use:   "claude-code",
		Short: "Claude Code PreToolUse hook for MCP tool calls",
		Long: `Reads a Claude Code PreToolUse event on standard input and, for MCP servers in
the catalog, prints Claude Code's allow, ask or deny decision. Other tools get
no output. Any error exits with status 2, which makes Claude Code block the
call rather than let it through. Install it with
"opfence export --target claude-code".`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := hook.ClaudeCode(cmd.InOrStdin(), cmd.OutOrStdout(), g.hookEngine); err != nil {
				return hookError{err}
			}
			return nil
		},
	})
	cmd.AddCommand(&cobra.Command{
		Use:   "codex",
		Short: "Codex PreToolUse and PermissionRequest hook for MCP tool calls",
		Long: `Reads a Codex PreToolUse or PermissionRequest event on standard input and, for
MCP servers in the catalog, prints Codex's decision: a deny where Opfence
denies, an approval where Opfence allows, and nothing where Opfence asks, so
Codex prompts (a deny when Codex is set never to prompt). Any error exits with
status 2, which Codex takes as a deny. "opfence run --srt -- codex" installs it.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := hook.Codex(cmd.InOrStdin(), cmd.OutOrStdout(), g.hookEngine); err != nil {
				return hookError{err}
			}
			return nil
		},
	})
	return cmd
}

// hookEngine builds the engine for a hook call made in project folder cwd.
func (g *globalOptions) hookEngine(cwd string) (*engine.Engine, error) {
	c, err := g.loadCatalog()
	if err != nil {
		return nil, err
	}
	gg := *g
	if gg.policyFile == "" && cwd != "" {
		// The repository policy belongs to the project the agent runs in,
		// not to wherever the hook process starts.
		if _, statErr := os.Stat(filepath.Join(cwd, "opfence.yaml")); statErr == nil {
			gg.policyFile = filepath.Join(cwd, "opfence.yaml")
		}
	}
	p, err := gg.loadPolicy()
	if err != nil {
		return nil, err
	}
	return engine.New(c, p), nil
}

// hookError makes Main exit 2 (Claude Code's "block") with the reason on
// stderr.
type hookError struct{ err error }

func (e hookError) Error() string { return e.err.Error() }
