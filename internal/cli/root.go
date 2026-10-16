// Package cli wires the opfence command line to the internal packages.
package cli

import (
	"errors"
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/rakeshnitb23/opfence/internal/version"
)

// Exit codes. Commands that check something (test, validate) use exitFail
// when the check finds problems, so scripts can tell that apart from a usage
// or runtime error.
const (
	exitOK    = 0
	exitFail  = 1
	exitError = 2
)

// failError marks a check that ran and found problems; it has already been
// reported to the user.
type failError struct{ msg string }

func (e failError) Error() string { return e.msg }

// Main runs the CLI and returns the process exit code.
func Main(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	root := newRootCmd()
	root.SetArgs(args)
	root.SetIn(stdin)
	root.SetOut(stdout)
	root.SetErr(stderr)
	err := root.Execute()
	if err == nil {
		return exitOK
	}
	var fe failError
	if errors.As(err, &fe) {
		return exitFail
	}
	fmt.Fprintln(stderr, "opfence:", err)
	return exitError
}

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "opfence",
		Short: "Stop AI agents from running dangerous cloud operations without asking",
		Long: `Opfence classifies the API calls and tool calls an AI agent makes, using a
tested catalog of cloud and MCP operations, and decides whether each one is
allowed, needs your approval, or is denied.`,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.CompletionOptions.HiddenDefaultCmd = true
	root.AddCommand(newVersionCmd())
	return root
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the version",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			fmt.Fprintln(cmd.OutOrStdout(), version.String())
			return nil
		},
	}
}
