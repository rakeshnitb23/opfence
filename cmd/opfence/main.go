// Command opfence classifies agent API calls against a tested catalog of
// dangerous operations, exports that catalog to other policy engines, and
// runs a local credential proxy that enforces it.
package main

import (
	"os"

	"github.com/rakeshnitb23/opfence/internal/cli"
)

func main() {
	os.Exit(cli.Main(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}
