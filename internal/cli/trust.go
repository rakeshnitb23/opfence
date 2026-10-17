package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/spf13/cobra"

	"github.com/rakeshnitb23/opfence/internal/audit"
	"github.com/rakeshnitb23/opfence/internal/launch"
	"github.com/rakeshnitb23/opfence/internal/trust"
)

// trustRunner runs the system commands opfence trust needs; tests replace it.
var trustRunner trust.Runner = trust.ExecRunner{}

// trustGOOS is the platform opfence trust installs for; tests replace it.
var trustGOOS = runtime.GOOS

func trustManifestPath() (string, error) {
	dir, err := audit.StateDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "trust.json"), nil
}

func newTrustCmd(g *globalOptions) *cobra.Command {
	var system, uninstall bool
	cmd := &cobra.Command{
		Use:   "trust",
		Short: "Trust Opfence's local CA in your system's certificate store (or undo it)",
		Long: `Opfence reads HTTPS to APIs in the catalog with certificates from a local
certificate authority whose key stays in your keychain. The CA can only issue
certificates for those APIs' domains (X.509 name constraints).

opfence run already points most tools at the CA with SSL_CERT_FILE and
similar variables. Some programs ignore those and use the system store: Go
programs on macOS (gh, terraform), for example. opfence trust adds the CA:

  macOS     your login keychain (you will be asked for your password)
  Linux     nothing by default; --system adds it to the distribution's
            store with sudo
  Windows   your user certificate store

Every step is recorded, and "opfence trust --uninstall" reverses them.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			out := cmd.OutOrStdout()
			path, err := trustManifestPath()
			if err != nil {
				return err
			}
			m, err := trust.Load(path)
			if err != nil {
				return err
			}
			if uninstall {
				if m == nil {
					fmt.Fprintln(out, "Opfence's CA is not installed anywhere; nothing to undo.")
					return nil
				}
				return untrust(cmd, path, m)
			}

			eng, err := g.engine()
			if err != nil {
				return err
			}
			_, vault := loadSecrets(cmd.ErrOrStderr())
			if vault == nil {
				return errors.New("opfence trust needs your keychain, which keeps the CA's key; without it the CA changes every run and would have to be trusted again each time")
			}
			authority, persistent, err := loadCA(cmd.ErrOrStderr(), eng, vault)
			if err != nil {
				return err
			}
			if !persistent {
				return errors.New("the CA could not be stored in your keychain, so it would change every run; fix the keychain first (see opfence doctor)")
			}
			certDir, err := launch.CertDir()
			if err != nil {
				return err
			}
			files, err := launch.WriteCAFiles(certDir, authority.CertPEM(), launch.BaseBundle(certDir))
			if err != nil {
				return err
			}
			sum, err := trust.SHA256(authority.CertPEM())
			if err != nil {
				return err
			}
			if m != nil && m.CertSHA256 != sum {
				fmt.Fprintln(out, "Your keychain holds a newer Opfence CA; removing the old one first.")
				if err := untrust(cmd, path, m); err != nil {
					return err
				}
				m = nil
			}
			if m != nil && (trustGOOS != "linux" || !system || hasKind(m, "file")) {
				fmt.Fprintln(out, "Opfence's CA is already trusted:")
				printSteps(cmd, m.Steps)
				return nil
			}
			home, _ := os.UserHomeDir()
			added, err := trust.Install(authority.CertPEM(), trust.Options{
				GOOS: trustGOOS, Home: home, System: system, AsRoot: os.Geteuid() == 0, CertFile: files.CA,
			}, trustRunner)
			if m == nil {
				m = added
			} else if added != nil {
				m.Steps = append(m.Steps, added.Steps...)
			}
			if serr := trust.Save(path, m); serr != nil {
				return errors.Join(err, serr)
			}
			if err != nil {
				if m != nil && len(m.Steps) > 0 {
					fmt.Fprintln(out, "Some steps finished before the error; opfence trust --uninstall reverses them.")
				}
				return err
			}
			if len(added.Steps) > 0 {
				fmt.Fprintln(out, "Opfence's CA is now trusted:")
				printSteps(cmd, added.Steps)
			}
			if trustGOOS == "linux" && !system {
				fmt.Fprintf(out, "Programs started with opfence run trust the CA through SSL_CERT_FILE and similar variables (%s).\n", files.Bundle)
				fmt.Fprintln(out, "Add --system to also trust it system-wide (uses sudo).")
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&system, "system", false, "Linux: also add the CA to the system store (uses sudo)")
	cmd.Flags().BoolVar(&uninstall, "uninstall", false, "remove the CA from everywhere opfence trust put it")
	return cmd
}

// untrust reverses a manifest and keeps only the steps that failed.
func untrust(cmd *cobra.Command, path string, m *trust.Manifest) error {
	tmp, err := os.CreateTemp("", "opfence-ca-*.pem")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.WriteString(m.CertPEM); err != nil {
		tmp.Close()
		return err
	}
	tmp.Close()
	failed, uerr := trust.Uninstall(m, tmp.Name(), trustRunner)
	out := cmd.OutOrStdout()
	for _, s := range m.Steps {
		if !containsStep(failed, s) {
			fmt.Fprintf(out, "  undone: %s\n", s.Description)
		}
	}
	m.Steps = failed
	if err := trust.Save(path, m); err != nil {
		return errors.Join(uerr, err)
	}
	if uerr != nil {
		for _, s := range failed {
			fmt.Fprintf(out, "  not undone: %s\n", s.Description)
		}
		return uerr
	}
	return nil
}

func printSteps(cmd *cobra.Command, steps []trust.Step) {
	for _, s := range steps {
		fmt.Fprintf(cmd.OutOrStdout(), "  %s\n", s.Description)
	}
}

func hasKind(m *trust.Manifest, kind string) bool {
	for _, s := range m.Steps {
		if s.Kind == kind {
			return true
		}
	}
	return false
}

func containsStep(steps []trust.Step, s trust.Step) bool {
	for _, x := range steps {
		if x.Kind == s.Kind && x.Description == s.Description {
			return true
		}
	}
	return false
}
