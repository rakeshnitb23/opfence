// Package trust installs Opfence's CA certificate in the operating system's
// trust store and removes it again (docs/ARCHITECTURE.md §8.3). Every step
// is recorded in a manifest, and uninstall reverses exactly those steps.
package trust

import (
	"crypto/sha1" //nolint:gosec // macOS's security tool names certificates by SHA-1
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Manifest records what an install did.
type Manifest struct {
	Version    int    `json:"version"`
	CertSHA256 string `json:"cert_sha256"`
	CertPEM    string `json:"cert_pem"`
	Steps      []Step `json:"steps"`
}

// Step is one change to the system. Undo runs Commands in order after
// removing File (when set).
type Step struct {
	Kind        string     `json:"kind"` // macos-keychain, file, windows-store
	Description string     `json:"description"`
	File        string     `json:"file,omitempty"` // a file the install wrote
	Undo        [][]string `json:"undo"`           // commands that reverse the step
}

// Runner runs a command; tests replace it.
type Runner interface {
	Run(name string, args ...string) error
}

// ExecRunner runs commands with the user's terminal, so sudo and macOS's
// password prompt can ask.
type ExecRunner struct{}

// Run implements Runner.
func (ExecRunner) Run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stderr, os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s %s: %w", name, strings.Join(args, " "), err)
	}
	return nil
}

// Options configures an install.
type Options struct {
	GOOS string
	// Home is the user's home folder (macOS login keychain).
	Home string
	// System also installs into the Linux system store, with sudo.
	System bool
	// Root is prefixed to system paths; tests set it to a temporary folder.
	Root string
	// AsRoot is true when the process already runs as root (no sudo).
	AsRoot bool
	// CertFile is where the certificate is written for tools that need a
	// file (the cache folder's ca.pem).
	CertFile string
}

// linuxStores are the anchor folders of the common distributions and the
// command that rebuilds the store from them.
var linuxStores = []struct {
	dir     string
	refresh []string
}{
	{"/usr/local/share/ca-certificates", []string{"update-ca-certificates"}},           // Debian, Ubuntu, Alpine
	{"/etc/pki/ca-trust/source/anchors", []string{"update-ca-trust", "extract"}},       // Fedora, RHEL
	{"/etc/ca-certificates/trust-source/anchors", []string{"trust", "extract-compat"}}, // Arch
	{"/usr/share/pki/trust/anchors", []string{"update-ca-certificates"}},               // openSUSE
}

// Install trusts certPEM and returns the manifest. Steps that succeeded
// before a failure are in the manifest, so they can be undone.
func Install(certPEM []byte, o Options, r Runner) (*Manifest, error) {
	cert, err := parse(certPEM)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(cert.Raw)
	m := &Manifest{Version: 1, CertSHA256: hex.EncodeToString(sum[:]), CertPEM: string(certPEM)}
	switch o.GOOS {
	case "darwin":
		keychain := filepath.Join(o.Home, "Library", "Keychains", "login.keychain-db")
		sha := sha1.Sum(cert.Raw) //nolint:gosec
		if err := r.Run("security", "add-trusted-cert", "-r", "trustRoot", "-k", keychain, o.CertFile); err != nil {
			return m, err
		}
		m.Steps = append(m.Steps, Step{
			Kind:        "macos-keychain",
			Description: "trusted in your login keychain",
			Undo: [][]string{
				{"security", "remove-trusted-cert", "{cert}"},
				{"security", "delete-certificate", "-Z", strings.ToUpper(hex.EncodeToString(sha[:])), keychain},
			},
		})
	case "linux":
		if !o.System {
			return m, nil // opfence run sets the CA variables; nothing to install
		}
		store, err := pickLinuxStore(o.Root)
		if err != nil {
			return m, err
		}
		dst := filepath.Join(o.Root+store.dir, "opfence-local-ca.crt")
		if err := run(r, sudo(o, "install", "-m", "0644", o.CertFile, dst)); err != nil {
			return m, err
		}
		step := Step{Kind: "file", Description: "added to the system store as " + dst, File: dst,
			Undo: [][]string{sudo(o, "rm", "-f", dst), sudo(o, store.refresh...)}}
		m.Steps = append(m.Steps, step)
		if err := run(r, sudo(o, store.refresh...)); err != nil {
			return m, err
		}
	case "windows":
		if err := r.Run("certutil", "-user", "-addstore", "Root", o.CertFile); err != nil {
			return m, err
		}
		m.Steps = append(m.Steps, Step{
			Kind:        "windows-store",
			Description: "trusted in your Windows certificate store",
			Undo:        [][]string{{"certutil", "-user", "-delstore", "Root", cert.SerialNumber.Text(16)}},
		})
	default:
		return m, fmt.Errorf("opfence trust does not support %s", o.GOOS)
	}
	return m, nil
}

// Uninstall reverses the manifest's steps, last first. It returns the
// steps it could not undo, so the manifest can keep them.
func Uninstall(m *Manifest, certFile string, r Runner) ([]Step, error) {
	var failed []Step
	var errs []error
	for i := len(m.Steps) - 1; i >= 0; i-- {
		s := m.Steps[i]
		var err error
		for _, c := range s.Undo {
			args := make([]string, len(c))
			for j, a := range c {
				if a == "{cert}" {
					a = certFile
				}
				args[j] = a
			}
			if err = run(r, args); err != nil {
				break
			}
		}
		if err != nil {
			failed = append([]Step{s}, failed...)
			errs = append(errs, err)
		}
	}
	return failed, errors.Join(errs...)
}

func run(r Runner, argv []string) error { return r.Run(argv[0], argv[1:]...) }

func sudo(o Options, args ...string) []string {
	if o.AsRoot {
		return args
	}
	return append([]string{"sudo"}, args...)
}

func pickLinuxStore(root string) (struct {
	dir     string
	refresh []string
}, error) {
	for _, s := range linuxStores {
		if info, err := os.Stat(root + s.dir); err == nil && info.IsDir() {
			return s, nil
		}
	}
	return linuxStores[0], errors.New("no system trust store folder found (looked for Debian, Fedora, Arch and openSUSE layouts); opfence run sets the CA variables without it")
}

func parse(certPEM []byte) (*x509.Certificate, error) {
	b, _ := pem.Decode(certPEM)
	if b == nil || b.Type != "CERTIFICATE" {
		return nil, errors.New("not a PEM certificate")
	}
	return x509.ParseCertificate(b.Bytes)
}

// SHA256 is the hex SHA-256 of a PEM certificate's DER bytes, as recorded
// in manifests.
func SHA256(certPEM []byte) (string, error) {
	c, err := parse(certPEM)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(c.Raw)
	return hex.EncodeToString(sum[:]), nil
}

// Load reads a manifest; a missing file returns nil and no error.
func Load(path string) (*Manifest, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &m, nil
}

// Save writes a manifest (0600), or removes the file when m has no steps.
func Save(path string, m *Manifest) error {
	if m == nil || len(m.Steps) == 0 {
		err := os.Remove(path)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o600)
}
