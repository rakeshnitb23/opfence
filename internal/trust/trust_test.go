package trust

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/rakeshnitb23/opfence/internal/ca"
)

// fakeRunner records commands and carries out install and rm on real files,
// so tests can check that uninstall leaves the system as it found it.
type fakeRunner struct {
	cmds [][]string
	fail string // a command name that fails
}

func (f *fakeRunner) Run(name string, args ...string) error {
	f.cmds = append(f.cmds, append([]string{name}, args...))
	argv := append([]string{name}, args...)
	if argv[0] == "sudo" {
		argv = argv[1:]
	}
	if argv[0] == f.fail {
		return errors.New(f.fail + " failed")
	}
	switch argv[0] {
	case "install":
		data, err := os.ReadFile(argv[len(argv)-2])
		if err != nil {
			return err
		}
		return os.WriteFile(argv[len(argv)-1], data, 0o644)
	case "rm":
		if err := os.Remove(argv[len(argv)-1]); err != nil && !(os.IsNotExist(err) && argv[1] == "-f") {
			return err
		}
	}
	return nil
}

func testCert(t *testing.T) (string, []byte) {
	t.Helper()
	c, err := ca.New("test", []string{"api.github.com"})
	if err != nil {
		t.Fatal(err)
	}
	f := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(f, c.CertPEM(), 0o644); err != nil {
		t.Fatal(err)
	}
	return f, c.CertPEM()
}

func TestLinuxSystemInstallReverses(t *testing.T) {
	file, pemBytes := testCert(t)
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "etc/pki/ca-trust/source/anchors"), 0o755); err != nil {
		t.Fatal(err)
	}
	before := listFiles(t, root)
	r := &fakeRunner{}
	m, err := Install(pemBytes, Options{GOOS: "linux", System: true, Root: root, CertFile: file}, r)
	if err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(root, "etc/pki/ca-trust/source/anchors/opfence-local-ca.crt")
	if _, err := os.Stat(dst); err != nil {
		t.Fatal("certificate not installed")
	}
	want := [][]string{{"sudo", "install", "-m", "0644", file, dst}, {"sudo", "update-ca-trust", "extract"}}
	if !reflect.DeepEqual(r.cmds, want) {
		t.Fatalf("install ran %v", r.cmds)
	}

	// The manifest survives a save and load.
	path := filepath.Join(t.TempDir(), "trust.json")
	if err := Save(path, m); err != nil {
		t.Fatal(err)
	}
	if info, _ := os.Stat(path); info.Mode().Perm() != 0o600 {
		t.Fatalf("manifest mode %v", info.Mode().Perm())
	}
	m, err = Load(path)
	if err != nil {
		t.Fatal(err)
	}

	r.cmds = nil
	failed, err := Uninstall(m, file, r)
	if err != nil || len(failed) != 0 {
		t.Fatal(failed, err)
	}
	want = [][]string{{"sudo", "rm", "-f", dst}, {"sudo", "update-ca-trust", "extract"}}
	if !reflect.DeepEqual(r.cmds, want) {
		t.Fatalf("uninstall ran %v", r.cmds)
	}
	if after := listFiles(t, root); !reflect.DeepEqual(before, after) {
		t.Fatalf("files before %v, after %v", before, after)
	}
	if err := Save(path, &Manifest{}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("empty manifest kept")
	}
}

func TestMacOSInstallReverses(t *testing.T) {
	file, pemBytes := testCert(t)
	r := &fakeRunner{}
	m, err := Install(pemBytes, Options{GOOS: "darwin", Home: "/Users/dev", CertFile: file}, r)
	if err != nil {
		t.Fatal(err)
	}
	keychain := "/Users/dev/Library/Keychains/login.keychain-db"
	if !reflect.DeepEqual(r.cmds, [][]string{{"security", "add-trusted-cert", "-r", "trustRoot", "-k", keychain, file}}) {
		t.Fatal(r.cmds)
	}
	r.cmds = nil
	if _, err := Uninstall(m, "/tmp/cert.pem", r); err != nil {
		t.Fatal(err)
	}
	if len(r.cmds) != 2 || !reflect.DeepEqual(r.cmds[0], []string{"security", "remove-trusted-cert", "/tmp/cert.pem"}) ||
		r.cmds[1][1] != "delete-certificate" || len(r.cmds[1][3]) != 40 || r.cmds[1][4] != keychain {
		t.Fatal(r.cmds)
	}
}

func TestWindowsInstallReverses(t *testing.T) {
	file, pemBytes := testCert(t)
	r := &fakeRunner{}
	m, err := Install(pemBytes, Options{GOOS: "windows", CertFile: file}, r)
	if err != nil {
		t.Fatal(err)
	}
	r.cmds = nil
	if _, err := Uninstall(m, file, r); err != nil {
		t.Fatal(err)
	}
	if len(r.cmds) != 1 || strings.Join(r.cmds[0][:4], " ") != "certutil -user -delstore Root" {
		t.Fatal(r.cmds)
	}
}

// A failed refresh after the file was copied still leaves a manifest that
// removes the file, and a failed undo keeps the step.
func TestPartialFailures(t *testing.T) {
	file, pemBytes := testCert(t)
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, "usr/local/share/ca-certificates"), 0o755)
	r := &fakeRunner{fail: "update-ca-certificates"}
	m, err := Install(pemBytes, Options{GOOS: "linux", System: true, Root: root, AsRoot: true, CertFile: file}, r)
	if err == nil || len(m.Steps) != 1 {
		t.Fatalf("err %v, steps %d", err, len(m.Steps))
	}
	failed, err := Uninstall(m, file, r)
	if err == nil || len(failed) != 1 {
		t.Fatalf("undo with a failing refresh: %v %v", failed, err)
	}
	r.fail = ""
	if failed, err := Uninstall(&Manifest{Steps: failed}, file, r); err != nil || len(failed) != 0 {
		t.Fatal(failed, err)
	}
	if _, err := Install(pemBytes, Options{GOOS: "linux", System: true, Root: t.TempDir(), CertFile: file}, r); err == nil {
		t.Fatal("installed without a store folder")
	}
	if m, err := Install(pemBytes, Options{GOOS: "linux", CertFile: file}, r); err != nil || len(m.Steps) != 0 {
		t.Fatal("linux without --system changes nothing", m, err)
	}
}

func listFiles(t *testing.T, root string) []string {
	t.Helper()
	var out []string
	filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			out = append(out, p)
		}
		return nil
	})
	return out
}
