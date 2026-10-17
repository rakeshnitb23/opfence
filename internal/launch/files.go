package launch

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// systemBundles are the usual places of the system's root certificates
// (the list Go's crypto/x509 reads on Linux, plus macOS's /etc/ssl/cert.pem).
var systemBundles = []string{
	"/etc/ssl/certs/ca-certificates.crt",
	"/etc/pki/tls/certs/ca-bundle.crt",
	"/etc/ssl/ca-bundle.pem",
	"/etc/pki/tls/cacert.pem",
	"/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
	"/etc/ssl/cert.pem",
}

// BaseBundle returns the root certificates the bundle starts from: the
// user's own SSL_CERT_FILE when it is set (a corporate CA, for example),
// else the system's file, else "" when there is none.
func BaseBundle(certDir string) string {
	if f := os.Getenv("SSL_CERT_FILE"); f != "" && filepath.Dir(f) != certDir {
		if _, err := os.Stat(f); err == nil {
			return f
		}
	}
	for _, f := range systemBundles {
		if _, err := os.Stat(f); err == nil {
			return f
		}
	}
	return ""
}

// CAFiles are the certificate files a session points clients at.
type CAFiles struct {
	CA     string // Opfence's CA alone
	Bundle string // base roots plus Opfence's CA; "" without base roots
}

// WriteCAFiles writes ca.pem and, when base is set, ca-bundle.pem into
// dir. Files are replaced atomically, because several sessions may share
// them.
func WriteCAFiles(dir string, caPEM []byte, base string) (CAFiles, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return CAFiles{}, err
	}
	f := CAFiles{CA: filepath.Join(dir, "ca.pem")}
	if err := writeAtomic(f.CA, caPEM); err != nil {
		return CAFiles{}, err
	}
	if base == "" {
		return f, nil
	}
	roots, err := os.ReadFile(base)
	if err != nil {
		return CAFiles{}, err
	}
	if !bytes.Contains(roots, []byte("-----BEGIN CERTIFICATE-----")) {
		return CAFiles{}, fmt.Errorf("%s holds no PEM certificates", base)
	}
	var b bytes.Buffer
	b.Write(bytes.TrimRight(roots, "\n"))
	b.WriteString("\n\n# Opfence local CA\n")
	b.Write(caPEM)
	f.Bundle = filepath.Join(dir, "ca-bundle.pem")
	if err := writeAtomic(f.Bundle, b.Bytes()); err != nil {
		return CAFiles{}, err
	}
	return f, nil
}

func writeAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	_, werr := tmp.Write(data)
	cerr := tmp.Close()
	if err := errors.Join(werr, cerr, os.Chmod(tmp.Name(), 0o644)); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	return nil
}
