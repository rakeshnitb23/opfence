// Package ca is Opfence's local certificate authority: a name-constrained
// root that mints short-lived leaf certificates for the API hosts the proxy
// intercepts (docs/ARCHITECTURE.md §8.3).
package ca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	rootValidity = 10 * 365 * 24 * time.Hour
	leafValidity = 24 * time.Hour
	// leafRenew is how close to expiry a cached leaf is replaced.
	leafRenew = time.Hour
	// maxLeaves bounds the leaf cache; wildcard hosts such as
	// *.amazonaws.com could otherwise grow it without limit.
	maxLeaves = 1024
)

// CA holds the root certificate and key and caches leaf certificates.
type CA struct {
	cert    *x509.Certificate
	certPEM []byte
	key     crypto.Signer
	leafKey crypto.Signer

	mu     sync.Mutex
	leaves map[string]*tls.Certificate

	now func() time.Time
}

// New generates a root whose name constraints permit only the given DNS
// domains (see PermittedDomains). An empty list is an error: an
// unconstrained root would let a leaked key impersonate any site.
func New(machine string, permitted []string) (*CA, error) {
	if len(permitted) == 0 {
		return nil, errors.New("ca: no permitted domains")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	cn := "Opfence local CA"
	if machine != "" {
		cn += " (" + machine + ")"
	}
	tmpl := &x509.Certificate{
		SerialNumber:                serial,
		Subject:                     pkix.Name{CommonName: cn, Organization: []string{"Opfence"}},
		NotBefore:                   now.Add(-time.Hour),
		NotAfter:                    now.Add(rootValidity),
		KeyUsage:                    x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid:       true,
		IsCA:                        true,
		MaxPathLenZero:              true,
		PermittedDNSDomainsCritical: true,
		PermittedDNSDomains:         permitted,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return nil, err
	}
	return fromParts(der, key)
}

// Load restores a CA from PEM-encoded certificate and PKCS #8 key.
func Load(certPEM, keyPEM []byte) (*CA, error) {
	cb, _ := pem.Decode(certPEM)
	if cb == nil || cb.Type != "CERTIFICATE" {
		return nil, errors.New("ca: certificate is not PEM")
	}
	kb, _ := pem.Decode(keyPEM)
	if kb == nil || kb.Type != "PRIVATE KEY" {
		return nil, errors.New("ca: key is not a PEM private key")
	}
	k, err := x509.ParsePKCS8PrivateKey(kb.Bytes)
	if err != nil {
		return nil, fmt.Errorf("ca: key: %w", err)
	}
	signer, ok := k.(crypto.Signer)
	if !ok {
		return nil, errors.New("ca: key cannot sign")
	}
	return fromParts(cb.Bytes, signer)
}

func fromParts(der []byte, key crypto.Signer) (*CA, error) {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	if !cert.IsCA {
		return nil, errors.New("ca: certificate is not a CA")
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return &CA{
		cert:    cert,
		certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		key:     key,
		leafKey: leafKey,
		leaves:  map[string]*tls.Certificate{},
		now:     time.Now,
	}, nil
}

// Certificate returns the root certificate.
func (c *CA) Certificate() *x509.Certificate { return c.cert }

// CertPEM returns the root certificate as PEM, for trust stores and the CA
// environment variables. It never contains the key.
func (c *CA) CertPEM() []byte { return c.certPEM }

// KeyPEM returns the root key as PKCS #8 PEM, for the secret store only.
func (c *CA) KeyPEM() ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(c.key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// Pool returns a certificate pool holding only the root.
func (c *CA) Pool() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(c.cert)
	return p
}

// Permits reports whether the root's name constraints allow host.
func (c *CA) Permits(host string) bool {
	host = strings.ToLower(host)
	for _, d := range c.cert.PermittedDNSDomains {
		if host == d || strings.HasSuffix(host, "."+d) {
			return true
		}
	}
	return false
}

// Leaf returns a certificate for host, minting one when none is cached or
// the cached one is close to expiry.
func (c *CA) Leaf(host string) (*tls.Certificate, error) {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if host == "" || net.ParseIP(host) != nil {
		return nil, fmt.Errorf("ca: no certificate for %q: a DNS name is required", host)
	}
	if !c.Permits(host) {
		return nil, fmt.Errorf("ca: %s is outside the CA's permitted names", host)
	}
	now := c.now()
	c.mu.Lock()
	defer c.mu.Unlock()
	if l, ok := c.leaves[host]; ok && now.Add(leafRenew).Before(l.Leaf.NotAfter) {
		return l, nil
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(leafValidity),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, c.leafKey.Public(), c.key)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	if len(c.leaves) >= maxLeaves {
		clear(c.leaves)
	}
	l := &tls.Certificate{Certificate: [][]byte{der, c.cert.Raw}, PrivateKey: c.leafKey, Leaf: leaf}
	c.leaves[host] = l
	return l, nil
}

// PermittedDomains turns catalog host patterns into name constraints:
// "*.amazonaws.com" becomes "amazonaws.com" (which covers its subdomains),
// exact hosts stay, and names covered by another entry are dropped.
func PermittedDomains(hosts []string) []string {
	set := map[string]bool{}
	for _, h := range hosts {
		h = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(h)), ".")
		h = strings.TrimPrefix(h, "*.")
		if h != "" && net.ParseIP(h) == nil {
			set[h] = true
		}
	}
	var out []string
	for h := range set {
		covered := false
		for d := range set {
			if d != h && strings.HasSuffix(h, "."+d) {
				covered = true
				break
			}
		}
		if !covered {
			out = append(out, h)
		}
	}
	sort.Strings(out)
	return out
}

func randomSerial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
}
