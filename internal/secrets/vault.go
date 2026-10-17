package secrets

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"
)

// Secret is one credential Opfence holds.
type Secret struct {
	Provider    string   `json:"provider"`
	Name        string   `json:"name"`
	Value       string   `json:"value"`
	Placeholder string   `json:"placeholder"`
	Sources     []string `json:"sources,omitempty"` // where opfence init found it
	// Group ties keys that work together, such as an AWS access key ID and
	// its secret key: the file they were found in, or "env".
	Group   string    `json:"group,omitempty"`
	Created time.Time `json:"created"`
}

// Account is the secret's key in the store.
func (s *Secret) Account() string { return "secret/" + s.Provider + "/" + s.Name }

const (
	indexAccount = "index"
	caAccount    = "ca"
)

// Vault keeps secrets in a Store, with an index item because keychains
// cannot list items.
type Vault struct {
	Store Store
}

// List returns every secret, sorted by provider and name.
func (v *Vault) List() ([]*Secret, error) {
	accounts, err := v.index()
	if err != nil {
		return nil, err
	}
	var out []*Secret
	for _, a := range accounts {
		raw, err := v.Store.Get(a)
		if errors.Is(err, ErrNotFound) {
			continue // removed outside Opfence
		}
		if err != nil {
			return nil, err
		}
		var s Secret
		if err := json.Unmarshal([]byte(raw), &s); err != nil {
			return nil, fmt.Errorf("keychain item %s: %w", a, err)
		}
		out = append(out, &s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Account() < out[j].Account() })
	return out, nil
}

// Put stores s and adds it to the index.
func (v *Vault) Put(s *Secret) error {
	if s.Provider == "" || s.Name == "" || len(s.Value) < MinLength || len(s.Placeholder) != len(s.Value) {
		return fmt.Errorf("secret %s/%s is incomplete", s.Provider, s.Name)
	}
	if s.Created.IsZero() {
		s.Created = time.Now().UTC()
	}
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	if err := v.Store.Set(s.Account(), string(b)); err != nil {
		return err
	}
	accounts, err := v.index()
	if err != nil {
		return err
	}
	if !slices.Contains(accounts, s.Account()) {
		accounts = append(accounts, s.Account())
		return v.setIndex(accounts)
	}
	return nil
}

// Remove deletes the secret provider/name.
func (v *Vault) Remove(provider, name string) error {
	acct := (&Secret{Provider: provider, Name: name}).Account()
	err := v.Store.Delete(acct)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return err
	}
	accounts, ierr := v.index()
	if ierr != nil {
		return ierr
	}
	i := slices.Index(accounts, acct)
	if i < 0 {
		if err != nil {
			return fmt.Errorf("no secret %s/%s", provider, name)
		}
		return nil
	}
	return v.setIndex(slices.Delete(accounts, i, i+1))
}

func (v *Vault) index() ([]string, error) {
	raw, err := v.Store.Get(indexAccount)
	if errors.Is(err, ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []string
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return nil, fmt.Errorf("keychain index: %w", err)
	}
	return out, nil
}

func (v *Vault) setIndex(accounts []string) error {
	sort.Strings(accounts)
	b, _ := json.Marshal(accounts)
	return v.Store.Set(indexAccount, string(b))
}

// CA returns the stored certificate authority's PEM blocks, or ErrNotFound.
func (v *Vault) CA() (certPEM, keyPEM []byte, err error) {
	raw, err := v.Store.Get(caAccount)
	if err != nil {
		return nil, nil, err
	}
	var c struct{ Cert, Key string }
	if err := json.Unmarshal([]byte(raw), &c); err != nil {
		return nil, nil, fmt.Errorf("keychain CA item: %w", err)
	}
	return []byte(c.Cert), []byte(c.Key), nil
}

// SetCA stores the certificate authority.
func (v *Vault) SetCA(certPEM, keyPEM []byte) error {
	b, _ := json.Marshal(struct{ Cert, Key string }{string(certPEM), string(keyPEM)})
	return v.Store.Set(caAccount, string(b))
}

// Set is the in-memory view the proxy uses: lookups by placeholder and the
// pairs the response scrubber replaces.
type Set struct {
	byPlaceholder map[string]*Secret
	all           []*Secret
}

// NewSet indexes secrets by placeholder.
func NewSet(secrets []*Secret) *Set {
	s := &Set{byPlaceholder: map[string]*Secret{}}
	for _, sec := range secrets {
		s.byPlaceholder[sec.Placeholder] = sec
		s.all = append(s.all, sec)
	}
	return s
}

// ByPlaceholder returns the secret a placeholder stands for, or nil.
func (s *Set) ByPlaceholder(p string) *Secret {
	if s == nil {
		return nil
	}
	return s.byPlaceholder[p]
}

// All returns every secret.
func (s *Set) All() []*Secret {
	if s == nil {
		return nil
	}
	return s.all
}

// Len is the number of secrets.
func (s *Set) Len() int {
	if s == nil {
		return 0
	}
	return len(s.all)
}

// IsPlaceholder reports whether v is one of the set's placeholders.
func (s *Set) IsPlaceholder(v string) bool { return s.ByPlaceholder(strings.TrimSpace(v)) != nil }
