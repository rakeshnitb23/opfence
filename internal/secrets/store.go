// Package secrets keeps real credentials out of the agent's reach: values
// live in the OS keychain, and files and the agent see placeholders that the
// proxy swaps back in only for the provider each one belongs to
// (docs/ARCHITECTURE.md §8.4).
package secrets

import (
	"errors"
	"fmt"
	"sync"

	"github.com/zalando/go-keyring"
)

// Service is the keychain service name for every Opfence item.
const Service = "opfence"

// ErrNotFound is returned for a missing item.
var ErrNotFound = errors.New("not found")

// Store is a flat key-value secret store.
type Store interface {
	Get(account string) (string, error)
	Set(account, value string) error
	Delete(account string) error
}

// Keychain stores items in the OS keychain: the macOS login keychain, or
// the Secret Service (GNOME Keyring, KWallet, KeePassXC) on Linux.
type Keychain struct{}

// Get implements Store.
func (Keychain) Get(account string) (string, error) {
	v, err := keyring.Get(Service, account)
	if errors.Is(err, keyring.ErrNotFound) {
		return "", ErrNotFound
	}
	return v, wrap(err)
}

// Set implements Store.
func (Keychain) Set(account, value string) error {
	return wrap(keyring.Set(Service, account, value))
}

// Delete implements Store.
func (Keychain) Delete(account string) error {
	err := keyring.Delete(Service, account)
	if errors.Is(err, keyring.ErrNotFound) {
		return ErrNotFound
	}
	return wrap(err)
}

func wrap(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("OS keychain: %w (on Linux, Opfence needs a Secret Service such as GNOME Keyring or KeePassXC running in your session)", err)
}

// Memory is an in-process Store for tests.
type Memory struct {
	mu sync.Mutex
	m  map[string]string
}

// Get implements Store.
func (s *Memory) Get(account string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.m[account]
	if !ok {
		return "", ErrNotFound
	}
	return v, nil
}

// Set implements Store.
func (s *Memory) Set(account, value string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.m == nil {
		s.m = map[string]string{}
	}
	s.m[account] = value
	return nil
}

// Delete implements Store.
func (s *Memory) Delete(account string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.m[account]; !ok {
		return ErrNotFound
	}
	delete(s.m, account)
	return nil
}
