//go:build !linux

package cli

// hideEnviron is needed on Linux only, where /proc exposes a process's
// environment to its user.
func hideEnviron() error { return nil }
