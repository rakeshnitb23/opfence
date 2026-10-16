// Package version reports the build's version information.
package version

import (
	"fmt"
	"runtime"
	"runtime/debug"
)

// Set at release time with -ldflags "-X github.com/rakeshnitb23/opfence/internal/version.Version=v0.1.0".
var (
	Version = "dev"
	Commit  = ""
)

// String returns a one-line description of the build.
func String() string {
	commit := Commit
	if commit == "" {
		commit = vcsRevision()
	}
	if commit == "" {
		commit = "unknown"
	}
	return fmt.Sprintf("opfence %s (commit %s, %s, %s/%s)", Version, commit, runtime.Version(), runtime.GOOS, runtime.GOARCH)
}

func vcsRevision() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return ""
	}
	var rev string
	var dirty bool
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			rev = s.Value
		case "vcs.modified":
			dirty = s.Value == "true"
		}
	}
	if len(rev) > 12 {
		rev = rev[:12]
	}
	if rev != "" && dirty {
		rev += "-dirty"
	}
	return rev
}
