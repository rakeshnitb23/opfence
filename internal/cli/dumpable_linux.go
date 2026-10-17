package cli

import "golang.org/x/sys/unix"

// hideEnviron makes /proc/<pid>/environ and the process's memory readable
// only by root. opfence run keeps the real keys it replaced with
// placeholders in its own environment, and Claude Code's file tools run as
// the same user outside the sandbox. Children are unaffected: exec resets
// the flag.
func hideEnviron() error {
	return unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0)
}
