//go:build !unix

package audit

import "os"

// Other platforms rely on the in-process mutex only.
func lock(*os.File) error   { return nil }
func unlock(*os.File) error { return nil }
