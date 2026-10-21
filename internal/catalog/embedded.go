package catalog

import (
	"sync"

	catalogdata "github.com/rakeshnitb23/opfence/catalog"
)

var embedded = sync.OnceValues(func() (*Catalog, error) { return Load(catalogdata.FS) })

// Embedded returns the catalog snapshot compiled into the binary. It is
// loaded once; callers must not modify it.
func Embedded() (*Catalog, error) { return embedded() }

var embeddedLazy = sync.OnceValues(func() (*Catalog, error) { return LoadLazy(catalogdata.FS) })

// EmbeddedLazy returns the embedded catalog loaded lazily (LoadLazy): every
// provider, and a provider's rules once LoadRules is called for it. Tests
// load the embedded catalog whole, so the checks a lazy load skips have
// passed. Callers must not modify it.
func EmbeddedLazy() (*Catalog, error) { return embeddedLazy() }
