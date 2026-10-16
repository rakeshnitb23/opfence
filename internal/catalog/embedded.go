package catalog

import (
	"sync"

	catalogdata "github.com/rakeshnitb23/opfence/catalog"
)

var embedded = sync.OnceValues(func() (*Catalog, error) { return Load(catalogdata.FS) })

// Embedded returns the catalog snapshot compiled into the binary. It is
// loaded once; callers must not modify it.
func Embedded() (*Catalog, error) { return embedded() }
