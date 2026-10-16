// Package catalog embeds the Opfence catalog snapshot shipped with the binary.
//
// The YAML files beside this one are the catalog itself; see
// docs/ARCHITECTURE.md §4 for the format and CONTRIBUTING.md for how to add a
// rule. Load it with internal/catalog.Embedded.
package catalog

import "embed"

// FS holds every provider folder.
//
//go:embed */*.yaml */fixtures
var FS embed.FS
