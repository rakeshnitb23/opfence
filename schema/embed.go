// Package schema embeds the JSON Schemas for catalog files, for editors and
// for tests that keep the schemas in step with the Go loader.
package schema

import "embed"

// FS holds the *.schema.json files.
//
//go:embed *.schema.json
var FS embed.FS
