// Wycheproof test vectors as an embedded filesystem of JSON content.
//
// Downstream Go code can import github.com/c2sp/wycheproof and access
// TestVectors and Schemas using the standard library fs.FS interface.

package wycheproof

import (
	"embed"
	"io/fs"
)

var TestVectors, _ = fs.Sub(testVectors, "testvectors_v1")

//go:embed testvectors_v1
var testVectors embed.FS

var Schemas, _ = fs.Sub(schemas, "schemas")

//go:embed schemas
var schemas embed.FS
