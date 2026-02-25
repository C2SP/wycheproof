// schemagen is a smoke test that go-jsonschema is able to generate Go code
// for the Wycheproof JSON schemas without any errors or warnings.
//
// In particular this is useful for catching cases where we are emitting
// schema types with conflicting names as this is often a strong indicator
// that there's commonality we can lift into a single shared definition.
// Ignoring these warnings results in generated types with clunky numeric
// suffixes (e.g. `SignatureTestCase` and `SignatureTestCase_1`)
package main

import (
	"flag"
	"log"
	"os"
	"path/filepath"

	"github.com/atombender/go-jsonschema/pkg/generator"
)

var schemaDirectory = flag.String("schemas-dir", "schemas", "directory containing schema files")

func main() {
	flag.Parse()

	var warnings []string

	ouputName := "schema.go"
	cfg := generator.Config{
		DefaultPackageName: "wycheproof",
		DefaultOutputName:  ouputName,
		Tags:               []string{"json"},
		Warner: func(message string) {
			warnings = append(warnings, message)
		},
	}
	gen, err := generator.New(cfg)
	if err != nil {
		log.Fatal(err)
	}

	entries, err := os.ReadDir(*schemaDirectory)
	if err != nil {
		log.Fatalf("reading schemas dir: %v", err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		schemaFile := filepath.Join(*schemaDirectory, entry.Name())
		err = gen.DoFile(schemaFile)
		if err != nil {
			log.Fatalf("processing %s: %v", schemaFile, err)
		}
	}

	sources, err := gen.Sources()
	if err != nil {
		log.Fatalf("error generating sources: %v\n", err)
	}
	if sourceCount := len(sources); sourceCount != 1 {
		log.Fatalf("expected to generate 1 source file, got %d\n", sourceCount)
	}
	_, ok := sources[ouputName]
	if !ok {
		log.Fatalf("missing generated %q output file source", ouputName)
	}

	for _, warning := range warnings {
		log.Printf("⚠️ Warning: %s", warning)
	}

	os.Exit(len(warnings))
}
