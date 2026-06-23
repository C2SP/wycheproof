package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"

	"github.com/c2sp/wycheproof/vectorgen"
)

func runLint(args []string) int {
	fs := flag.NewFlagSet("lint", flag.ContinueOnError)
	schemasDir := fs.String("schemas-dir", "", "directory containing schema files (default: embedded)")
	vectorsDirs := fs.String("vectors-dir", "testvectors_v1", "comma-separated directories containing vector files")
	filter := fs.String("vector-filter", "", "regexp; only validate vector files matching")
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), `Usage: vectorgen lint [flags]

Validate Wycheproof JSON vector files against their declared schemas and
against structural invariants (single test-group type per file, unique tcIds,
accurate numberOfTests).

Flags:
`)
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return 2
	}

	opts := vectorgen.LintOptions{
		VectorDirs: strings.Split(*vectorsDirs, ","),
		Log:        log.Printf,
	}

	if *schemasDir != "" {
		opts.SchemasFS = os.DirFS(*schemasDir)
		log.Printf("reading schemas from %q", *schemasDir)
	} else {
		log.Printf("reading schemas from embedded wycheproof.Schemas")
	}
	log.Printf("reading vectors from %q", opts.VectorDirs)

	if *filter != "" {
		re, err := regexp.Compile(*filter)
		if err != nil {
			fmt.Fprintf(os.Stderr, "vectorgen lint: invalid filter regexp: %v\n", err)
			return 2
		}
		opts.Filter = re
		log.Printf("filtering vectors with %q", *filter)
	}

	results, err := vectorgen.Lint(opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "vectorgen lint: %v\n", err)
		return 1
	}

	log.Printf("linted %d vector files", results.Total)
	log.Printf("valid: %d", results.Valid)
	log.Printf("invalid: %d", results.Invalid)
	log.Printf("no schema: %d", results.NoSchema)

	if results.Invalid > 0 || results.NoSchema > 0 {
		return 1
	}
	return 0
}
