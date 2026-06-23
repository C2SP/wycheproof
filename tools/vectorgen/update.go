package main

import (
	"encoding/json/v2"
	"flag"
	"fmt"
	"os"

	"github.com/c2sp/wycheproof/vectorgen"
)

func runUpdate(args []string) int {
	fs := flag.NewFlagSet("update", flag.ContinueOnError)
	vectorsGlob := fs.String("vectors", "", "vector file glob, e.g. 'testvectors_v1/mlkem_*_test.json' (required)")
	input := fs.String("input", "", "envelope JSON file, or '-' for stdin (required)")
	overwrite := fs.Bool("overwrite", false, "permit patches to replace existing field values")
	partial := fs.Bool("partial", false, "permit patches that cover a subset of matching groups' tests")
	schemasDir := fs.String("schemas-dir", "", "schema directory (default: embedded)")
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), `Usage: vectorgen update --vectors <glob> --input <envelope>|- [flags]

Patch existing tests in vector files. Tests are matched by tcId; new fields
are inserted in the test-vector schema's properties order. Each file is
processed independently and atomically; a failure on one does not prevent
others from succeeding.

Envelope fields:
  source        source name (or "name@version") identifying which groups to patch
  patches       array of test patches; each must contain a tcId

Flags:
`)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *vectorsGlob == "" || *input == "" {
		fs.Usage()
		return 2
	}

	envBytes, err := readEnvelope(*input)
	if err != nil {
		fmt.Fprintf(os.Stderr, "vectorgen update: %v\n", err)
		return 1
	}

	var env vectorgen.UpdateEnvelope
	if err := json.Unmarshal(envBytes, &env); err != nil {
		fmt.Fprintf(os.Stderr, "vectorgen update: parsing envelope: %v\n", err)
		return 1
	}
	env.Overwrite = *overwrite
	env.Partial = *partial

	files, err := expandGlobs([]string{*vectorsGlob})
	if err != nil {
		fmt.Fprintf(os.Stderr, "vectorgen update: %v\n", err)
		return 1
	}

	opts := optionsFor(*schemasDir)
	var succeeded, failed []string
	for _, path := range files {
		if err := vectorgen.Update(path, env, opts); err != nil {
			fmt.Fprintf(os.Stderr, "vectorgen update: %s: %v\n", path, err)
			failed = append(failed, path)
			continue
		}
		succeeded = append(succeeded, path)
	}

	fmt.Fprintf(os.Stderr, "vectorgen update: %d updated, %d failed\n", len(succeeded), len(failed))
	for _, p := range succeeded {
		fmt.Println(p)
	}
	if len(failed) > 0 {
		return 1
	}

	return 0
}
