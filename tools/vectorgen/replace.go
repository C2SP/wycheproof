package main

import (
	"encoding/json/v2"
	"flag"
	"fmt"
	"os"

	"github.com/c2sp/wycheproof/vectorgen"
)

func runReplace(args []string) int {
	fs := flag.NewFlagSet("replace", flag.ContinueOnError)
	vectorPath := fs.String("vectors", "", "target vector file (required)")
	source := fs.String("source", "", "source filter identifying the group to replace; \"name\" or \"name@version\" (required)")
	input := fs.String("input", "", "envelope JSON file, or '-' for stdin (required)")
	schemasDir := fs.String("schemas-dir", "", "schema directory (default: embedded)")
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), `Usage: vectorgen replace --vectors <file> --source <name>[@<version>] --input <envelope>|- [flags]

Replace the single group matching --source with the new group described by
the envelope. The new group is inserted at the original group's position;
every test in the file is then renumbered sequentially from 1.

Envelope fields: same as 'add' (groupTemplate, tests, notes). The new-file
metadata fields (algorithm, schema, header) must be unset.

Flags:
`)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *vectorPath == "" || *source == "" || *input == "" {
		fs.Usage()
		return 2
	}

	envBytes, err := readEnvelope(*input)
	if err != nil {
		fmt.Fprintf(os.Stderr, "vectorgen replace: %v\n", err)
		return 1
	}
	var env vectorgen.AddEnvelope
	if err := json.Unmarshal(envBytes, &env); err != nil {
		fmt.Fprintf(os.Stderr, "vectorgen replace: parsing envelope: %v\n", err)
		return 1
	}

	if err := vectorgen.Replace(*vectorPath, env, vectorgen.ParseSourceFilter(*source), optionsFor(*schemasDir)); err != nil {
		fmt.Fprintf(os.Stderr, "vectorgen replace: %v\n", err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "vectorgen replace: wrote %s\n", *vectorPath)

	return 0
}
