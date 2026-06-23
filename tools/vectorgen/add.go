package main

import (
	"encoding/json/v2"
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/c2sp/wycheproof/vectorgen"
)

func runAdd(args []string) int {
	fs := flag.NewFlagSet("add", flag.ContinueOnError)
	vectorPath := fs.String("vectors", "", "target vector file (required)")
	input := fs.String("input", "", "envelope JSON file, or '-' for stdin (required)")
	intoGroup := fs.String("into-group", "", "append tests into an existing group (source name, optionally name@version)")
	create := fs.Bool("create", false, "permit creating the target file if it does not exist")
	schemasDir := fs.String("schemas-dir", "", "schema directory (default: embedded)")
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), `Usage: vectorgen add --vectors <file> --input <envelope>|- [flags]

Append a new test group, or new tests into an existing group, to a vector file.
The envelope JSON describes the operation. When the target file does not exist,
--create must be passed (and the envelope must supply algorithm/schema along
with the group/tests).

Envelope fields:
  algorithm     (new file only) the algorithm name
  schema        (new file only) the schema basename, e.g. mldsa_verify_schema.json
  header        (new file only) optional array of header strings
  groupTemplate the new group's object (minus its tests array); required unless --into-group is set
  tests         array of test objects; must not include tcId (the tool assigns them)
  notes         optional notes object to merge into the file's top-level notes

Flags:
`)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *vectorPath == "" || *input == "" {
		fs.Usage()
		return 2
	}

	envBytes, err := readEnvelope(*input)
	if err != nil {
		fmt.Fprintf(os.Stderr, "vectorgen add: %v\n", err)
		return 1
	}

	var env vectorgen.AddEnvelope
	if err := json.Unmarshal(envBytes, &env); err != nil {
		fmt.Fprintf(os.Stderr, "vectorgen add: parsing envelope: %v\n", err)
		return 1
	}
	env.IntoGroup = *intoGroup

	if !*create {
		if _, err := os.Stat(*vectorPath); errors.Is(err, os.ErrNotExist) {
			fmt.Fprintf(os.Stderr, "vectorgen add: %s does not exist; pass --create to create it\n", *vectorPath)
			return 1
		}
	}

	if err := vectorgen.Add(*vectorPath, env, optionsFor(*schemasDir)); err != nil {
		fmt.Fprintf(os.Stderr, "vectorgen add: %v\n", err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "vectorgen add: wrote %s\n", *vectorPath)

	return 0
}
