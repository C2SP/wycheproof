package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/c2sp/wycheproof/vectorgen"
)

func runScaffold(args []string) int {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: vectorgen scaffold <subcommand> [flags]")
		fmt.Fprintln(os.Stderr, "subcommands: add")
		return 2
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "add":
		return runScaffoldAdd(rest)
	default:
		fmt.Fprintf(os.Stderr, "vectorgen scaffold: unknown subcommand %q\n", sub)
		return 2
	}
}

func runScaffoldAdd(args []string) int {
	fs := flag.NewFlagSet("scaffold add", flag.ContinueOnError)
	schema := fs.String("schema", "", "schema basename to scaffold from, e.g. mac_test_schema_v1.json (required)")
	output := fs.String("output", "-", "output file path, or '-' for stdout")
	schemasDir := fs.String("schemas-dir", "", "schema directory (default: embedded)")
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), `Usage: vectorgen scaffold add --schema <name> [flags]

Emit an AddEnvelope JSON skeleton for the given schema. The output is a
placeholder envelope an operator can fill in and feed back to:

  vectorgen add --create --vectors <new-file> --input <envelope>

Constrained fields (enums, formats) carry angle-bracket hints like
"<HexBytes>" or "<one of: valid, invalid, acceptable>" to indicate what to
fill in.

Flags:
`)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *schema == "" {
		fs.Usage()
		return 2
	}

	out, err := vectorgen.ScaffoldAdd(*schema, optionsFor(*schemasDir))
	if err != nil {
		fmt.Fprintf(os.Stderr, "vectorgen scaffold add: %v\n", err)
		return 1
	}

	if *output == "-" {
		_, _ = os.Stdout.Write(out)
		return 0
	}
	if err := os.WriteFile(*output, out, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "vectorgen scaffold add: %v\n", err)
		return 1
	}
	return 0
}
