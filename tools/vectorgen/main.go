// vectorgen is the CLI for adding to and regenerating Wycheproof test vectors.
//
// Requires GOEXPERIMENT=jsonv2 to build.
//
// Subcommands:
//
//	fmt     [--check] <glob>...   Format vector files (or check formatting).
//	lint    [flags]               Validate vector files against their schemas.
//	add     [flags]               Add a new file or group, or append tests into an existing group.
//	update  [flags]               Patch existing tests in place.
//	replace [flags]               Swap a whole group for a fresh one in place.
//	scaffold add [flags]          Emit a placeholder envelope to fill in.
package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"

	"github.com/c2sp/wycheproof/vectorgen"
)

type subCommandHandler = func(args []string) int

var handlers = map[string]subCommandHandler{
	"fmt":      runFmt,
	"lint":     runLint,
	"add":      runAdd,
	"update":   runUpdate,
	"replace":  runReplace,
	"scaffold": runScaffold,
	"h":        helpHandler,
	"help":     helpHandler,
	"--help":   helpHandler,
}

func main() {
	if len(os.Args) < 2 {
		usage(os.Stderr)
		os.Exit(2)
	}

	cmd, args := os.Args[1], os.Args[2:]
	handler, found := handlers[cmd]
	if !found {
		fmt.Fprintf(os.Stderr, "vectorgen: unknown subcommand %q\n\n", cmd)
		usage(os.Stderr)
		os.Exit(2)
	}
	os.Exit(handler(args))
}

func usage(w *os.File) {
	fmt.Fprint(w, `vectorgen — Wycheproof test vector tooling

Usage:
  vectorgen fmt     [--check] <glob>...
  vectorgen lint    [flags]
  vectorgen add     --vectors <file> --input <envelope>|- [flags]
  vectorgen update  --vectors <glob> --input <envelope>|- [flags]
  vectorgen replace --vectors <file> --source <name>[@<v>] --input <envelope>|- [flags]
  vectorgen scaffold add --schema <name> [flags]

Subcommands:
  fmt      Normalize formatting of vector JSON files in place.
           With --check, exit non-zero if any file would be modified.
  lint     Validate vector files against their declared schemas and
           structural invariants.
  add      Append a new test group, or new tests into an existing group,
           per an envelope JSON. Pass --create to allow creating new files.
  update   Patch existing tests in place across one or more files, matching
           tests by tcId within source-filtered groups.
  replace  Swap the single group matching --source for a fresh group from the
           envelope, preserving the original group's position in the file.
  scaffold Emit a placeholder envelope for the given schema, for the
           operator to fill in.

Glob patterns for fmt and update are expanded with Go's filepath.Glob
(shell-style, no recursion).
`)
}

func helpHandler(_ []string) int {
	usage(os.Stdout)
	return 0
}

// readEnvelope reads an envelope JSON from path, or from stdin if path is "-".
func readEnvelope(path string) ([]byte, error) {
	if path == "-" {
		return io.ReadAll(os.Stdin)
	}
	return os.ReadFile(path)
}

// optionsFor returns a vectorgen.Options configured to read schemas from
// schemasDir on disk, or from the embedded FS when schemasDir is empty.
func optionsFor(schemasDir string) vectorgen.Options {
	if schemasDir == "" {
		return vectorgen.Options{}
	}
	return vectorgen.Options{SchemasFS: os.DirFS(schemasDir)}
}

// expandGlobs expands each pattern with filepath.Glob and returns the union,
// sorted. A pattern matching no files is an error (filepath.Glob alone
// reports that as an empty result).
func expandGlobs(patterns []string) ([]string, error) {
	var out []string
	for _, p := range patterns {
		matches, err := filepath.Glob(p)
		if err != nil {
			return nil, fmt.Errorf("glob %q: %w", p, err)
		}
		if len(matches) == 0 {
			return nil, fmt.Errorf("no files matched %q", p)
		}
		out = append(out, matches...)
	}
	slices.Sort(out)

	return out, nil
}
