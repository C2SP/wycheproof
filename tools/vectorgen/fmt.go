package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/c2sp/wycheproof/vectorgen"
)

func runFmt(args []string) int {
	fs := flag.NewFlagSet("fmt", flag.ContinueOnError)
	check := fs.Bool("check", false, "do not modify files; exit non-zero if any file would change")
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), `Usage: vectorgen fmt [--check] <glob>...

Format Wycheproof JSON vector files. The aes_ff1_radix* files are exempt
(their integer-list fields would balloon) and are reported as skipped.

Flags:
`)
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() == 0 {
		fs.Usage()
		return 2
	}

	files, err := expandGlobs(fs.Args())
	if err != nil {
		fmt.Fprintf(os.Stderr, "vectorgen fmt: %v\n", err)
		return 1
	}

	var (
		modified []string
		skipped  []string
		failed   []string
	)
	for _, path := range files {
		if vectorgen.FormatSkipped(path) {
			skipped = append(skipped, path)
			continue
		}

		if *check {
			ok, err := vectorgen.CheckFormatFile(path)
			if err != nil {
				fmt.Fprintf(os.Stderr, "vectorgen fmt: %v\n", err)
				failed = append(failed, path)
				continue
			}
			if !ok {
				modified = append(modified, path)
			}
		} else {
			changed, err := vectorgen.FormatFile(path)
			if err != nil {
				fmt.Fprintf(os.Stderr, "vectorgen fmt: %v\n", err)
				failed = append(failed, path)
				continue
			}
			if changed {
				modified = append(modified, path)
			}
		}
	}

	for _, p := range modified {
		fmt.Println(p)
	}

	if *check {
		if len(failed) > 0 || len(modified) > 0 {
			fmt.Fprintf(os.Stderr, "vectorgen fmt: %d file(s) need formatting, %d error(s), %d skipped\n",
				len(modified), len(failed), len(skipped))
			return 1
		}

		fmt.Fprintf(os.Stderr, "vectorgen fmt: all %d file(s) formatted, %d skipped\n",
			len(files)-len(skipped), len(skipped))
	} else {
		if len(failed) > 0 {
			fmt.Fprintf(os.Stderr, "vectorgen fmt: %d file(s) modified, %d error(s), %d skipped\n",
				len(modified), len(failed), len(skipped))
			return 1
		}
		fmt.Fprintf(os.Stderr, "vectorgen fmt: %d file(s) modified, %d skipped\n",
			len(modified), len(skipped))
	}

	return 0
}
