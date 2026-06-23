// Package vectorgen provides primitives for adding to and regenerating
// Wycheproof test vector files while preserving field order and producing
// minimal diffs.
//
// This package requires the GOEXPERIMENT=jsonv2 build experiment.
package vectorgen

import (
	"bytes"
	"encoding/json/jsontext"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// CheckFormatFile reports whether path is already in canonical formatted form.
// Use FormatFile to actually reformat the file.
func CheckFormatFile(path string) (bool, error) {
	orig, out, err := formatFileContents(path)
	if err != nil {
		return false, err
	}
	return bytes.Equal(orig, out), nil
}

// FormatFile reads path, formats its contents, and writes the result back
// atomically if anything changed. Returns true if the file was modified.
func FormatFile(path string) (bool, error) {
	orig, out, err := formatFileContents(path)
	if err != nil {
		return false, err
	}
	if bytes.Equal(orig, out) {
		return false, nil
	}
	if err := writeAtomic(path, out); err != nil {
		return false, err
	}
	return true, nil
}

// FormatBytes returns the canonical formatted form of a Wycheproof JSON vector
// file's contents. The output ends with a trailing newline.
//
// Formatting preserves existing object key order and the raw byte form of
// scalar values (numbers, strings) — only whitespace is normalized.
func FormatBytes(in []byte) ([]byte, error) {
	v := jsontext.Value(bytes.Clone(bytes.TrimRight(in, "\n")))
	if err := v.Format(
		jsontext.Multiline(true),
		jsontext.WithIndent("  "),
		jsontext.SpaceAfterColon(true),
		jsontext.PreserveRawStrings(true),
		jsontext.CanonicalizeRawInts(false),
		jsontext.CanonicalizeRawFloats(false),
	); err != nil {
		return nil, fmt.Errorf("formatting JSON: %w", err)
	}
	return append([]byte(v), '\n'), nil
}

// formatFileContents reads path and returns (original, formatted) bytes.
func formatFileContents(path string) (orig, out []byte, err error) {
	orig, err = os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	out, err = FormatBytes(orig)
	if err != nil {
		return nil, nil, fmt.Errorf("%s: %w", path, err)
	}
	return orig, out, nil
}

// FormatSkipped reports whether path matches a file pattern that is exempt
// from canonical formatting.
//
// Currently only the aes_ff1_radix*_test.json files are exempt: they contain
// integer-list "msg" and "ct" inputs which the formatter would expand to one
// element per line, ballooning these files. No other vectors in the tree have
// this shape, so the carve-out is intentionally narrow.
func FormatSkipped(path string) bool {
	return strings.HasPrefix(filepath.Base(path), "aes_ff1_radix")
}

func writeAtomic(path string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".vectorgen-*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	renamed := false
	defer func() {
		if !renamed {
			_ = os.Remove(tmp)
		}
	}()

	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	renamed = true
	return nil
}
