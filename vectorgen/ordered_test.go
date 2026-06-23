package vectorgen

import (
	"bytes"
	"io/fs"
	"strings"
	"testing"

	"github.com/c2sp/wycheproof"
)

// TestRawObjectRoundTripsTree asserts that parsing every non-skipped vector
// file into a RawObject and re-emitting it through marshalObject produces
// byte-identical output.
//
// This is the load-bearing property the ordered helpers must preserve, and the
// foundation of vectorgen.Add / Update / Replace.
func TestRawObjectRoundTripsTree(t *testing.T) {
	var checked, skipped int
	var diverged []string

	err := fs.WalkDir(wycheproof.TestVectors, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".json") {
			return nil
		}
		if FormatSkipped(path) {
			skipped++
			return nil
		}

		orig, err := fs.ReadFile(wycheproof.TestVectors, path)
		if err != nil {
			return err
		}
		obj, err := parseObject(bytes.TrimRight(orig, "\n"))
		if err != nil {
			t.Errorf("%s: parse: %v", path, err)
			return nil
		}
		out, err := marshalObject(obj)
		if err != nil {
			t.Errorf("%s: marshal: %v", path, err)
			return nil
		}

		if !bytes.Equal(orig, out) {
			diverged = append(diverged, path)
		}
		checked++

		return nil
	})
	if err != nil {
		t.Fatalf("walking vectors: %v", err)
	}

	t.Logf("checked %d files, skipped %d", checked, skipped)
	if len(diverged) > 0 {
		t.Errorf("%d files did not round-trip:\n  %s",
			len(diverged), strings.Join(diverged, "\n  "))
	}
}
