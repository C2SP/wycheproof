package vectorgen_test

import (
	"bytes"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"os"
	"path/filepath"
	"testing"

	"github.com/c2sp/wycheproof/vectorgen"
)

// TestReplacePreservesGroupPosition replaces the second group in a two-group
// file. The first group's bytes must remain untouched, and the replacement
// must land at the original group's position (not appended at the end).
func TestReplacePreservesGroupPosition(t *testing.T) {
	before, err := os.ReadFile("testdata/add_intogroup/before.json")
	if err != nil {
		t.Fatal(err)
	}
	envelopeBytes, err := os.ReadFile("testdata/replace_reenc/envelope.json")
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile("testdata/replace_reenc/after.json")
	if err != nil {
		t.Fatal(err)
	}

	tmp := t.TempDir()
	target := filepath.Join(tmp, "target.json")
	if err := os.WriteFile(target, before, 0o644); err != nil {
		t.Fatal(err)
	}

	var env vectorgen.AddEnvelope
	if err := json.Unmarshal(envelopeBytes, &env); err != nil {
		t.Fatalf("parsing envelope: %v", err)
	}

	opts := vectorgen.Options{SchemasFS: os.DirFS("testdata/add_intogroup")}
	filter := vectorgen.ParseSourceFilter("github/lukaszobernig/reenc@1.0")
	if err := vectorgen.Replace(target, env, filter, opts); err != nil {
		t.Fatalf("Replace: %v", err)
	}

	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	// The golden encodes the interesting properties: the replacement group
	// sits at the original group's position (second, after aws-lc), every
	// test is renumbered densely from 1, and numberOfTests reflects the new
	// (smaller) group.
	if !bytes.Equal(got, want) {
		t.Errorf("Replace output does not match expected after-state, file head:\n%s", head(got, 300))
	}
}

// TestReplaceRejectsAmbiguousSource ensures Replace refuses to silently pick
// one of multiple groups sharing the same source name.
func TestReplaceRejectsAmbiguousSource(t *testing.T) {
	file := []byte(`{
  "algorithm": "TEST",
  "schema": "rewrite_schema.json",
  "numberOfTests": 0,
  "notes": {},
  "testGroups": [
    {"type": "RewriteTest", "source": {"name": "dup", "version": "1"}, "tests": []},
    {"type": "RewriteTest", "source": {"name": "dup", "version": "2"}, "tests": []}
  ]
}
`)
	tmp := t.TempDir()
	target := filepath.Join(tmp, "ambig.json")
	if err := os.WriteFile(target, file, 0o644); err != nil {
		t.Fatal(err)
	}
	env := vectorgen.AddEnvelope{
		GroupTemplate: jsontext.Value(`{"type": "RewriteTest", "source": {"name": "dup", "version": "3"}}`),
		Tests:         []jsontext.Value{jsontext.Value(`{"value": "x"}`)},
	}
	opts := vectorgen.Options{SchemasFS: os.DirFS("testdata/update_rewrite")}
	err := vectorgen.Replace(target, env, vectorgen.SourceFilter{Name: "dup"}, opts)
	if err == nil {
		t.Fatal("expected error for ambiguous source")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("matched 2")) {
		t.Errorf("expected ambiguity error, got: %v", err)
	}
}

// TestReplaceRejectsMetadataFields ensures Replace rejects envelopes that
// contain new-file-only metadata (catches operator confusion between add and
// replace).
func TestReplaceRejectsMetadataFields(t *testing.T) {
	dir := "testdata/add_intogroup"
	before, err := os.ReadFile(filepath.Join(dir, "before.json"))
	if err != nil {
		t.Fatal(err)
	}
	tmp := t.TempDir()
	target := filepath.Join(tmp, "target.json")
	if err := os.WriteFile(target, before, 0o644); err != nil {
		t.Fatal(err)
	}
	env := vectorgen.AddEnvelope{
		Algorithm:     "ML-KEM",
		GroupTemplate: jsontext.Value(`{"type": "X"}`),
		Tests:         []jsontext.Value{jsontext.Value(`{"comment": "x"}`)},
	}
	opts := vectorgen.Options{SchemasFS: os.DirFS(dir)}
	err = vectorgen.Replace(target, env, vectorgen.SourceFilter{Name: "github/lukaszobernig/reenc"}, opts)
	if err == nil {
		t.Fatal("expected error for metadata fields in Replace envelope")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("algorithm/schema/header")) {
		t.Errorf("expected error to mention metadata fields, got: %v", err)
	}
}

// TestReplaceRejectsSuppliedTcId ensures Replace envelope tests carrying a
// tcId are rejected, matching Add's contract.
func TestReplaceRejectsSuppliedTcId(t *testing.T) {
	env := vectorgen.AddEnvelope{
		GroupTemplate: jsontext.Value(`{"type": "X"}`),
		Tests:         []jsontext.Value{jsontext.Value(`{"tcId": 1, "comment": "x"}`)},
	}
	err := vectorgen.Replace(filepath.Join(t.TempDir(), "missing.json"), env,
		vectorgen.SourceFilter{Name: "any"}, vectorgen.Options{})
	if err == nil {
		t.Fatal("expected tcId rejection, got nil")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("tcId")) {
		t.Errorf("expected tcId rejection, got: %v", err)
	}
}

func head(b []byte, n int) string {
	if len(b) < n {
		return string(b)
	}
	return string(b[:n])
}
