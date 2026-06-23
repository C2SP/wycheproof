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

// TestUpdateAddsFields takes the pre-ek/K mlkem_512 file and applies an
// envelope that adds ek to all 7 tests plus K to tcId 1. The expected output
// uses schema-properties order (ek between dk and c; K between c and result),
// which is a different layout than the human-authored PR #254 commit 1, but
// is stable and predictable. The after.json fixture was captured from the
// tool's own output on first run; subsequent runs assert byte-equality.
func TestUpdateAddsFields(t *testing.T) {
	dir := "testdata/update_pr254c1"
	before, err := os.ReadFile(filepath.Join(dir, "before.json"))
	if err != nil {
		t.Fatal(err)
	}
	envelopeBytes, err := os.ReadFile(filepath.Join(dir, "envelope.json"))
	if err != nil {
		t.Fatal(err)
	}

	tmp := t.TempDir()
	target := filepath.Join(tmp, "target.json")
	if err := os.WriteFile(target, before, 0o644); err != nil {
		t.Fatal(err)
	}

	var env vectorgen.UpdateEnvelope
	if err := json.Unmarshal(envelopeBytes, &env); err != nil {
		t.Fatalf("parsing envelope: %v", err)
	}

	opts := vectorgen.Options{SchemasFS: os.DirFS(dir)}
	if err := vectorgen.Update(target, env, opts); err != nil {
		t.Fatalf("Update: %v", err)
	}

	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}

	wantPath := filepath.Join(dir, "after.json")
	want, err := os.ReadFile(wantPath)
	if os.IsNotExist(err) {
		if err := os.WriteFile(wantPath, got, 0o644); err != nil {
			t.Fatal(err)
		}
		t.Fatalf("captured initial expected output at %s; please review and re-run the test", wantPath)
	}
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(got, want) {
		gp := filepath.Join(tmp, "result.got")
		_ = os.WriteFile(gp, got, 0o644)
		t.Errorf("Update output does not match expected; got written to %s", gp)
	}
}

// TestUpdateRejectsOverwriteWithoutFlag asserts that a patch trying to
// replace an existing field's value errors out unless --overwrite is set.
func TestUpdateRejectsOverwriteWithoutFlag(t *testing.T) {
	dir := "testdata/update_pr254c1"
	before, err := os.ReadFile(filepath.Join(dir, "before.json"))
	if err != nil {
		t.Fatal(err)
	}
	tmp := t.TempDir()
	target := filepath.Join(tmp, "target.json")
	if err := os.WriteFile(target, before, 0o644); err != nil {
		t.Fatal(err)
	}

	// Patch tcId 1's "comment" to a different string.
	env := vectorgen.UpdateEnvelope{
		Source: "github/aws/aws-lc",
		Patches: []jsontext.Value{
			jsontext.Value(`{"tcId": 1, "comment": "MODIFIED"}`),
		},
		Partial: true, // we're only patching one of seven
	}
	opts := vectorgen.Options{SchemasFS: os.DirFS(dir)}
	err = vectorgen.Update(target, env, opts)
	if err == nil {
		t.Fatal("expected error for overwrite without --overwrite flag")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("--overwrite")) {
		t.Errorf("expected error to mention --overwrite, got: %v", err)
	}

	// Original must be unchanged.
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, before) {
		t.Error("target file was modified despite overwrite error")
	}
}

// TestUpdateRejectsPartialWithoutFlag asserts that a patch covering only some
// of a group's tests errors out unless --partial is set.
func TestUpdateRejectsPartialWithoutFlag(t *testing.T) {
	dir := "testdata/update_pr254c1"
	before, err := os.ReadFile(filepath.Join(dir, "before.json"))
	if err != nil {
		t.Fatal(err)
	}
	tmp := t.TempDir()
	target := filepath.Join(tmp, "target.json")
	if err := os.WriteFile(target, before, 0o644); err != nil {
		t.Fatal(err)
	}

	env := vectorgen.UpdateEnvelope{
		Source: "github/aws/aws-lc",
		Patches: []jsontext.Value{
			jsontext.Value(`{"tcId": 1, "ek": "deadbeef"}`),
		},
	}
	opts := vectorgen.Options{SchemasFS: os.DirFS(dir)}
	err = vectorgen.Update(target, env, opts)
	if err == nil {
		t.Fatal("expected error for partial update without --partial flag")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("--partial")) {
		t.Errorf("expected error to mention --partial, got: %v", err)
	}
}

// TestUpdateRejectsMissingTcId asserts that a patch referencing a tcId not in
// any matching group is an error.
func TestUpdateRejectsMissingTcId(t *testing.T) {
	dir := "testdata/update_pr254c1"
	before, err := os.ReadFile(filepath.Join(dir, "before.json"))
	if err != nil {
		t.Fatal(err)
	}
	tmp := t.TempDir()
	target := filepath.Join(tmp, "target.json")
	if err := os.WriteFile(target, before, 0o644); err != nil {
		t.Fatal(err)
	}

	env := vectorgen.UpdateEnvelope{
		Source: "github/aws/aws-lc",
		Patches: []jsontext.Value{
			jsontext.Value(`{"tcId": 999, "ek": "deadbeef"}`),
		},
		Partial: true,
	}
	opts := vectorgen.Options{SchemasFS: os.DirFS(dir)}
	err = vectorgen.Update(target, env, opts)
	if err == nil {
		t.Fatal("expected error for patch with nonexistent tcId")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("999")) {
		t.Errorf("expected error to mention tcId 999, got: %v", err)
	}
}

// TestUpdateRewritesExistingValueWithOverwrite covers the "generator-bug
// rewrite" use case: an existing field is rewritten with a new value when
// --overwrite is passed. Uses a self-contained fixture so schema details
// don't get in the way of the semantics under test.
func TestUpdateRewritesExistingValueWithOverwrite(t *testing.T) {
	dir := "testdata/update_rewrite"
	before, err := os.ReadFile(filepath.Join(dir, "before.json"))
	if err != nil {
		t.Fatal(err)
	}
	tmp := t.TempDir()
	target := filepath.Join(tmp, "target.json")
	if err := os.WriteFile(target, before, 0o644); err != nil {
		t.Fatal(err)
	}

	env := vectorgen.UpdateEnvelope{
		Source: "test/rewrite",
		Patches: []jsontext.Value{
			jsontext.Value(`{"tcId": 1, "value": "after"}`),
		},
		Overwrite: true,
		Partial:   true,
	}
	opts := vectorgen.Options{SchemasFS: os.DirFS(dir)}
	if err := vectorgen.Update(target, env, opts); err != nil {
		t.Fatalf("Update: %v", err)
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Count(got, []byte(`"value": "after"`)) != 1 {
		t.Error("expected exactly one occurrence of \"after\" (tcId 1)")
	}
	if bytes.Count(got, []byte(`"value": "before"`)) != 1 {
		t.Error("expected exactly one occurrence of \"before\" (tcId 2 unchanged)")
	}
}
