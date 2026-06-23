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

// TestAddRecreatesPR254Commit2 takes the mlkem_512 file as it stood just
// before PR #254's re-encryption commit (post-ek/K state) and applies the
// envelope distilled from that commit's diff. The result must be
// byte-identical to the committed after-state.
func TestAddRecreatesPR254Commit2(t *testing.T) {
	before, err := os.ReadFile("testdata/add_pr254c2/before.json")
	if err != nil {
		t.Fatal(err)
	}
	envelopeBytes, err := os.ReadFile("testdata/add_pr254c2/envelope.json")
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile("testdata/add_pr254c2/after.json")
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	target := filepath.Join(dir, "mlkem_512_semi_expanded_decaps_test.json")
	if err := os.WriteFile(target, before, 0o644); err != nil {
		t.Fatal(err)
	}

	var env vectorgen.AddEnvelope
	if err := json.Unmarshal(envelopeBytes, &env); err != nil {
		t.Fatalf("parsing envelope: %v", err)
	}

	opts := vectorgen.Options{SchemasFS: os.DirFS("testdata/add_pr254c2")}
	if err := vectorgen.Add(target, env, opts); err != nil {
		t.Fatalf("Add: %v", err)
	}

	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		writeRejForInspection(t, dir, got, want)
		t.Errorf("Add output does not match expected after-state (see %s.{got,want})", target)
	}
}

// TestAddRecreatesPR255 takes an empty workspace and the mldsa_verify_schema
// (from the embedded schemas, which already include it), and recreates the
// new vector file from PR #255 by feeding Add an envelope that bundles the
// file metadata (algorithm, header, schema), notes, group template, and tests.
func TestAddRecreatesPR255(t *testing.T) {
	envelopeBytes, err := os.ReadFile("testdata/add_pr255/envelope.json")
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile("testdata/add_pr255/after.json")
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	target := filepath.Join(dir, "mldsa_87_reduction_omission_verify_test.json")

	var env vectorgen.AddEnvelope
	if err := json.Unmarshal(envelopeBytes, &env); err != nil {
		t.Fatalf("parsing envelope: %v", err)
	}

	if err := vectorgen.Add(target, env, vectorgen.Options{}); err != nil {
		t.Fatalf("Add: %v", err)
	}

	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		writeRejForInspection(t, dir, got, want)
		t.Errorf("Add output does not match expected after-state")
	}
}

// TestAddIntoGroup replays testdata/add_intogroup/envelope.json: a single
// test appended into an existing group identified by its source name. The
// result is asserted byte-equal to the captured after.json (only the matched
// group's tests array grows; the new test gets the next sequential tcId).
func TestAddIntoGroup(t *testing.T) {
	before, err := os.ReadFile("testdata/add_intogroup/before.json")
	if err != nil {
		t.Fatal(err)
	}
	envelopeBytes, err := os.ReadFile("testdata/add_intogroup/envelope.json")
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile("testdata/add_intogroup/after.json")
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	target := filepath.Join(dir, "target.json")
	if err := os.WriteFile(target, before, 0o644); err != nil {
		t.Fatal(err)
	}

	var env vectorgen.AddEnvelope
	if err := json.Unmarshal(envelopeBytes, &env); err != nil {
		t.Fatalf("parsing envelope: %v", err)
	}
	env.IntoGroup = "github/lukaszobernig/reenc"

	opts := vectorgen.Options{SchemasFS: os.DirFS("testdata/add_intogroup")}
	if err := vectorgen.Add(target, env, opts); err != nil {
		t.Fatalf("Add: %v", err)
	}

	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		writeRejForInspection(t, dir, got, want)
		t.Errorf("Add output does not match expected after-state")
	}
}

// TestAddRejectsAmbiguousIntoGroup ensures the tool refuses to silently pick
// one of multiple groups sharing the same source name.
func TestAddRejectsAmbiguousIntoGroup(t *testing.T) {
	// Synthesize a file with two groups under the same source name.
	file := []byte(`{
  "algorithm": "TEST",
  "schema": "nonexistent.json",
  "numberOfTests": 0,
  "notes": {},
  "testGroups": [
    {"type": "T", "source": {"name": "dup", "version": "1"}, "tests": []},
    {"type": "T", "source": {"name": "dup", "version": "2"}, "tests": []}
  ]
}
`)
	dir := t.TempDir()
	target := filepath.Join(dir, "ambig.json")
	if err := os.WriteFile(target, file, 0o644); err != nil {
		t.Fatal(err)
	}
	env := vectorgen.AddEnvelope{
		IntoGroup: "dup",
		Tests:     []jsontext.Value{jsontext.Value(`{"comment": "x"}`)},
	}
	err := vectorgen.Add(target, env, vectorgen.Options{})
	if err == nil {
		t.Fatal("expected error for ambiguous --into-group, got nil")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("matched 2")) {
		t.Errorf("expected ambiguity error, got: %v", err)
	}
}

// TestAddRejectsSuppliedTcId ensures envelope tests carrying a tcId are
// rejected outright rather than silently renumbered.
func TestAddRejectsSuppliedTcId(t *testing.T) {
	env := vectorgen.AddEnvelope{
		IntoGroup: "whatever",
		Tests:     []jsontext.Value{jsontext.Value(`{"tcId": 5, "comment": "x"}`)},
	}
	err := vectorgen.Add(filepath.Join(t.TempDir(), "missing.json"), env, vectorgen.Options{})
	if err == nil {
		t.Fatal("expected tcId rejection, got nil")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("tcId")) {
		t.Errorf("expected tcId rejection, got: %v", err)
	}
}

// TestAddRejectsDuplicateGroup ensures Add refuses to append a group whose
// fields and tests (ignoring tcIds) are identical to an existing group — the
// signature of a generator re-run. The same envelope with a test changed is
// accepted, since same-source groups with differing content are legitimate.
func TestAddRejectsDuplicateGroup(t *testing.T) {
	before, err := os.ReadFile("testdata/add_intogroup/before.json")
	if err != nil {
		t.Fatal(err)
	}
	var root vectorgen.RawObject
	if err := json.Unmarshal(before, &root); err != nil {
		t.Fatal(err)
	}
	rawGroups, ok := root.Get("testGroups")
	if !ok {
		t.Fatal("before.json has no testGroups")
	}
	var groups []jsontext.Value
	if err := json.Unmarshal(rawGroups, &groups); err != nil {
		t.Fatal(err)
	}

	// Rebuild the second group (github/lukaszobernig/reenc, 2 tests) as an
	// add envelope: template = group minus tests, tests = tests minus tcIds.
	var group vectorgen.RawObject
	if err := json.Unmarshal(groups[1], &group); err != nil {
		t.Fatal(err)
	}
	var template vectorgen.RawObject
	var tests []jsontext.Value
	for _, m := range group {
		if m.Name != "tests" {
			template = append(template, m)
			continue
		}
		var groupTests []jsontext.Value
		if err := json.Unmarshal(m.Value, &groupTests); err != nil {
			t.Fatal(err)
		}
		for _, gt := range groupTests {
			var test vectorgen.RawObject
			if err := json.Unmarshal(gt, &test); err != nil {
				t.Fatal(err)
			}
			var stripped vectorgen.RawObject
			for _, tm := range test {
				if tm.Name != "tcId" {
					stripped = append(stripped, tm)
				}
			}
			enc, err := json.Marshal(&stripped)
			if err != nil {
				t.Fatal(err)
			}
			tests = append(tests, jsontext.Value(enc))
		}
	}
	templateVal, err := json.Marshal(&template)
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	target := filepath.Join(dir, "target.json")
	if err := os.WriteFile(target, before, 0o644); err != nil {
		t.Fatal(err)
	}
	opts := vectorgen.Options{SchemasFS: os.DirFS("testdata/add_intogroup")}

	env := vectorgen.AddEnvelope{GroupTemplate: jsontext.Value(templateVal), Tests: tests}
	err = vectorgen.Add(target, env, opts)
	if err == nil {
		t.Fatal("expected duplicate-group error, got nil")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("identical to existing group")) {
		t.Errorf("expected duplicate-group error, got: %v", err)
	}

	// Changing a test's content makes the group acceptable again.
	var first vectorgen.RawObject
	if err := json.Unmarshal(tests[0], &first); err != nil {
		t.Fatal(err)
	}
	first = first.Set("comment", jsontext.Value(`"a distinct comment"`))
	changed, err := json.Marshal(&first)
	if err != nil {
		t.Fatal(err)
	}
	env.Tests[0] = jsontext.Value(changed)
	if err := vectorgen.Add(target, env, opts); err != nil {
		t.Fatalf("Add with differing tests: %v", err)
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(got, []byte(`"numberOfTests": 11,`)) {
		t.Errorf("expected numberOfTests bumped to 11")
	}
}

func writeRejForInspection(t *testing.T, dir string, got, want []byte) {
	t.Helper()
	gp := filepath.Join(dir, "result.got")
	wp := filepath.Join(dir, "result.want")
	_ = os.WriteFile(gp, got, 0o644)
	_ = os.WriteFile(wp, want, 0o644)
	t.Logf("wrote diff artifacts: %s and %s", gp, wp)
}
