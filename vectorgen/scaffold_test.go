package vectorgen_test

import (
	"bytes"
	"encoding/json/v2"
	"os"
	"path/filepath"
	"testing"

	"github.com/c2sp/wycheproof/vectorgen"
)

// TestScaffoldAddStructure checks the scaffold output for a known schema
// has the expected top-level keys, placeholder shapes, and schema-derived
// fixed values (type discriminators, schema filename).
func TestScaffoldAddStructure(t *testing.T) {
	out, err := vectorgen.ScaffoldAdd("mac_test_schema_v1.json", vectorgen.Options{})
	if err != nil {
		t.Fatal(err)
	}

	for _, want := range []string{
		`"schema": "mac_test_schema_v1.json"`,
		`"type": "MacTest"`,                      // single-value enum filled in
		`"<one of: valid, invalid, acceptable>"`, // multi-value enum hint
		`"<HexBytes>"`,                           // format hint
		`"name": "<source name>"`,                // Source $ref special-case
		`"version": "<version>"`,                 //   ^
		`"<flag>"`,                               // array-item singular-name trick
	} {
		if !bytes.Contains(out, []byte(want)) {
			t.Errorf("scaffold output missing %q\n--- output ---\n%s", want, out)
		}
	}
}

// TestScaffoldAddRoundTrip exercises the full workflow: scaffold for a
// schema, replace placeholders with real values, feed back to Add, assert
// the resulting file is lint-valid. This is the property the scaffold is
// meant to enable.
func TestScaffoldAddRoundTrip(t *testing.T) {
	scaffold, err := vectorgen.ScaffoldAdd("mac_test_schema_v1.json", vectorgen.Options{})
	if err != nil {
		t.Fatal(err)
	}

	// Operator-style fill-in: substitute the placeholders we know about.
	filled := scaffold
	for _, sub := range []struct{ old, new string }{
		{`"<algorithm>"`, `"HMACSHA256"`},
		{`"<header line>"`, `"scaffold round-trip test"`},
		{`"<source name>"`, `"test/scaffold"`},
		{`"<version>"`, `"1"`},
		{`"<comment>"`, `"empty message"`},
		{`"<HexBytes>"`, `""`},
		{`"<one of: valid, invalid, acceptable>"`, `"valid"`},
		{`"<flag>"`, `"ScaffoldDemo"`},
	} {
		filled = bytes.ReplaceAll(filled, []byte(sub.old), []byte(sub.new))
	}
	// HMAC needs a real key/msg/tag. Just empty values aren't enough — but
	// for the round-trip-validates property, we mostly need the structure to
	// match schema requirements, which empty hex satisfies.
	// keySize/tagSize need real integers.
	filled = bytes.ReplaceAll(filled, []byte(`"keySize": 0`), []byte(`"keySize": 256`))
	filled = bytes.ReplaceAll(filled, []byte(`"tagSize": 0`), []byte(`"tagSize": 256`))

	var env vectorgen.AddEnvelope
	if err := json.Unmarshal(filled, &env); err != nil {
		t.Fatalf("parsing filled scaffold: %v\nfilled:\n%s", err, filled)
	}

	tmp := t.TempDir()
	target := filepath.Join(tmp, "example_test.json")
	if err := vectorgen.Add(target, env, vectorgen.Options{}); err != nil {
		t.Fatalf("Add: %v", err)
	}

	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if err := vectorgen.LintBytes(got, nil); err != nil {
		t.Errorf("scaffold->Add output failed lint: %v", err)
	}
}

// TestScaffoldAddCrossDocRefs verifies that scaffolding succeeds for schemas
// whose test-vector definition lives in a cross-document $ref. Before the
// resolver was extended these would error out; this test guards against
// regression. The 10 schemas listed are every schema in the tree that hits
// the cross-doc path at tests.items.
func TestScaffoldAddCrossDocRefs(t *testing.T) {
	schemas := []string{
		"bls_sig_verify_schema.json",
		"dsa_p1363_verify_schema_v1.json",
		"dsa_verify_schema_v1.json",
		"ecdsa_p1363_verify_schema_v1.json",
		"ecdsa_verify_schema_v1.json",
		"eddsa_verify_schema_v1.json",
		"mldsa_sign_noseed_schema.json",
		"mldsa_sign_seed_schema.json",
		"rsassa_pkcs1_generate_schema_v1.json",
		"rsassa_pkcs1_verify_schema_v1.json",
	}
	for _, s := range schemas {
		t.Run(s, func(t *testing.T) {
			out, err := vectorgen.ScaffoldAdd(s, vectorgen.Options{})
			if err != nil {
				t.Fatalf("ScaffoldAdd: %v", err)
			}
			// Sanity: every cross-doc-resolved test vector defines a tcId
			// (which we skip) plus standard fields. The resolved test object
			// should at minimum contain "msg", "sig", and "result".
			for _, want := range []string{`"msg":`, `"sig":`, `"result":`} {
				if !bytes.Contains(out, []byte(want)) {
					t.Errorf("scaffold for %s missing %q\noutput:\n%s", s, want, out)
				}
			}
		})
	}
}
