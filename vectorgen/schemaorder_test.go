package vectorgen

import (
	"os"
	"slices"
	"testing"

	"github.com/c2sp/wycheproof"
)

// TestTestVectorProperties spot-checks the schema-property resolver against
// schemas with different shapes (inline tests.items vs $ref into definitions).
func TestTestVectorProperties(t *testing.T) {
	cases := []struct {
		name   string
		schema string
		want   []string
	}{
		{
			// Two-hop $ref: testGroups.items -> #/definitions/MlDsaVerifyTestGroup,
			// then tests.items -> #/definitions/MlDsaVerifyTestVector.
			name:   "mldsa_verify (embedded, two-hop ref)",
			schema: "mldsa_verify_schema.json",
			want:   []string{"tcId", "comment", "msg", "ctx", "sig", "result", "flags"},
		},
		{
			// Cross-doc ref: tests.items -> signatures_common.json#/definitions/AsnSignatureTestVector
			name:   "ecdsa_verify (cross-doc tests.items ref)",
			schema: "ecdsa_verify_schema_v1.json",
			want:   []string{"tcId", "comment", "msg", "sig", "result", "flags"},
		},
		{
			// Cross-doc ref into mldsa_sign_common.json, which itself uses
			// same-doc refs internally.
			name:   "mldsa_sign_seed (cross-doc tests.items ref)",
			schema: "mldsa_sign_seed_schema.json",
			want:   []string{"tcId", "comment", "msg", "ctx", "rnd", "mu", "sig", "result", "flags"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := testVectorProperties(wycheproof.Schemas, c.schema)
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(got, c.want) {
				t.Errorf("got %v, want %v", got, c.want)
			}
		})
	}

	// Inline-tests.items case: the mlkem semi-expanded decaps schema has its
	// test vector definition inline inside the test-group definition. Uses the
	// post-ek/K schema fixture from the PR #254 testdata.
	t.Run("mlkem (inline tests.items)", func(t *testing.T) {
		got, err := testVectorProperties(
			os.DirFS("testdata/add_pr254c2"),
			"mlkem_semi_expanded_decaps_test_schema.json")
		if err != nil {
			t.Fatal(err)
		}
		want := []string{"tcId", "comment", "dk", "ek", "c", "K", "result", "flags"}
		if !slices.Equal(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})
}
