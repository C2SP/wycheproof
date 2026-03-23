// blsverify-go verifies BLS12-381 Wycheproof test vectors using
// gnark-crypto as an independent implementation from the blst-based
// generator.
package main

import (
	"encoding/hex"
	"encoding/json"
	"log"
	"os"
	"path/filepath"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
)

// JSON types matching the Wycheproof schema.

type SigVerifyFile struct {
	Algorithm  string           `json:"algorithm"`
	Schema     string           `json:"schema"`
	TestGroups []SigVerifyGroup `json:"testGroups"`
}

type SigVerifyGroup struct {
	Type        string `json:"type"`
	Ciphersuite string `json:"ciphersuite"`
	PublicKey   struct {
		PK    string `json:"pk"`
		Group string `json:"group"`
	} `json:"publicKey"`
	Tests []SigVerifyTest `json:"tests"`
}

type SigVerifyTest struct {
	TcID    int      `json:"tcId"`
	Comment string   `json:"comment"`
	Msg     string   `json:"msg"`
	Sig     string   `json:"sig"`
	Result  string   `json:"result"`
	Flags   []string `json:"flags"`
}

type AggVerifyFile struct {
	Algorithm  string           `json:"algorithm"`
	Schema     string           `json:"schema"`
	TestGroups []AggVerifyGroup `json:"testGroups"`
}

type AggVerifyGroup struct {
	Type        string          `json:"type"`
	Ciphersuite string          `json:"ciphersuite"`
	Tests       []AggVerifyTest `json:"tests"`
}

type AggVerifyTest struct {
	TcID     int      `json:"tcId"`
	Comment  string   `json:"comment"`
	Pubkeys  []string `json:"pubkeys"`
	Messages []string `json:"messages"`
	Sig      string   `json:"sig"`
	Result   string   `json:"result"`
	Flags    []string `json:"flags"`
}

type HashToG2File struct {
	Algorithm  string          `json:"algorithm"`
	Schema     string          `json:"schema"`
	TestGroups []HashToG2Group `json:"testGroups"`
}

type HashToG2Group struct {
	Type  string         `json:"type"`
	DST   string         `json:"dst"`
	Tests []HashToG2Test `json:"tests"`
}

type HashToG2Test struct {
	TcID     int      `json:"tcId"`
	Comment  string   `json:"comment"`
	Msg      string   `json:"msg"`
	Expected string   `json:"expected"`
	Result   string   `json:"result"`
	Flags    []string `json:"flags"`
}

func decHex(s string) ([]byte, error) {
	return hex.DecodeString(s)
}

func main() {
	if len(os.Args) < 2 {
		log.Fatal("usage: blsverify-go <vectors-dir>")
	}
	vecDir := os.Args[1]

	var totalFail int

	// Verify signature test vectors (basic + pop, skip aggregate).
	for _, pattern := range []string{
		"bls_sig_g2_basic_verify_test.json",
		"bls_sig_g2_pop_verify_test.json",
	} {
		matches, _ := filepath.Glob(
			filepath.Join(vecDir, pattern))
		for _, f := range matches {
			totalFail += verifySigFile(f)
		}
	}

	// Verify aggregate test vectors.
	aggFiles, _ := filepath.Glob(
		filepath.Join(vecDir, "bls_sig_g2_aggregate_verify_test.json"))
	for _, f := range aggFiles {
		totalFail += verifyAggFile(f)
	}

	// Verify hash-to-curve test vectors.
	h2cFiles, _ := filepath.Glob(
		filepath.Join(vecDir, "bls_hash_to_g2_test.json"))
	for _, f := range h2cFiles {
		totalFail += verifyHashToG2File(f)
	}

	if totalFail > 0 {
		log.Fatalf("FAIL: %d test vectors failed", totalFail)
	}
	log.Println("PASS: all test vectors verified")
}

func verifySigFile(path string) int {
	data, err := os.ReadFile(path)
	if err != nil {
		log.Fatalf("read %s: %v", path, err)
	}

	var file SigVerifyFile
	if err := json.Unmarshal(data, &file); err != nil {
		log.Fatalf("parse %s: %v", path, err)
	}

	log.Printf("verifying %s ...", filepath.Base(path))

	fails := 0
	for _, group := range file.TestGroups {
		pkBytes, err := decHex(group.PublicKey.PK)
		if err != nil {
			for _, tc := range group.Tests {
				if tc.Result == "valid" {
					log.Printf(
						"  FAIL tcId=%d: expected valid but pk is invalid hex",
						tc.TcID)
					fails++
				}
			}
			continue
		}

		for _, tc := range group.Tests {
			ok := verifySingleSig(
				pkBytes, group.Ciphersuite, tc)
			expected := tc.Result == "valid"
			if ok != expected && tc.Result != "acceptable" {
				log.Printf(
					"  FAIL tcId=%d (%s): got=%v want=%s",
					tc.TcID, tc.Comment, ok, tc.Result)
				fails++
			}
		}
	}
	return fails
}

func verifySingleSig(
	pkBytes []byte, ciphersuite string, tc SigVerifyTest,
) bool {
	msgBytes, err := decHex(tc.Msg)
	if err != nil {
		return false
	}
	sigBytes, err := decHex(tc.Sig)
	if err != nil {
		return false
	}

	// Deserialize public key (G1 compressed).
	if len(pkBytes) != 48 {
		return false
	}
	var pk bls12381.G1Affine
	_, err = pk.SetBytes(pkBytes)
	if err != nil {
		return false
	}
	if pk.IsInfinity() {
		return false
	}

	// Deserialize signature (G2 compressed).
	if len(sigBytes) != 96 {
		return false
	}
	var sig bls12381.G2Affine
	_, err = sig.SetBytes(sigBytes)
	if err != nil {
		return false
	}
	if sig.IsInfinity() {
		return false
	}

	// Hash message to G2.
	hm, err := bls12381.HashToG2(msgBytes, []byte(ciphersuite))
	if err != nil {
		return false
	}

	// BLS verify: e(pk, H(m)) * e(-G1, sig) == 1
	_, _, g1Gen, _ := bls12381.Generators()
	var negG1 bls12381.G1Affine
	negG1.Neg(&g1Gen)

	ok, err := bls12381.PairingCheck(
		[]bls12381.G1Affine{pk, negG1},
		[]bls12381.G2Affine{hm, sig},
	)
	if err != nil {
		return false
	}
	return ok
}

func verifyAggFile(path string) int {
	data, err := os.ReadFile(path)
	if err != nil {
		log.Fatalf("read %s: %v", path, err)
	}

	var file AggVerifyFile
	if err := json.Unmarshal(data, &file); err != nil {
		log.Fatalf("parse %s: %v", path, err)
	}

	log.Printf("verifying %s ...", filepath.Base(path))

	fails := 0
	for _, group := range file.TestGroups {
		for _, tc := range group.Tests {
			ok := verifyAggregate(group.Ciphersuite, tc)
			expected := tc.Result == "valid"
			if ok != expected && tc.Result != "acceptable" {
				log.Printf(
					"  FAIL tcId=%d (%s): got=%v want=%s",
					tc.TcID, tc.Comment, ok, tc.Result)
				fails++
			}
		}
	}
	return fails
}

func verifyAggregate(
	ciphersuite string, tc AggVerifyTest,
) bool {
	if len(tc.Pubkeys) != len(tc.Messages) {
		return false
	}
	if len(tc.Pubkeys) == 0 {
		return false
	}

	sigBytes, err := decHex(tc.Sig)
	if err != nil {
		return false
	}
	if len(sigBytes) != 96 {
		return false
	}
	var aggSig bls12381.G2Affine
	_, err = aggSig.SetBytes(sigBytes)
	if err != nil {
		return false
	}
	if aggSig.IsInfinity() {
		return false
	}

	n := len(tc.Pubkeys)
	g1Points := make([]bls12381.G1Affine, n+1)
	g2Points := make([]bls12381.G2Affine, n+1)

	for i := 0; i < n; i++ {
		pkBytes, err := decHex(tc.Pubkeys[i])
		if err != nil {
			return false
		}
		if len(pkBytes) != 48 {
			return false
		}
		_, err = g1Points[i].SetBytes(pkBytes)
		if err != nil {
			return false
		}
		if g1Points[i].IsInfinity() {
			return false
		}

		msgBytes, err := decHex(tc.Messages[i])
		if err != nil {
			return false
		}
		hm, err := bls12381.HashToG2(
			msgBytes, []byte(ciphersuite))
		if err != nil {
			return false
		}
		g2Points[i] = hm
	}

	// Add -G1 * aggSig pairing.
	_, _, g1Gen, _ := bls12381.Generators()
	g1Points[n].Neg(&g1Gen)
	g2Points[n] = aggSig

	ok, err := bls12381.PairingCheck(g1Points, g2Points)
	if err != nil {
		return false
	}
	return ok
}

func verifyHashToG2File(path string) int {
	data, err := os.ReadFile(path)
	if err != nil {
		log.Fatalf("read %s: %v", path, err)
	}

	var file HashToG2File
	if err := json.Unmarshal(data, &file); err != nil {
		log.Fatalf("parse %s: %v", path, err)
	}

	log.Printf("verifying %s ...", filepath.Base(path))

	fails := 0
	for _, group := range file.TestGroups {
		for _, tc := range group.Tests {
			msgBytes, err := decHex(tc.Msg)
			if err != nil {
				log.Printf(
					"  FAIL tcId=%d: invalid msg hex", tc.TcID)
				fails++
				continue
			}
			expectedBytes, err := decHex(tc.Expected)
			if err != nil {
				log.Printf(
					"  FAIL tcId=%d: invalid expected hex", tc.TcID)
				fails++
				continue
			}

			p, err := bls12381.HashToG2(
				msgBytes, []byte(group.DST))
			if err != nil {
				log.Printf(
					"  FAIL tcId=%d: hash_to_g2 error: %v",
					tc.TcID, err)
				fails++
				continue
			}

			got := p.Bytes()
			gotHex := hex.EncodeToString(got[:])
			wantHex := hex.EncodeToString(expectedBytes)
			if gotHex != wantHex {
				log.Printf(
					"  FAIL tcId=%d (%s): hash mismatch",
					tc.TcID, tc.Comment)
				log.Printf("    got:  %s", gotHex)
				log.Printf("    want: %s", wantHex)
				fails++
			}
		}
	}
	return fails
}
