// twistcheck verifies that X25519 and X448 test vectors with twist points are
// correctly marked with the Twist flag. Additionally, the result must be
// "acceptable" since specific implementations may choose to reject twist points.
package main

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"math/big"
	"os"
	"slices"
	"strings"

	"filippo.io/edwards25519/field"
)

var (
	vectorFile = flag.String("vectors", "", "path to test vector file")
)

func main() {
	flag.Parse()

	files := []string{
		"testvectors_v1/x25519_test.json",
		"testvectors_v1/x448_test.json",
		"testvectors_v1/x25519_pem_test.json",
		"testvectors_v1/x448_pem_test.json",
		"testvectors_v1/x25519_jwk_test.json",
		"testvectors_v1/x448_jwk_test.json",
	}
	if *vectorFile != "" {
		files = []string{*vectorFile}
	}

	totalErrors := 0
	for _, file := range files {
		log.Printf("Checking %s...\n", file)
		totalErrors += checkVectorFile(file)
		log.Println()
	}

	if totalErrors > 0 {
		os.Exit(1)
	}
}

func checkVectorFile(filename string) int {
	data, err := os.ReadFile(filename)
	if err != nil {
		panic(fmt.Sprintf("failed to read vector file: %v", err))
	}

	var vectors TestVector
	if err := json.Unmarshal(data, &vectors); err != nil {
		panic(fmt.Sprintf("failed to parse vector JSON: %v", err))
	}

	errors := 0
	for _, group := range vectors.TestGroups {
		for _, test := range group.Tests {

			publicKeyBytes, err := extractPublicKey(test.Public)
			if err != nil || slices.Contains(test.Flags, "InvalidPublic") {
				// Skip test vectors with invalid public keys (different test concern)
				continue
			}

			var expectedLen int
			switch group.Curve {
			case "curve25519":
				expectedLen = 32
			case "curve448":
				expectedLen = 56
			default:
				panic(fmt.Sprintf("unknown curve: %s", group.Curve))
			}

			if len(publicKeyBytes) != expectedLen {
				// Skip test vectors with invalid key lengths (different test concern)
				continue
			}

			isOnTwist, err := isPointOnTwist(publicKeyBytes, group.Curve)
			if err != nil {
				log.Printf("❌ tcId %d: error checking twist: %v", test.TcId, err)
				errors++
				continue
			}

			hasTwistFlag := slices.Contains(test.Flags, "Twist")

			if !isOnTwist && hasTwistFlag {
				log.Printf("❌ tcId %d: point is not on twist but has 'Twist' flag", test.TcId)
				errors++
			} else if isOnTwist && !hasTwistFlag {
				log.Printf("❌ tcId %d: point is on twist but missing 'Twist' flag", test.TcId)
				errors++
			} else if !isOnTwist {
				continue
			}

			if test.Result != "acceptable" {
				log.Printf("❌ tcId %d: point is on twist but result is %q (expected 'acceptable')", test.TcId, test.Result)
				errors++
			}
		}
	}

	log.Printf("Errors: %d\n", errors)
	return errors
}

type TestVector struct {
	TestGroups []TestGroup `json:"testGroups"`
}

type TestGroup struct {
	Curve string     `json:"curve"`
	Tests []TestCase `json:"tests"`
}

type TestCase struct {
	TcId   int             `json:"tcId"`
	Flags  []string        `json:"flags"`
	Public json.RawMessage `json:"public"`
	Result string          `json:"result"`
}

func extractPublicKey(publicRaw json.RawMessage) ([]byte, error) {
	// Try to parse as a plain string (hex or PEM format)
	var publicStr string
	if err := json.Unmarshal(publicRaw, &publicStr); err == nil {
		if strings.HasPrefix(publicStr, "-----BEGIN") {
			return extractFromPEM(publicStr)
		}
		return hex.DecodeString(publicStr)
	}

	// Try to parse as JWK object
	var jwk struct {
		X string `json:"x"`
	}
	if err := json.Unmarshal(publicRaw, &jwk); err == nil && jwk.X != "" {
		return base64.RawURLEncoding.DecodeString(jwk.X)
	}

	return nil, fmt.Errorf("unknown public key format")
}

func extractFromPEM(pemStr string) ([]byte, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	var spki struct {
		Algorithm        pkix.AlgorithmIdentifier
		SubjectPublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(block.Bytes, &spki); err != nil {
		return nil, fmt.Errorf("failed to parse SubjectPublicKeyInfo: %w", err)
	}

	return spki.SubjectPublicKey.Bytes, nil
}

func isPointOnTwist(publicKey []byte, curve string) (bool, error) {
	switch curve {
	case "curve25519":
		return isPointOnTwist25519(publicKey)
	case "curve448":
		return isPointOnTwist448(publicKey)
	default:
		return false, fmt.Errorf("unknown curve: %s", curve)
	}
}

// isPointOnTwist25519 checks if a point is on the twist of Curve25519.
// A point is on the twist if x³ + 486662x² + x is NOT a quadratic residue mod p.
func isPointOnTwist25519(publicKey []byte) (bool, error) {
	x := new(field.Element)
	if _, err := x.SetBytes(publicKey); err != nil {
		return false, fmt.Errorf("invalid field element: %w", err)
	}

	x2 := new(field.Element).Square(x)
	x3 := new(field.Element).Multiply(x2, x)
	ax2 := new(field.Element).Mult32(x2, 486662)
	rhs := new(field.Element).Add(x3, ax2)
	rhs.Add(rhs, x)

	_, wasSquare := new(field.Element).SqrtRatio(rhs, new(field.Element).One())

	return wasSquare == 0, nil
}

// isPointOnTwist448 checks if a point is on the twist of Curve448.
// A point is on the twist if x³ + 156326x² + x is NOT a quadratic residue mod p.
func isPointOnTwist448(publicKey []byte) (bool, error) {
	// Curve448 field: p = 2^448 - 2^224 - 1
	p := new(big.Int).Lsh(big.NewInt(1), 448)
	p.Sub(p, new(big.Int).Lsh(big.NewInt(1), 224))
	p.Sub(p, big.NewInt(1))

	slices.Reverse(publicKey) // Little endian -> Big endian
	x := new(big.Int).SetBytes(publicKey)
	x.Mod(x, p)

	x2 := new(big.Int).Mul(x, x)
	x2.Mod(x2, p)

	x3 := new(big.Int).Mul(x2, x)
	x3.Mod(x3, p)

	a := big.NewInt(156326)
	ax2 := new(big.Int).Mul(a, x2)
	ax2.Mod(ax2, p)

	rhs := new(big.Int).Add(x3, ax2)
	rhs.Add(rhs, x)
	rhs.Mod(rhs, p)

	exp := new(big.Int).Sub(p, big.NewInt(1))
	exp.Div(exp, big.NewInt(2))
	legendre := new(big.Int).Exp(rhs, exp, p)

	// If legendre is 0 or 1, point is on main curve
	if legendre.Cmp(big.NewInt(0)) == 0 || legendre.Cmp(big.NewInt(1)) == 0 {
		return false, nil
	}

	return true, nil
}
