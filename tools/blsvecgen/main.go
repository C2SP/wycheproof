// blsvecgen generates BLS12-381 test vectors for Wycheproof.
//
// It uses the blst library as the reference implementation and generates
// test vectors for signature verification, aggregate verification,
// and hash-to-curve operations.
package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"math/rand"
	"os"
	"path/filepath"

	blst "github.com/supranational/blst/bindings/go"
)

const (
	sourceVersion = "0.1"
	sourceName    = "c2sp/wycheproof/blsvecgen"
)

// JSON structure types matching the Wycheproof format.

type Source struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type NoteEntry struct {
	BugType     string   `json:"bugType"`
	Description string   `json:"description,omitempty"`
	Effect      string   `json:"effect,omitempty"`
	Links       []string `json:"links,omitempty"`
}

// Signature verification types.

type SigVerifyTestVector struct {
	TcID    int      `json:"tcId"`
	Comment string   `json:"comment"`
	Msg     string   `json:"msg"`
	Sig     string   `json:"sig"`
	Result  string   `json:"result"`
	Flags   []string `json:"flags"`
}

type BlsPublicKey struct {
	PK      string `json:"pk"`
	Group   string `json:"group"`
	KeySize int    `json:"keySize"`
}

type SigVerifyTestGroup struct {
	Type        string                `json:"type"`
	Source      Source                `json:"source"`
	Ciphersuite string               `json:"ciphersuite"`
	PublicKey   BlsPublicKey          `json:"publicKey"`
	Tests       []SigVerifyTestVector `json:"tests"`
}

type SigVerifyFile struct {
	Algorithm     string               `json:"algorithm"`
	Schema        string               `json:"schema"`
	NumberOfTests int                  `json:"numberOfTests"`
	Header        []string             `json:"header"`
	Notes         map[string]NoteEntry `json:"notes"`
	TestGroups    []SigVerifyTestGroup `json:"testGroups"`
}

// Aggregate verification types.

type AggVerifyTestVector struct {
	TcID     int      `json:"tcId"`
	Comment  string   `json:"comment"`
	Pubkeys  []string `json:"pubkeys"`
	Messages []string `json:"messages"`
	Sig      string   `json:"sig"`
	Result   string   `json:"result"`
	Flags    []string `json:"flags"`
}

type AggVerifyTestGroup struct {
	Type        string                `json:"type"`
	Source      Source                `json:"source"`
	Ciphersuite string               `json:"ciphersuite"`
	Tests       []AggVerifyTestVector `json:"tests"`
}

type AggVerifyFile struct {
	Algorithm     string               `json:"algorithm"`
	Schema        string               `json:"schema"`
	NumberOfTests int                  `json:"numberOfTests"`
	Header        []string             `json:"header"`
	Notes         map[string]NoteEntry `json:"notes"`
	TestGroups    []AggVerifyTestGroup `json:"testGroups"`
}

// Hash-to-curve types.

type HashToG2TestVector struct {
	TcID     int      `json:"tcId"`
	Comment  string   `json:"comment"`
	Msg      string   `json:"msg"`
	Expected string   `json:"expected"`
	Result   string   `json:"result"`
	Flags    []string `json:"flags"`
}

type HashToG2TestGroup struct {
	Type   string               `json:"type"`
	Source Source                `json:"source"`
	DST    string               `json:"dst"`
	Tests  []HashToG2TestVector `json:"tests"`
}

type HashToG2File struct {
	Algorithm     string               `json:"algorithm"`
	Schema        string               `json:"schema"`
	NumberOfTests int                  `json:"numberOfTests"`
	Header        []string             `json:"header"`
	Notes         map[string]NoteEntry `json:"notes"`
	TestGroups    []HashToG2TestGroup  `json:"testGroups"`
}

func main() {
	if len(os.Args) < 2 {
		log.Fatal("usage: blsvecgen <output-dir>")
	}
	outDir := os.Args[1]

	log.Println("generating BLS12-381 test vectors...")

	if err := generateMinPKBasicVerify(outDir); err != nil {
		log.Fatalf("min-pk basic verify: %v", err)
	}
	if err := generateMinPKPopVerify(outDir); err != nil {
		log.Fatalf("min-pk pop verify: %v", err)
	}
	if err := generateAggregateVerify(outDir); err != nil {
		log.Fatalf("aggregate verify: %v", err)
	}
	if err := generateHashToG2(outDir); err != nil {
		log.Fatalf("hash-to-g2: %v", err)
	}

	log.Println("done.")
}

func writeJSON(outDir, filename string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	path := filepath.Join(outDir, filename)
	if err := os.WriteFile(path, append(data, '\n'), 0644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	log.Printf("wrote %s (%d bytes)", path, len(data))
	return nil
}

func encHex(b []byte) string {
	return hex.EncodeToString(b)
}

func decHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(fmt.Sprintf("invalid hex: %s", s))
	}
	return b
}

// rng is a deterministic PRNG seeded per generator function.
// This ensures the output is reproducible across runs: same code
// always produces identical test vectors.
var rng *rand.Rand

func initRNG(label string) {
	h := sha256.Sum256([]byte(label))
	seed := int64(binary.BigEndian.Uint64(h[:8]))
	rng = rand.New(rand.NewSource(seed))
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(rng.Intn(256))
	}
	return b
}

// blsFieldPrime returns the BLS12-381 base field modulus p.
func blsFieldPrime() *big.Int {
	p, _ := new(big.Int).SetString(
		"1a0111ea397fe69a4b1ba7b6434bacd7"+
			"64774b84f38512bf6730d2a0f6b0f624"+
			"1eabfffeb153ffffb9feffffffffaaab", 16)
	return p
}

// isG1CurvePoint checks if x³+4 is a quadratic residue mod p
// (i.e., whether a G1 point with this x-coordinate exists).
func isG1CurvePoint(x, p *big.Int) bool {
	rhs := new(big.Int).Exp(x, big.NewInt(3), p)
	rhs.Add(rhs, big.NewInt(4))
	rhs.Mod(rhs, p)
	if rhs.Sign() == 0 {
		return true
	}
	exp := new(big.Int).Sub(p, big.NewInt(1))
	exp.Rsh(exp, 1)
	return new(big.Int).Exp(rhs, exp, p).Cmp(big.NewInt(1)) == 0
}

// encodeCompressedG1 encodes x as a compressed G1 point (48 bytes).
// Sets compression flag; optionally sets sort bit.
func encodeCompressedG1(x *big.Int, sortBit bool) []byte {
	b := make([]byte, 48)
	xBytes := x.Bytes()
	if len(xBytes) > 47 {
		copy(b[1:], xBytes[:47])
	} else {
		copy(b[48-len(xBytes):], xBytes)
	}
	b[0] |= 0x80
	if sortBit {
		b[0] |= 0x20
	}
	return b
}

// findNotOnCurveG1 returns compressed G1 bytes where x is a valid
// field element but x³+4 is not a QR mod p (point not on curve).
func findNotOnCurveG1() []byte {
	p := blsFieldPrime()
	for x := int64(1); x < 10000; x++ {
		bx := big.NewInt(x)
		if !isG1CurvePoint(bx, p) {
			return encodeCompressedG1(bx, false)
		}
	}
	panic("could not find not-on-curve G1 x-coordinate")
}

// findWrongSubgroupG1 returns compressed G1 bytes for a point
// on E(Fp) but not in the prime-order G1 subgroup.
func findWrongSubgroupG1() []byte {
	p := blsFieldPrime()
	for x := int64(0); x < 10000; x++ {
		bx := big.NewInt(x)
		if !isG1CurvePoint(bx, p) {
			continue
		}
		for _, sort := range []bool{false, true} {
			b := encodeCompressedG1(bx, sort)
			pt := new(blst.P1Affine).Uncompress(b)
			if pt != nil && !pt.InG1() {
				return b
			}
		}
	}
	panic("could not find wrong-subgroup G1 point")
}

// findFieldBoundaryG1 returns compressed G1 bytes where x is
// near the field modulus p but not on the curve. Exercises
// field validation boundary conditions.
func findFieldBoundaryG1() []byte {
	p := blsFieldPrime()
	for delta := int64(1); delta < 10000; delta++ {
		x := new(big.Int).Sub(p, big.NewInt(delta))
		if !isG1CurvePoint(x, p) {
			return encodeCompressedG1(x, false)
		}
	}
	panic("could not find field boundary G1 point")
}

// findNotOnCurveG2 returns compressed G2 bytes (96 bytes)
// where the Fp2 x-coordinate is valid but the point is not
// on the G2 twist curve.
func findNotOnCurveG2() []byte {
	for i := byte(1); i < 200; i++ {
		b := make([]byte, 96)
		b[0] = 0x80 // compression flag
		b[95] = i   // x_c0 = i, x_c1 = 0
		pt := new(blst.P2Affine).Uncompress(b)
		if pt == nil {
			return b
		}
	}
	panic("could not find not-on-curve G2 point")
}

// findWrongSubgroupG2 returns compressed G2 bytes for a point
// on the twist curve but not in the prime-order G2 subgroup.
func findWrongSubgroupG2() []byte {
	for i := byte(0); i < 200; i++ {
		for _, sort := range []bool{false, true} {
			b := make([]byte, 96)
			b[0] = 0x80
			if sort {
				b[0] |= 0x20
			}
			b[95] = i
			pt := new(blst.P2Affine).Uncompress(b)
			if pt != nil && !pt.InG2() {
				return b
			}
		}
	}
	panic("could not find wrong-subgroup G2 point")
}

// findFieldBoundaryG2 returns compressed G2 bytes where the
// x-coordinate (Fp2 element) has components near p.
func findFieldBoundaryG2() []byte {
	p := blsFieldPrime()
	// Put p-1 in the c0 component of the Fp2 x-coordinate.
	nearP := new(big.Int).Sub(p, big.NewInt(1))
	nearPBytes := nearP.Bytes()
	b := make([]byte, 96)
	b[0] = 0x80
	// c1 is bytes[1..47], c0 is bytes[48..95]
	copy(b[96-len(nearPBytes):], nearPBytes)
	pt := new(blst.P2Affine).Uncompress(b)
	if pt == nil {
		return b // not on curve with this x, use as negative vector
	}
	// Try with c1 = 1
	b[47] = 0x01
	pt = new(blst.P2Affine).Uncompress(b)
	if pt == nil {
		return b
	}
	panic("could not find field boundary G2 point")
}

// generateKeyPair generates a BLS key pair for min-pk (PK in G1).
func generateKeyPair() (*blst.SecretKey, *blst.P1Affine) {
	ikm := randBytes(32)
	sk := blst.KeyGen(ikm)
	pk := new(blst.P1Affine).From(sk)
	return sk, pk
}

// signMinPK signs a message with min-pk (signature in G2).
func signMinPK(sk *blst.SecretKey, msg []byte, dst string) *blst.P2Affine {
	return new(blst.P2Affine).Sign(sk, msg, []byte(dst))
}

func sigVerifyNotes() map[string]NoteEntry {
	return map[string]NoteEntry{
		"Valid": {
			BugType:     "BASIC",
			Description: "The test vector contains a valid BLS signature.",
		},
		"InvalidSignature": {
			BugType:     "AUTH_BYPASS",
			Description: "The signature is not a valid point or does not verify.",
			Effect:      "Accepting such signatures allows forgery.",
		},
		"WrongMessage": {
			BugType:     "AUTH_BYPASS",
			Description: "The signature was computed over a different message.",
			Effect:      "Accepting such signatures means message integrity is broken.",
		},
		"WrongKey": {
			BugType:     "AUTH_BYPASS",
			Description: "The signature was computed with a different key.",
			Effect:      "Accepting such signatures means authentication is broken.",
		},
		"IdentityPoint": {
			BugType:     "EDGE_CASE",
			Description: "The signature or public key is the identity (point at infinity).",
			Effect:      "The identity point as a signature or key is always invalid per the BLS spec.",
		},
		"NotOnCurve": {
			BugType:     "AUTH_BYPASS",
			Description: "The signature point is not on the curve.",
			Effect:      "Accepting points not on the curve can lead to forgery or subgroup attacks.",
		},
		"NotInSubgroup": {
			BugType:     "AUTH_BYPASS",
			Description: "The signature point is on the curve but not in the prime-order subgroup.",
			Effect:      "Accepting points not in the subgroup enables rogue-key and other attacks.",
			Links:       []string{"https://eprint.iacr.org/2021/323"},
		},
		"SignatureMalleability": {
			BugType:     "SIGNATURE_MALLEABILITY",
			Description: "A modified signature that is mathematically related to a valid one.",
			Effect:      "Signature malleability can break protocols that assume signature uniqueness.",
		},
		"InvalidEncoding": {
			BugType:     "AUTH_BYPASS",
			Description: "The serialized point has an invalid encoding.",
			Effect:      "Accepting invalid encodings may enable various attacks.",
		},
		"TruncatedSignature": {
			BugType:     "AUTH_BYPASS",
			Description: "The signature has been truncated.",
			Effect:      "Accepting truncated signatures likely means signatures can be forged.",
		},
		"EmptyMessage": {
			BugType:     "EDGE_CASE",
			Description: "The message is empty. Valid BLS signatures support empty messages.",
		},
		"LargeMessage": {
			BugType:     "EDGE_CASE",
			Description: "The message is large. Ensures hash-to-curve handles arbitrary length input.",
		},
		"InvalidFlags": {
			BugType:     "AUTH_BYPASS",
			Description: "The serialized point has valid coordinates but incorrect flag bits.",
			Effect:      "Accepting points with wrong flags can bypass validation or produce incorrect points.",
		},
		"FieldBoundary": {
			BugType:     "EDGE_CASE",
			Description: "The x-coordinate is near the field modulus, exercising boundary arithmetic.",
			Effect:      "Implementations with carry propagation bugs may mishandle values near the modulus.",
		},
	}
}

func generateMinPKBasicVerify(outDir string) error {
	initRNG("basicVerify-v1")
	dst := "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_"

	sk, pk := generateKeyPair()
	pkBytes := pk.Compress()

	var groups []SigVerifyTestGroup
	var tests []SigVerifyTestVector
	tcID := 1

	add := func(comment, msg, sig, result string, flags []string) {
		tests = append(tests, SigVerifyTestVector{
			TcID:    tcID,
			Comment: comment,
			Msg:     msg,
			Sig:     sig,
			Result:  result,
			Flags:   flags,
		})
		tcID++
	}

	// 1. Valid signature over a normal message.
	msg1 := randBytes(32)
	sig1 := signMinPK(sk, msg1, dst)
	add("valid signature", encHex(msg1),
		encHex(sig1.Compress()), "valid", []string{"Valid"})

	// 2. Valid signature over empty message.
	sigEmpty := signMinPK(sk, []byte{}, dst)
	add("valid signature over empty message", "",
		encHex(sigEmpty.Compress()), "valid",
		[]string{"Valid", "EmptyMessage"})

	// 3. Valid signature over a large message (1024 bytes).
	msgLarge := randBytes(1024)
	sigLarge := signMinPK(sk, msgLarge, dst)
	add("valid signature over 1024-byte message",
		encHex(msgLarge), encHex(sigLarge.Compress()),
		"valid", []string{"Valid", "LargeMessage"})

	// 4. Wrong message: valid signature but wrong message.
	wrongMsg := randBytes(32)
	add("signature for a different message",
		encHex(wrongMsg), encHex(sig1.Compress()),
		"invalid", []string{"WrongMessage"})

	// 5. All-zero signature (identity point in G2 compressed).
	// The identity/infinity point in compressed G2 is 0xc0 followed by 95 zero bytes.
	identitySigG2 := make([]byte, 96)
	identitySigG2[0] = 0xc0
	add("identity point as signature",
		encHex(msg1), encHex(identitySigG2),
		"invalid", []string{"IdentityPoint"})

	// 6. Truncated signature (only first 48 bytes).
	add("truncated signature",
		encHex(msg1), encHex(sig1.Compress()[:48]),
		"invalid", []string{"TruncatedSignature"})

	// 7. Signature with extra bytes appended.
	sigWithExtra := append(sig1.Compress(), 0x00, 0x01)
	add("signature with extra trailing bytes",
		encHex(msg1), encHex(sigWithExtra),
		"invalid", []string{"InvalidEncoding"})

	// 8. All-zero bytes (not a valid point).
	allZero := make([]byte, 96)
	add("all-zero signature bytes (invalid encoding)",
		encHex(msg1), encHex(allZero),
		"invalid", []string{"InvalidEncoding"})

	// 9. Negated signature (s -> -s, swap the sign bit).
	negSig := make([]byte, 96)
	copy(negSig, sig1.Compress())
	negSig[0] ^= 0x20 // Flip the sign/sort bit for compressed G2
	add("negated valid signature (flipped sign bit)",
		encHex(msg1), encHex(negSig),
		"invalid", []string{"SignatureMalleability"})

	// 10. Coordinate >= field prime p.
	// BLS12-381 field prime p starts with 0x1a0111ea397fe69a4b1ba7b6434bacd7...
	// Setting the x-coordinate to all 0xff (after clearing compression flags) gives x >= p.
	invalidFieldSig := make([]byte, 96)
	for i := range invalidFieldSig {
		invalidFieldSig[i] = 0xff
	}
	// Set compression bit, clear infinity bit
	invalidFieldSig[0] = 0xff // 0b1010... with top bits: compressed=1, infinity=0, sort=1, rest=1...
	// Actually need: compressed (bit 7 of byte 0) = 1, all coordinate bits = 1 => x >= p
	invalidFieldSig[0] = 0xbf // 10111111 - compressed=1, infinity=0, sort=0, rest all 1s
	add("x-coordinate >= field prime",
		encHex(msg1), encHex(invalidFieldSig),
		"invalid", []string{"NotOnCurve"})

	// 11. Valid signature with a second key pair (wrong key).
	sk2, _ := generateKeyPair()
	sig2 := signMinPK(sk2, msg1, dst)
	add("valid signature but wrong public key",
		encHex(msg1), encHex(sig2.Compress()),
		"invalid", []string{"WrongKey"})

	// 12-14. Multiple additional valid messages to ensure basic functionality.
	for i := 0; i < 3; i++ {
		m := randBytes(48)
		s := signMinPK(sk, m, dst)
		add(fmt.Sprintf("valid signature #%d", i+2),
			encHex(m), encHex(s.Compress()),
			"valid", []string{"Valid"})
	}

	// 15. Single-byte messages (edge cases 0x00 through some values).
	for _, b := range []byte{0x00, 0x01, 0xff} {
		m := []byte{b}
		s := signMinPK(sk, m, dst)
		add(fmt.Sprintf("valid signature on single byte 0x%02x", b),
			encHex(m), encHex(s.Compress()),
			"valid", []string{"Valid", "EdgeCase"})
	}

	// --- Additional valid signatures at various message sizes ---
	// These exercise hash-to-curve with different input lengths,
	// catching length-handling bugs and padding issues.
	for _, sz := range []int{2, 4, 8, 16, 64, 128, 256, 512} {
		m := randBytes(sz)
		s := signMinPK(sk, m, dst)
		add(fmt.Sprintf("valid signature on %d-byte message", sz),
			encHex(m), encHex(s.Compress()),
			"valid", []string{"Valid"})
	}

	// Valid signatures on structured messages (non-random patterns).
	{
		// All-zero message.
		m := make([]byte, 32)
		s := signMinPK(sk, m, dst)
		add("valid signature on all-zero 32-byte message",
			encHex(m), encHex(s.Compress()),
			"valid", []string{"Valid"})
	}
	{
		// All-0xff message.
		m := make([]byte, 32)
		for i := range m {
			m[i] = 0xff
		}
		s := signMinPK(sk, m, dst)
		add("valid signature on all-0xff 32-byte message",
			encHex(m), encHex(s.Compress()),
			"valid", []string{"Valid"})
	}
	{
		// Alternating 0xaa pattern.
		m := make([]byte, 32)
		for i := range m {
			m[i] = 0xaa
		}
		s := signMinPK(sk, m, dst)
		add("valid signature on alternating 0xaa pattern",
			encHex(m), encHex(s.Compress()),
			"valid", []string{"Valid"})
	}
	{
		// Alternating 0x55 pattern (complement of 0xaa).
		m := make([]byte, 32)
		for i := range m {
			m[i] = 0x55
		}
		s := signMinPK(sk, m, dst)
		add("valid signature on alternating 0x55 pattern",
			encHex(m), encHex(s.Compress()),
			"valid", []string{"Valid"})
	}
	{
		// ASCII text message.
		m := []byte("BLS12-381 Wycheproof test vector")
		s := signMinPK(sk, m, dst)
		add("valid signature on ASCII text message",
			encHex(m), encHex(s.Compress()),
			"valid", []string{"Valid"})
	}
	{
		// Single-byte 0x80 (high bit set).
		m := []byte{0x80}
		s := signMinPK(sk, m, dst)
		add("valid signature on single byte 0x80",
			encHex(m), encHex(s.Compress()),
			"valid", []string{"Valid", "EdgeCase"})
	}
	{
		// Message = field prime bytes (just a message, not a field elem).
		p := blsFieldPrime()
		m := p.Bytes()
		s := signMinPK(sk, m, dst)
		add("valid signature on message equal to field prime bytes",
			encHex(m), encHex(s.Compress()),
			"valid", []string{"Valid"})
	}

	// Additional valid signatures with different random messages.
	for i := 0; i < 5; i++ {
		m := randBytes(32)
		s := signMinPK(sk, m, dst)
		add(fmt.Sprintf("valid signature (random) #%d", i+5),
			encHex(m), encHex(s.Compress()),
			"valid", []string{"Valid"})
	}

	// --- Flag-targeted vectors (mutation-driven) ---
	// These target specific flag-validation code paths in
	// deserialization (from_compressed_unchecked). Each vector
	// has valid coordinates but exactly one wrong flag bit.
	// Designed to kill mutations replacing & with | in flag
	// parsing logic.

	// 18. Valid G2 sig with compression flag cleared.
	// A compressed G2 point has byte[0] bit 7 = 1.
	// Clearing it produces an invalid encoding.
	noCompressSig := make([]byte, 96)
	copy(noCompressSig, sig1.Compress())
	noCompressSig[0] &= 0x7f // clear compression flag (bit 7)
	add("valid G2 point but compression flag cleared",
		encHex(msg1), encHex(noCompressSig),
		"invalid", []string{"InvalidFlags"})

	// 19. Valid G2 sig with infinity flag set but non-zero x.
	// Infinity flag = bit 6 of byte[0]. Setting it on a
	// non-identity point must be rejected.
	infFlagSig := make([]byte, 96)
	copy(infFlagSig, sig1.Compress())
	infFlagSig[0] |= 0x40 // set infinity flag (bit 6)
	add("valid G2 point but infinity flag set",
		encHex(msg1), encHex(infFlagSig),
		"invalid", []string{"InvalidFlags"})

	// 20. G2 identity with sort flag set.
	// The identity encoding must have sort flag = 0.
	identitySortSig := make([]byte, 96)
	identitySortSig[0] = 0xe0 // compressed=1, infinity=1, sort=1
	add("G2 identity point with sort flag set",
		encHex(msg1), encHex(identitySortSig),
		"invalid", []string{"InvalidFlags"})

	// 21. G2 identity with compression flag cleared.
	// Identity must still have compression flag set in
	// compressed format.
	identityNoCompress := make([]byte, 96)
	identityNoCompress[0] = 0x40 // compressed=0, infinity=1, sort=0
	add("G2 identity with compression flag cleared",
		encHex(msg1), encHex(identityNoCompress),
		"invalid", []string{"InvalidFlags"})

	// 22. Valid G2 point with both infinity and sort flags set.
	// Non-identity point should not have infinity flag.
	bothFlagsSig := make([]byte, 96)
	copy(bothFlagsSig, sig1.Compress())
	bothFlagsSig[0] |= 0x60 // set both infinity (bit 6) and sort (bit 5)
	add("valid G2 point with infinity and sort flags set",
		encHex(msg1), encHex(bothFlagsSig),
		"invalid", []string{"InvalidFlags"})

	// 23. Uncompressed-length encoding with compression flag.
	// 192 bytes (uncompressed G2 size) but compression flag set.
	wrongLenSig := make([]byte, 192)
	copy(wrongLenSig, sig1.Compress())
	// Pad with zeros, keep compression flag — length mismatch.
	add("compressed flag but uncompressed-length encoding",
		encHex(msg1), encHex(wrongLenSig),
		"invalid", []string{"InvalidEncoding"})

	// --- Curve/subgroup validation vectors ---
	// These target the on-curve and subgroup check paths in
	// deserialization. Each has a valid Fp/Fp2 field element
	// but fails a specific geometric check.

	// G2 signature: not on twist curve.
	notOnCurveG2 := findNotOnCurveG2()
	add("G2 point not on the twist curve",
		encHex(msg1), encHex(notOnCurveG2),
		"invalid", []string{"NotOnCurve"})

	// G2 signature: on twist curve but wrong subgroup.
	wrongSubG2 := findWrongSubgroupG2()
	add("G2 point on curve but not in prime-order subgroup",
		encHex(msg1), encHex(wrongSubG2),
		"invalid", []string{"NotInSubgroup"})

	// G2 signature: field boundary (x near modulus p).
	fieldBoundG2 := findFieldBoundaryG2()
	add("G2 x-coordinate near field modulus boundary",
		encHex(msg1), encHex(fieldBoundG2),
		"invalid", []string{"FieldBoundary"})

	// --- Additional invalid signature variations ---
	// Bit-flip corruptions at various byte positions of a valid sig.
	// These catch implementations that don't fully verify signatures.
	for _, pos := range []int{1, 10, 24, 47, 48, 72, 95} {
		corruptSig := make([]byte, 96)
		copy(corruptSig, sig1.Compress())
		corruptSig[pos] ^= 0x01
		add(fmt.Sprintf("valid sig with bit flip at byte %d", pos),
			encHex(msg1), encHex(corruptSig),
			"invalid", []string{"InvalidSignature"})
	}

	// Truncated to various lengths.
	for _, trunc := range []int{1, 47, 48, 95} {
		add(fmt.Sprintf("signature truncated to %d bytes", trunc),
			encHex(msg1), encHex(sig1.Compress()[:trunc]),
			"invalid", []string{"TruncatedSignature"})
	}

	// Empty signature (0 bytes).
	add("empty signature (0 bytes)",
		encHex(msg1), "",
		"invalid", []string{"InvalidEncoding"})

	// Signature with message that differs by 1 bit from msg1.
	{
		flippedMsg := make([]byte, len(msg1))
		copy(flippedMsg, msg1)
		flippedMsg[0] ^= 0x01
		add("valid sig verified against 1-bit-flipped message",
			encHex(flippedMsg), encHex(sig1.Compress()),
			"invalid", []string{"WrongMessage"})
	}
	{
		flippedMsg := make([]byte, len(msg1))
		copy(flippedMsg, msg1)
		flippedMsg[len(flippedMsg)-1] ^= 0x80
		add("valid sig verified against last-bit-flipped message",
			encHex(flippedMsg), encHex(sig1.Compress()),
			"invalid", []string{"WrongMessage"})
	}

	// Message with extra byte appended.
	{
		extMsg := append(append([]byte{}, msg1...), 0x00)
		add("valid sig but message has extra null byte appended",
			encHex(extMsg), encHex(sig1.Compress()),
			"invalid", []string{"WrongMessage"})
	}

	// Message with byte removed.
	{
		shortMsg := msg1[:len(msg1)-1]
		add("valid sig but message has last byte removed",
			encHex(shortMsg), encHex(sig1.Compress()),
			"invalid", []string{"WrongMessage"})
	}

	// Signature = all 0x80 bytes (compression flag in first byte,
	// junk in rest).
	{
		junkSig := make([]byte, 96)
		for i := range junkSig {
			junkSig[i] = 0x80
		}
		add("signature with all bytes 0x80",
			encHex(msg1), encHex(junkSig),
			"invalid", []string{"InvalidEncoding"})
	}

	// Signature > field prime in c1 component (bytes 0..47).
	{
		overflowSig := make([]byte, 96)
		overflowSig[0] = 0x80 // compression flag
		// Set c1 (bytes 1..47) to all 0xff => c1 > p.
		for i := 1; i < 48; i++ {
			overflowSig[i] = 0xff
		}
		add("G2 sig with c1 coordinate >= field prime",
			encHex(msg1), encHex(overflowSig),
			"invalid", []string{"InvalidEncoding"})
	}

	// Multiple wrong-key tests with different key pairs.
	for i := 0; i < 3; i++ {
		skW, _ := generateKeyPair()
		sigW := signMinPK(skW, msg1, dst)
		add(fmt.Sprintf("valid sig from wrong key #%d", i+2),
			encHex(msg1), encHex(sigW.Compress()),
			"invalid", []string{"WrongKey"})
	}

	// Additional not-on-curve G2 points (different x-coordinates).
	for i := byte(2); i <= 10; i++ {
		b := make([]byte, 96)
		b[0] = 0x80
		b[95] = i
		pt := new(blst.P2Affine).Uncompress(b)
		if pt == nil {
			add(fmt.Sprintf(
				"G2 point not on curve (x_c0=%d)", i),
				encHex(msg1), encHex(b),
				"invalid", []string{"NotOnCurve"})
		}
	}

	// Additional not-on-curve G2 with nonzero c1 component.
	{
		b := make([]byte, 96)
		b[0] = 0x80
		b[47] = 0x01 // c1 = 1
		b[95] = 0x01 // c0 = 1
		pt := new(blst.P2Affine).Uncompress(b)
		if pt == nil {
			add("G2 point not on curve (c1=1, c0=1)",
				encHex(msg1), encHex(b),
				"invalid", []string{"NotOnCurve"})
		}
	}

	groups = append(groups, SigVerifyTestGroup{
		Type:        "BlsSigVerify",
		Source:      Source{Name: sourceName, Version: sourceVersion},
		Ciphersuite: dst,
		PublicKey: BlsPublicKey{
			PK:      encHex(pkBytes),
			Group:   "G1",
			KeySize: 48,
		},
		Tests: tests,
	})

	// Second test group: tests with identity public key.
	var identityTests []SigVerifyTestVector
	identityPKG1 := make([]byte, 48)
	identityPKG1[0] = 0xc0 // compressed infinity point in G1
	msgForIdentity := randBytes(32)
	// Generate an arbitrary sig (it won't verify with identity PK).
	sigForIdentity := signMinPK(sk, msgForIdentity, dst)

	identityTests = append(identityTests, SigVerifyTestVector{
		TcID:    tcID,
		Comment: "identity public key must be rejected",
		Msg:     encHex(msgForIdentity),
		Sig:     encHex(sigForIdentity.Compress()),
		Result:  "invalid",
		Flags:   []string{"IdentityPoint"},
	})
	tcID++

	groups = append(groups, SigVerifyTestGroup{
		Type:        "BlsSigVerify",
		Source:      Source{Name: sourceName, Version: sourceVersion},
		Ciphersuite: dst,
		PublicKey: BlsPublicKey{
			PK:      encHex(identityPKG1),
			Group:   "G1",
			KeySize: 48,
		},
		Tests: identityTests,
	})

	// Third test group: public key flag tests (G1 deserialization).
	// These target from_compressed_unchecked flag validation in G1.
	var pkFlagTests []SigVerifyTestVector
	validSigForPKTests := signMinPK(sk, msg1, dst)

	// PK with compression flag cleared.
	noCompressPK := make([]byte, 48)
	copy(noCompressPK, pkBytes)
	noCompressPK[0] &= 0x7f
	pkFlagTests = append(pkFlagTests, SigVerifyTestVector{
		TcID:    tcID,
		Comment: "valid G1 public key but compression flag cleared",
		Msg:     encHex(msg1),
		Sig:     encHex(validSigForPKTests.Compress()),
		Result:  "invalid",
		Flags:   []string{"InvalidFlags"},
	})
	tcID++

	// PK with infinity flag set but non-zero coordinates.
	infFlagPK := make([]byte, 48)
	copy(infFlagPK, pkBytes)
	infFlagPK[0] |= 0x40
	pkFlagTests = append(pkFlagTests, SigVerifyTestVector{
		TcID:    tcID,
		Comment: "valid G1 public key but infinity flag set",
		Msg:     encHex(msg1),
		Sig:     encHex(validSigForPKTests.Compress()),
		Result:  "invalid",
		Flags:   []string{"InvalidFlags"},
	})
	tcID++

	// PK identity with sort flag set.
	identitySortPK := make([]byte, 48)
	identitySortPK[0] = 0xe0
	pkFlagTests = append(pkFlagTests, SigVerifyTestVector{
		TcID:    tcID,
		Comment: "G1 identity public key with sort flag set",
		Msg:     encHex(msg1),
		Sig:     encHex(validSigForPKTests.Compress()),
		Result:  "invalid",
		Flags:   []string{"InvalidFlags"},
	})
	tcID++

	// PK identity with compression flag cleared.
	identityNoCompressPK := make([]byte, 48)
	identityNoCompressPK[0] = 0x40
	pkFlagTests = append(pkFlagTests, SigVerifyTestVector{
		TcID:    tcID,
		Comment: "G1 identity with compression flag cleared",
		Msg:     encHex(msg1),
		Sig:     encHex(validSigForPKTests.Compress()),
		Result:  "invalid",
		Flags:   []string{"InvalidFlags"},
	})
	tcID++

	// PK with both infinity and sort flags on a real point.
	bothFlagsPK := make([]byte, 48)
	copy(bothFlagsPK, pkBytes)
	bothFlagsPK[0] |= 0x60
	pkFlagTests = append(pkFlagTests, SigVerifyTestVector{
		TcID:    tcID,
		Comment: "valid G1 public key with infinity and sort flags set",
		Msg:     encHex(msg1),
		Sig:     encHex(validSigForPKTests.Compress()),
		Result:  "invalid",
		Flags:   []string{"InvalidFlags"},
	})
	tcID++

	groups = append(groups, SigVerifyTestGroup{
		Type:        "BlsSigVerify",
		Source:      Source{Name: sourceName, Version: sourceVersion},
		Ciphersuite: dst,
		PublicKey: BlsPublicKey{
			PK:      encHex(noCompressPK),
			Group:   "G1",
			KeySize: 48,
		},
		Tests: pkFlagTests[:1],
	})

	groups = append(groups, SigVerifyTestGroup{
		Type:        "BlsSigVerify",
		Source:      Source{Name: sourceName, Version: sourceVersion},
		Ciphersuite: dst,
		PublicKey: BlsPublicKey{
			PK:      encHex(infFlagPK),
			Group:   "G1",
			KeySize: 48,
		},
		Tests: pkFlagTests[1:2],
	})

	groups = append(groups, SigVerifyTestGroup{
		Type:        "BlsSigVerify",
		Source:      Source{Name: sourceName, Version: sourceVersion},
		Ciphersuite: dst,
		PublicKey: BlsPublicKey{
			PK:      encHex(identitySortPK),
			Group:   "G1",
			KeySize: 48,
		},
		Tests: pkFlagTests[2:3],
	})

	groups = append(groups, SigVerifyTestGroup{
		Type:        "BlsSigVerify",
		Source:      Source{Name: sourceName, Version: sourceVersion},
		Ciphersuite: dst,
		PublicKey: BlsPublicKey{
			PK:      encHex(identityNoCompressPK),
			Group:   "G1",
			KeySize: 48,
		},
		Tests: pkFlagTests[3:4],
	})

	groups = append(groups, SigVerifyTestGroup{
		Type:        "BlsSigVerify",
		Source:      Source{Name: sourceName, Version: sourceVersion},
		Ciphersuite: dst,
		PublicKey: BlsPublicKey{
			PK:      encHex(bothFlagsPK),
			Group:   "G1",
			KeySize: 48,
		},
		Tests: pkFlagTests[4:5],
	})

	// --- G1 PK curve/subgroup validation vectors ---
	// Each PK is a separate test group since the PK is in
	// the group header.

	addPKGroup := func(pkBytes []byte, comment string, flags []string) {
		groups = append(groups, SigVerifyTestGroup{
			Type:        "BlsSigVerify",
			Source:      Source{Name: sourceName, Version: sourceVersion},
			Ciphersuite: dst,
			PublicKey: BlsPublicKey{
				PK:      encHex(pkBytes),
				Group:   "G1",
				KeySize: 48,
			},
			Tests: []SigVerifyTestVector{{
				TcID:    tcID,
				Comment: comment,
				Msg:     encHex(msg1),
				Sig:     encHex(validSigForPKTests.Compress()),
				Result:  "invalid",
				Flags:   flags,
			}},
		})
		tcID++
	}

	addPKGroup(findNotOnCurveG1(),
		"G1 public key not on the curve",
		[]string{"NotOnCurve"})

	addPKGroup(findWrongSubgroupG1(),
		"G1 public key on curve but not in subgroup",
		[]string{"NotInSubgroup"})

	addPKGroup(findFieldBoundaryG1(),
		"G1 public key with x near field modulus",
		[]string{"FieldBoundary"})

	// Additional not-on-curve G1 PKs (different x-coordinates).
	{
		p := blsFieldPrime()
		count := 0
		for x := int64(1); count < 3 && x < 10000; x++ {
			bx := big.NewInt(x)
			if !isG1CurvePoint(bx, p) {
				count++
				if count > 1 { // skip the first, already used above
					addPKGroup(encodeCompressedG1(bx, false),
						fmt.Sprintf(
							"G1 PK not on curve (x=%d)", x),
						[]string{"NotOnCurve"})
				}
			}
		}
	}

	// Additional field boundary G1 PKs (different deltas from p).
	{
		p := blsFieldPrime()
		count := 0
		for delta := int64(1); count < 3 && delta < 10000; delta++ {
			x := new(big.Int).Sub(p, big.NewInt(delta))
			if !isG1CurvePoint(x, p) {
				count++
				if count > 1 {
					addPKGroup(encodeCompressedG1(x, false),
						fmt.Sprintf(
							"G1 PK near field modulus (p-%d)", delta),
						[]string{"FieldBoundary"})
				}
			}
		}
	}

	// G1 PK with x-coordinate >= field prime (all bits set).
	{
		overflowPK := make([]byte, 48)
		overflowPK[0] = 0xbf // compressed=1, rest all 1s
		for i := 1; i < 48; i++ {
			overflowPK[i] = 0xff
		}
		addPKGroup(overflowPK,
			"G1 PK with x-coordinate >= field prime",
			[]string{"InvalidEncoding"})
	}

	// G1 PK that is all zero (no flags, invalid encoding).
	{
		zeroPK := make([]byte, 48)
		addPKGroup(zeroPK,
			"G1 PK all-zero bytes (no compression flag)",
			[]string{"InvalidEncoding"})
	}

	// G1 PK truncated to 47 bytes.
	{
		truncPK := make([]byte, 47)
		truncPK[0] = 0x80
		groups = append(groups, SigVerifyTestGroup{
			Type:        "BlsSigVerify",
			Source:      Source{Name: sourceName, Version: sourceVersion},
			Ciphersuite: dst,
			PublicKey: BlsPublicKey{
				PK:      encHex(truncPK),
				Group:   "G1",
				KeySize: 48,
			},
			Tests: []SigVerifyTestVector{{
				TcID:    tcID,
				Comment: "G1 PK truncated to 47 bytes",
				Msg:     encHex(msg1),
				Sig:     encHex(validSigForPKTests.Compress()),
				Result:  "invalid",
				Flags:   []string{"InvalidEncoding"},
			}},
		})
		tcID++
	}

	// G1 PK with extra trailing byte (49 bytes).
	{
		extraPK := make([]byte, 49)
		copy(extraPK, pkBytes)
		groups = append(groups, SigVerifyTestGroup{
			Type:        "BlsSigVerify",
			Source:      Source{Name: sourceName, Version: sourceVersion},
			Ciphersuite: dst,
			PublicKey: BlsPublicKey{
				PK:      encHex(extraPK),
				Group:   "G1",
				KeySize: 48,
			},
			Tests: []SigVerifyTestVector{{
				TcID:    tcID,
				Comment: "G1 PK with extra trailing byte (49 bytes)",
				Msg:     encHex(msg1),
				Sig:     encHex(validSigForPKTests.Compress()),
				Result:  "invalid",
				Flags:   []string{"InvalidEncoding"},
			}},
		})
		tcID++
	}

	total := 0
	for _, g := range groups {
		total += len(g.Tests)
	}

	notes := sigVerifyNotes()
	notes["EdgeCase"] = NoteEntry{
		BugType:     "EDGE_CASE",
		Description: "The test vector tests an edge case input.",
	}

	file := SigVerifyFile{
		Algorithm:     "BLS",
		Schema:        "bls_sig_verify_schema_v1.json",
		NumberOfTests: total,
		Header: []string{
			"Test vectors for BLS signature verification using the",
			"min-pk variant (public keys in G1, signatures in G2)",
			"with the Basic scheme (NUL DST).",
			"See draft-irtf-cfrg-bls-signature-06 for specification.",
		},
		Notes:      notes,
		TestGroups: groups,
	}

	return writeJSON(outDir,
		"bls_sig_g2_basic_verify_test.json", file)
}

func generateMinPKPopVerify(outDir string) error {
	initRNG("popVerify-v1")
	dst := "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_"

	sk, pk := generateKeyPair()
	pkBytes := pk.Compress()

	var tests []SigVerifyTestVector
	tcID := 1

	add := func(comment, msg, sig, result string, flags []string) {
		tests = append(tests, SigVerifyTestVector{
			TcID:    tcID,
			Comment: comment,
			Msg:     msg,
			Sig:     sig,
			Result:  result,
			Flags:   flags,
		})
		tcID++
	}

	// Valid signatures with POP scheme.
	for i := 0; i < 5; i++ {
		m := randBytes(32)
		s := signMinPK(sk, m, dst)
		add(fmt.Sprintf("valid POP-scheme signature #%d", i+1),
			encHex(m), encHex(s.Compress()),
			"valid", []string{"Valid"})
	}

	// Empty message.
	sigEmpty := signMinPK(sk, []byte{}, dst)
	add("valid POP-scheme signature on empty message", "",
		encHex(sigEmpty.Compress()), "valid",
		[]string{"Valid", "EmptyMessage"})

	// Cross-scheme: sign with Basic DST, try to verify with POP DST.
	basicDST := "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_"
	msgCross := randBytes(32)
	sigBasic := signMinPK(sk, msgCross, basicDST)
	add("signature from Basic scheme, verified under POP scheme",
		encHex(msgCross), encHex(sigBasic.Compress()),
		"invalid", []string{"WrongDST"})

	// Invalid: identity signature.
	identitySigG2 := make([]byte, 96)
	identitySigG2[0] = 0xc0
	add("identity point as POP-scheme signature",
		encHex(msgCross), encHex(identitySigG2),
		"invalid", []string{"IdentityPoint"})

	// Wrong key.
	sk2, _ := generateKeyPair()
	sig2 := signMinPK(sk2, msgCross, dst)
	add("POP-scheme signature with wrong key",
		encHex(msgCross), encHex(sig2.Compress()),
		"invalid", []string{"WrongKey"})

	// --- Additional POP vectors ---

	// More valid signatures at various message sizes.
	for _, sz := range []int{1, 2, 8, 64, 256, 1024} {
		m := randBytes(sz)
		s := signMinPK(sk, m, dst)
		add(fmt.Sprintf("valid POP sig on %d-byte message", sz),
			encHex(m), encHex(s.Compress()),
			"valid", []string{"Valid"})
	}

	// Valid POP sig on all-zero message.
	{
		m := make([]byte, 32)
		s := signMinPK(sk, m, dst)
		add("valid POP sig on all-zero 32-byte message",
			encHex(m), encHex(s.Compress()),
			"valid", []string{"Valid"})
	}

	// Negated valid POP signature.
	{
		m := randBytes(32)
		s := signMinPK(sk, m, dst)
		negSig := make([]byte, 96)
		copy(negSig, s.Compress())
		negSig[0] ^= 0x20
		add("negated POP-scheme signature (flipped sign bit)",
			encHex(m), encHex(negSig),
			"invalid", []string{"SignatureMalleability"})
	}

	// Truncated POP signature.
	{
		m := randBytes(32)
		s := signMinPK(sk, m, dst)
		add("truncated POP-scheme signature",
			encHex(m), encHex(s.Compress()[:48]),
			"invalid", []string{"TruncatedSignature"})
	}

	// G2 sig not on curve (POP scheme).
	{
		notOnCurve := findNotOnCurveG2()
		add("POP: G2 signature not on the twist curve",
			encHex(msgCross), encHex(notOnCurve),
			"invalid", []string{"NotOnCurve"})
	}

	// G2 sig wrong subgroup (POP scheme).
	{
		wrongSub := findWrongSubgroupG2()
		add("POP: G2 signature on curve but wrong subgroup",
			encHex(msgCross), encHex(wrongSub),
			"invalid", []string{"NotInSubgroup"})
	}

	// POP sig with compression flag cleared.
	{
		m := randBytes(32)
		s := signMinPK(sk, m, dst)
		noCompress := make([]byte, 96)
		copy(noCompress, s.Compress())
		noCompress[0] &= 0x7f
		add("POP sig with compression flag cleared",
			encHex(m), encHex(noCompress),
			"invalid", []string{"InvalidFlags"})
	}

	// POP sig with infinity flag set on non-identity.
	{
		m := randBytes(32)
		s := signMinPK(sk, m, dst)
		infFlag := make([]byte, 96)
		copy(infFlag, s.Compress())
		infFlag[0] |= 0x40
		add("POP sig with infinity flag set on non-identity",
			encHex(m), encHex(infFlag),
			"invalid", []string{"InvalidFlags"})
	}

	// Cross-scheme: sign with aggregate DST.
	{
		aggDST := "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_AUG_"
		m := randBytes(32)
		sigAug := signMinPK(sk, m, aggDST)
		add("signature from AUG scheme, verified under POP scheme",
			encHex(m), encHex(sigAug.Compress()),
			"invalid", []string{"WrongDST"})
	}

	// Bit-flip corruptions of valid POP sig.
	{
		m := randBytes(32)
		s := signMinPK(sk, m, dst)
		for _, pos := range []int{1, 48, 95} {
			corruptSig := make([]byte, 96)
			copy(corruptSig, s.Compress())
			corruptSig[pos] ^= 0x01
			add(fmt.Sprintf(
				"POP sig with bit flip at byte %d", pos),
				encHex(m), encHex(corruptSig),
				"invalid", []string{"InvalidSignature"})
		}
	}

	group := SigVerifyTestGroup{
		Type:        "BlsSigVerify",
		Source:      Source{Name: sourceName, Version: sourceVersion},
		Ciphersuite: dst,
		PublicKey: BlsPublicKey{
			PK:      encHex(pkBytes),
			Group:   "G1",
			KeySize: 48,
		},
		Tests: tests,
	}

	notes := sigVerifyNotes()
	notes["WrongDST"] = NoteEntry{
		BugType:     "AUTH_BYPASS",
		Description: "The signature was produced with a different domain separation tag.",
		Effect:      "Accepting signatures with wrong DST enables cross-protocol attacks.",
		Links:       []string{"https://datatracker.ietf.org/doc/draft-irtf-cfrg-bls-signature/"},
	}

	file := SigVerifyFile{
		Algorithm:     "BLS",
		Schema:        "bls_sig_verify_schema_v1.json",
		NumberOfTests: len(tests),
		Header: []string{
			"Test vectors for BLS signature verification using the",
			"min-pk variant (public keys in G1, signatures in G2)",
			"with the Proof of Possession scheme (POP DST).",
			"See draft-irtf-cfrg-bls-signature-06.",
		},
		Notes:      notes,
		TestGroups: []SigVerifyTestGroup{group},
	}

	return writeJSON(outDir,
		"bls_sig_g2_pop_verify_test.json", file)
}

func generateAggregateVerify(outDir string) error {
	initRNG("aggregateVerify-v1")
	dst := "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_"

	var groups []AggVerifyTestGroup
	var tests []AggVerifyTestVector
	tcID := 1

	add := func(
		comment string, pks, msgs []string,
		sig, result string, flags []string,
	) {
		tests = append(tests, AggVerifyTestVector{
			TcID:     tcID,
			Comment:  comment,
			Pubkeys:  pks,
			Messages: msgs,
			Sig:      sig,
			Result:   result,
			Flags:    flags,
		})
		tcID++
	}

	// Generate 5 key pairs.
	type kp struct {
		sk *blst.SecretKey
		pk *blst.P1Affine
	}
	var keys []kp
	for i := 0; i < 5; i++ {
		s, p := generateKeyPair()
		keys = append(keys, kp{s, p})
	}

	// 1. Valid aggregate: 3 signers, distinct messages.
	{
		var pks []string
		var msgs []string
		var sigs []*blst.P2Affine
		for i := 0; i < 3; i++ {
			m := randBytes(32)
			s := signMinPK(keys[i].sk, m, dst)
			pks = append(pks, encHex(keys[i].pk.Compress()))
			msgs = append(msgs, encHex(m))
			sigs = append(sigs, s)
		}
		agg := aggregateG2Sigs(sigs)
		add("valid aggregate of 3 signatures",
			pks, msgs, encHex(agg), "valid",
			[]string{"ValidAggregate"})
	}

	// 2. Valid aggregate: single signer.
	{
		m := randBytes(32)
		s := signMinPK(keys[0].sk, m, dst)
		add("valid aggregate of 1 signature",
			[]string{encHex(keys[0].pk.Compress())},
			[]string{encHex(m)},
			encHex(s.Compress()),
			"valid", []string{"ValidAggregate"})
	}

	// 3. Valid aggregate: 5 signers.
	{
		var pks []string
		var msgs []string
		var sigs []*blst.P2Affine
		for i := 0; i < 5; i++ {
			m := randBytes(32)
			s := signMinPK(keys[i].sk, m, dst)
			pks = append(pks, encHex(keys[i].pk.Compress()))
			msgs = append(msgs, encHex(m))
			sigs = append(sigs, s)
		}
		agg := aggregateG2Sigs(sigs)
		add("valid aggregate of 5 signatures",
			pks, msgs, encHex(agg), "valid",
			[]string{"ValidAggregate"})
	}

	// 4. Invalid: one signature replaced with wrong signature.
	{
		var pks []string
		var msgs []string
		var sigs []*blst.P2Affine
		for i := 0; i < 3; i++ {
			m := randBytes(32)
			s := signMinPK(keys[i].sk, m, dst)
			pks = append(pks, encHex(keys[i].pk.Compress()))
			msgs = append(msgs, encHex(m))
			sigs = append(sigs, s)
		}
		// Replace last signature with a signature on wrong message.
		wrongMsg := randBytes(32)
		sigs[2] = signMinPK(keys[2].sk, wrongMsg, dst)
		agg := aggregateG2Sigs(sigs)
		add("aggregate with one wrong message",
			pks, msgs, encHex(agg), "invalid",
			[]string{"WrongMessage"})
	}

	// 5. Invalid: mismatched pubkey/message count.
	{
		m := randBytes(32)
		s := signMinPK(keys[0].sk, m, dst)
		add("mismatched pubkey and message count",
			[]string{
				encHex(keys[0].pk.Compress()),
				encHex(keys[1].pk.Compress()),
			},
			[]string{encHex(m)},
			encHex(s.Compress()),
			"invalid", []string{"MismatchedCount"})
	}

	// 6. Invalid: empty lists.
	{
		identitySigG2 := make([]byte, 96)
		identitySigG2[0] = 0xc0
		add("empty aggregate (no signers)",
			[]string{}, []string{},
			encHex(identitySigG2),
			"invalid", []string{"EmptyAggregate"})
	}

	// 7. Invalid: identity signature.
	{
		identitySigG2 := make([]byte, 96)
		identitySigG2[0] = 0xc0
		m := randBytes(32)
		add("identity point as aggregate signature",
			[]string{encHex(keys[0].pk.Compress())},
			[]string{encHex(m)},
			encHex(identitySigG2),
			"invalid", []string{"IdentityPoint"})
	}

	// 8. Invalid: identity public key in aggregate.
	{
		identityPK := make([]byte, 48)
		identityPK[0] = 0xc0
		m1 := randBytes(32)
		m2 := randBytes(32)
		s1 := signMinPK(keys[0].sk, m1, dst)
		// Can't sign with identity key, use any sig.
		s2 := signMinPK(keys[1].sk, m2, dst)
		agg := aggregateG2Sigs([]*blst.P2Affine{s1, s2})
		add("identity public key in aggregate",
			[]string{
				encHex(keys[0].pk.Compress()),
				encHex(identityPK),
			},
			[]string{encHex(m1), encHex(m2)},
			encHex(agg),
			"invalid", []string{"IdentityPoint"})
	}

	// --- Additional aggregate vectors ---

	// Valid aggregate of 2 signers.
	{
		var pks []string
		var msgs []string
		var sigs []*blst.P2Affine
		for i := 0; i < 2; i++ {
			m := randBytes(32)
			s := signMinPK(keys[i].sk, m, dst)
			pks = append(pks, encHex(keys[i].pk.Compress()))
			msgs = append(msgs, encHex(m))
			sigs = append(sigs, s)
		}
		agg := aggregateG2Sigs(sigs)
		add("valid aggregate of 2 signatures",
			pks, msgs, encHex(agg), "valid",
			[]string{"ValidAggregate"})
	}

	// Valid aggregate of 4 signers.
	{
		var pks []string
		var msgs []string
		var sigs []*blst.P2Affine
		for i := 0; i < 4; i++ {
			m := randBytes(32)
			s := signMinPK(keys[i].sk, m, dst)
			pks = append(pks, encHex(keys[i].pk.Compress()))
			msgs = append(msgs, encHex(m))
			sigs = append(sigs, s)
		}
		agg := aggregateG2Sigs(sigs)
		add("valid aggregate of 4 signatures",
			pks, msgs, encHex(agg), "valid",
			[]string{"ValidAggregate"})
	}

	// Valid aggregate with empty messages.
	{
		var pks []string
		var msgs []string
		var sigs []*blst.P2Affine
		for i := 0; i < 2; i++ {
			m := randBytes(32)
			s := signMinPK(keys[i].sk, m, dst)
			pks = append(pks, encHex(keys[i].pk.Compress()))
			msgs = append(msgs, encHex(m))
			sigs = append(sigs, s)
		}
		// Third signer with empty message.
		s := signMinPK(keys[2].sk, []byte{}, dst)
		pks = append(pks, encHex(keys[2].pk.Compress()))
		msgs = append(msgs, "")
		sigs = append(sigs, s)
		agg := aggregateG2Sigs(sigs)
		add("valid aggregate with one empty message",
			pks, msgs, encHex(agg), "valid",
			[]string{"ValidAggregate"})
	}

	// Invalid: wrong key at position 0 (first signer).
	{
		var pks []string
		var msgs []string
		var sigs []*blst.P2Affine
		for i := 0; i < 3; i++ {
			m := randBytes(32)
			s := signMinPK(keys[i].sk, m, dst)
			pks = append(pks, encHex(keys[i].pk.Compress()))
			msgs = append(msgs, encHex(m))
			sigs = append(sigs, s)
		}
		// Replace first key with wrong key.
		pks[0] = encHex(keys[4].pk.Compress())
		agg := aggregateG2Sigs(sigs)
		add("aggregate with wrong key at position 0",
			pks, msgs, encHex(agg), "invalid",
			[]string{"WrongKey"})
	}

	// Invalid: wrong key at middle position.
	{
		var pks []string
		var msgs []string
		var sigs []*blst.P2Affine
		for i := 0; i < 3; i++ {
			m := randBytes(32)
			s := signMinPK(keys[i].sk, m, dst)
			pks = append(pks, encHex(keys[i].pk.Compress()))
			msgs = append(msgs, encHex(m))
			sigs = append(sigs, s)
		}
		pks[1] = encHex(keys[4].pk.Compress())
		agg := aggregateG2Sigs(sigs)
		add("aggregate with wrong key at position 1",
			pks, msgs, encHex(agg), "invalid",
			[]string{"WrongKey"})
	}

	// Invalid: more messages than keys.
	{
		m := randBytes(32)
		s := signMinPK(keys[0].sk, m, dst)
		add("more messages than pubkeys",
			[]string{encHex(keys[0].pk.Compress())},
			[]string{encHex(m), encHex(randBytes(32))},
			encHex(s.Compress()),
			"invalid", []string{"MismatchedCount"})
	}

	// Invalid: not-on-curve aggregate signature.
	{
		notOnCurve := findNotOnCurveG2()
		m := randBytes(32)
		add("aggregate sig that is not on the twist curve",
			[]string{encHex(keys[0].pk.Compress())},
			[]string{encHex(m)},
			encHex(notOnCurve),
			"invalid", []string{"NotOnCurve"})
	}

	// Invalid: truncated aggregate signature.
	{
		m := randBytes(32)
		s := signMinPK(keys[0].sk, m, dst)
		add("truncated aggregate signature (48 bytes)",
			[]string{encHex(keys[0].pk.Compress())},
			[]string{encHex(m)},
			encHex(s.Compress()[:48]),
			"invalid", []string{"TruncatedSignature"})
	}

	// Invalid: not-on-curve PK in aggregate.
	{
		notOnCurvePK := findNotOnCurveG1()
		m1 := randBytes(32)
		m2 := randBytes(32)
		s1 := signMinPK(keys[0].sk, m1, dst)
		s2 := signMinPK(keys[1].sk, m2, dst)
		agg := aggregateG2Sigs([]*blst.P2Affine{s1, s2})
		add("not-on-curve public key in aggregate",
			[]string{
				encHex(keys[0].pk.Compress()),
				encHex(notOnCurvePK),
			},
			[]string{encHex(m1), encHex(m2)},
			encHex(agg),
			"invalid", []string{"NotOnCurve"})
	}

	// Invalid: wrong-subgroup PK in aggregate.
	{
		wrongSubPK := findWrongSubgroupG1()
		m1 := randBytes(32)
		m2 := randBytes(32)
		s1 := signMinPK(keys[0].sk, m1, dst)
		s2 := signMinPK(keys[1].sk, m2, dst)
		agg := aggregateG2Sigs([]*blst.P2Affine{s1, s2})
		add("wrong-subgroup public key in aggregate",
			[]string{
				encHex(keys[0].pk.Compress()),
				encHex(wrongSubPK),
			},
			[]string{encHex(m1), encHex(m2)},
			encHex(agg),
			"invalid", []string{"NotInSubgroup"})
	}

	// Invalid: aggregate sig with compression flag cleared.
	{
		var pks []string
		var msgs []string
		var sigs []*blst.P2Affine
		for i := 0; i < 2; i++ {
			m := randBytes(32)
			s := signMinPK(keys[i].sk, m, dst)
			pks = append(pks, encHex(keys[i].pk.Compress()))
			msgs = append(msgs, encHex(m))
			sigs = append(sigs, s)
		}
		agg := aggregateG2Sigs(sigs)
		aggRaw := make([]byte, len(agg))
		copy(aggRaw, agg)
		aggRaw[0] &= 0x7f // clear compression flag
		add("aggregate sig with compression flag cleared",
			pks, msgs, encHex(aggRaw), "invalid",
			[]string{"InvalidFlags"})
	}

	groups = append(groups, AggVerifyTestGroup{
		Type:        "BlsAggregateVerify",
		Source:      Source{Name: sourceName, Version: sourceVersion},
		Ciphersuite: dst,
		Tests:       tests,
	})

	total := 0
	for _, g := range groups {
		total += len(g.Tests)
	}

	file := AggVerifyFile{
		Algorithm:     "BLS",
		Schema:        "bls_aggregate_verify_schema_v1.json",
		NumberOfTests: total,
		Header: []string{
			"Test vectors for BLS aggregate signature verification",
			"using the min-pk variant (public keys in G1, sigs in G2).",
			"AggregateVerify checks multiple (PK, message) pairs",
			"against a single aggregate signature.",
			"See draft-irtf-cfrg-bls-signature-06, Section 3.3.4.",
		},
		Notes: map[string]NoteEntry{
			"ValidAggregate": {
				BugType:     "BASIC",
				Description: "A valid aggregate signature.",
			},
			"WrongMessage": {
				BugType:     "AUTH_BYPASS",
				Description: "One of the individual signatures was over a wrong message.",
			},
			"MismatchedCount": {
				BugType:     "AUTH_BYPASS",
				Description: "The number of public keys and messages does not match.",
				Effect:      "Implementations must reject when counts differ.",
			},
			"EmptyAggregate": {
				BugType:     "EDGE_CASE",
				Description: "An aggregate with zero signers.",
				Effect:      "The spec says AggregateVerify with n=0 returns INVALID.",
				Links:       []string{"https://datatracker.ietf.org/doc/draft-irtf-cfrg-bls-signature/"},
			},
			"IdentityPoint": {
				BugType:     "EDGE_CASE",
				Description: "The identity point appears in the aggregate.",
				Effect:      "Identity points as signatures or keys must be rejected.",
			},
			"WrongKey": {
				BugType:     "AUTH_BYPASS",
				Description: "One of the public keys does not match the corresponding signer.",
			},
			"NotOnCurve": {
				BugType:     "AUTH_BYPASS",
				Description: "A point in the aggregate is not on the curve.",
				Effect:      "Accepting points not on the curve can lead to forgery.",
			},
			"NotInSubgroup": {
				BugType:     "AUTH_BYPASS",
				Description: "A point in the aggregate is on the curve but not in the subgroup.",
				Effect:      "Accepting wrong-subgroup points enables rogue-key attacks.",
			},
			"TruncatedSignature": {
				BugType:     "AUTH_BYPASS",
				Description: "The aggregate signature has been truncated.",
			},
			"InvalidFlags": {
				BugType:     "AUTH_BYPASS",
				Description: "The aggregate signature has incorrect flag bits.",
			},
		},
		TestGroups: groups,
	}

	return writeJSON(outDir,
		"bls_sig_g2_aggregate_verify_test.json", file)
}

func aggregateG2Sigs(sigs []*blst.P2Affine) []byte {
	if len(sigs) == 0 {
		id := make([]byte, 96)
		id[0] = 0xc0
		return id
	}
	agg := blst.P2AffinesAdd(sigs)
	return agg.ToAffine().Compress()
}

func generateHashToG2(outDir string) error {
	initRNG("hashToG2-v1")
	dst := "QUUX-V01-CS02-with-BLS12381G2_XMD:SHA-256_SSWU_RO_"

	var tests []HashToG2TestVector
	tcID := 1

	add := func(comment, msg, expected string, flags []string) {
		tests = append(tests, HashToG2TestVector{
			TcID:     tcID,
			Comment:  comment,
			Msg:      msg,
			Expected: expected,
			Result:   "valid",
			Flags:    flags,
		})
		tcID++
	}

	// RFC test vectors from draft-irtf-cfrg-hash-to-curve.
	// We compute these using blst to generate reference values.
	testMsgs := []struct {
		name string
		msg  []byte
	}{
		// Canonical edge cases.
		{"empty message", []byte{}},
		{"single byte 0x00", []byte{0x00}},
		{"single byte 0x01", []byte{0x01}},
		{"single byte 0x7f", []byte{0x7f}},
		{"single byte 0x80", []byte{0x80}},
		{"single byte 0xff", []byte{0xff}},

		// ASCII strings.
		{"ascii 'abc'", []byte("abc")},
		{"ascii 'abcdef0123456789'", []byte("abcdef0123456789")},
		{"ascii 'test'", []byte("test")},
		{"ascii 'BLS12-381'", []byte("BLS12-381")},
		{
			"ascii long string",
			[]byte("The quick brown fox jumps over the lazy dog"),
		},

		// Power-of-two message sizes.
		{"2-byte message", randBytes(2)},
		{"4-byte message", randBytes(4)},
		{"8-byte message", randBytes(8)},
		{"16-byte message", randBytes(16)},
		{"32-byte message", randBytes(32)},
		{"64-byte message", randBytes(64)},
		{"128-byte message", randBytes(128)},
		{"256-byte message", randBytes(256)},
		{"512-byte message", randBytes(512)},
		{"1024-byte message", randBytes(1024)},

		// Structured patterns.
		{"all-zero 32 bytes", make([]byte, 32)},
	}

	// All-0xff 32 bytes.
	{
		m := make([]byte, 32)
		for i := range m {
			m[i] = 0xff
		}
		testMsgs = append(testMsgs, struct {
			name string
			msg  []byte
		}{"all-0xff 32 bytes", m})
	}

	// Alternating pattern.
	{
		m := make([]byte, 32)
		for i := range m {
			m[i] = 0xaa
		}
		testMsgs = append(testMsgs, struct {
			name string
			msg  []byte
		}{"alternating 0xaa 32 bytes", m})
	}

	// Counter-style messages (useful for differential testing).
	for i := 0; i < 10; i++ {
		testMsgs = append(testMsgs, struct {
			name string
			msg  []byte
		}{
			fmt.Sprintf("counter message %d", i),
			[]byte(fmt.Sprintf("%d", i)),
		})
	}

	for _, tc := range testMsgs {
		q := blst.HashToG2(tc.msg, []byte(dst)).ToAffine()
		add(tc.name, encHex(tc.msg), encHex(q.Compress()),
			[]string{"HashToG2"})
	}

	group := HashToG2TestGroup{
		Type:   "BlsHashToG2",
		Source: Source{Name: sourceName, Version: sourceVersion},
		DST:    dst,
		Tests:  tests,
	}

	file := HashToG2File{
		Algorithm:     "BLS",
		Schema:        "bls_hash_to_g2_schema_v1.json",
		NumberOfTests: len(tests),
		Header: []string{
			"Test vectors for hash_to_G2 on BLS12-381.",
			"Uses the BLS12381G2_XMD:SHA-256_SSWU_RO_ suite",
			"from draft-irtf-cfrg-hash-to-curve.",
		},
		Notes: map[string]NoteEntry{
			"HashToG2": {
				BugType:     "BASIC",
				Description: "A hash-to-curve test vector.",
				Links:       []string{"https://datatracker.ietf.org/doc/draft-irtf-cfrg-hash-to-curve/"},
			},
		},
		TestGroups: []HashToG2TestGroup{group},
	}

	return writeJSON(outDir,
		"bls_hash_to_g2_test.json", file)
}
