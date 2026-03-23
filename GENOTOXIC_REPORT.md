# Genotoxic Triage Report: BLS12-381 Wycheproof Test Vectors

## Summary

Mutation testing was performed on three BLS12-381 implementations to measure
the coverage impact of adding Wycheproof test vectors. The goal: determine
whether the new test vectors catch implementation bugs that existing library
tests miss.

| Library | Language | Type | Mutants | Baseline Killed | w/ Wycheproof |
|---------|----------|------|---------|-----------------|---------------|
| gnark-crypto v0.19.2 | Go | Pure impl | 4674 | 820 (100% of covered) | 3353 (87.6% of covered) |
| blst v0.3.16 | Rust | FFI to C | 79 | 0 caught | 0 caught |
| zkcrypto/bls12_381 v0.8.0 | Rust | Pure impl | 1164 | 745 caught | 843 caught |

### Key Findings

- **gnark-crypto BLS-specific files (marshal, pairing, g1, g2, hash_to_g2):**
  Identical results between baseline and Wycheproof — 469 killed, 53 not covered.
  The Wycheproof vectors exercise the same code paths already covered by
  gnark-crypto's own comprehensive test suite.

- **blst Rust crate:** 0% kill rate in both baseline and Wycheproof runs.
  The Rust layer is thin FFI wrappers around C/assembly. Mutations to Rust
  glue code don't affect the C implementation underneath. Mutation testing
  at the Rust binding level is ineffective for this crate.

- **zkcrypto/bls12_381:** 843/1164 caught (72.4%), up from 745 (64.0%).
  **+98 new mutants caught** by Wycheproof vectors with targeted tests
  (roundtrip assertions, negative flag validation, scalar ct_eq/arithmetic).

## zkcrypto/bls12_381: Before/After Comparison

### Per-File Delta

| File | Before Missed | After Missed | Delta | Key Kills |
|------|--------------|-------------|-------|-----------|
| scalar.rs | 35 | 10 | **-25** | ct_eq (`&`→`^`), arithmetic (square, neg, from_bytes) |
| fp.rs | 46 | 31 | **-15** | Roundtrip caught field arithmetic corruption |
| fp2.rs | 12 | 12 | 0 | No change (pow_vartime_extended, sqrt not in deser path) |
| g1.rs | 42 → 59* | 54 | **-5** | All from_compressed_unchecked flag mutations killed |
| g2.rs | 29 → 54* | 54 | **0** | All from_compressed_unchecked flag mutations killed |

*Full file now tested (more mutants in scope).

### What the Wycheproof Tests Caught

**Flag-permissive mutations (P1 — all killed):**
- `G1Affine::from_compressed_unchecked` `&`→`|` (5 mutations): negative
  assertions on invalid flag vectors (tc18-tc29) now reject points with
  wrong compression/infinity/sort bits.
- `G2Affine::from_compressed_unchecked` `&`→`|`: Same pattern, killed by
  same negative assertions on G2 signature vectors.

**Scalar arithmetic (25 killed):**
- `Scalar::ct_eq` `&`→`^` (3 mutations): per-limb inequality tests
- `Scalar::square` shift mutations (15 mutations): `a*a == a.square()`
- `Scalar::neg`, `from_bytes`, `to_bytes`, `Sum`, `Product`

**Field arithmetic via roundtrip (15 killed in fp.rs):**
- `compress(decompress(bytes)) == bytes` catches corruption in y-coordinate
  recovery that involves square root, modular reduction, and negation.

### What Still Survives (and Why)

| Category | Count | Mutations | Root Cause |
|----------|-------|-----------|------------|
| Equivalent mutants | 14 | `square` `\|`→`^` (scalar.rs:5, fp.rs:9) | `(t << 1)` has bit 0=0, so `\|` and `^` with carry bit are identical |
| Formatting | 8 | `fmt::Debug/Display` → `Ok(Default)` | Cosmetic, no behavioral impact |
| Random | 3 | `random` → `Default` | RNG function, not exercised by deterministic tests |
| ct_eq `&`→`\|` | 8 | G1/G2 Affine + Scalar ct_eq | Needs values sharing a Montgomery limb (not reachable via Wycheproof API) |
| subtract_p | 6 | `\|`→`^` in conditional select | Needs values triggering modular reduction with overlapping bits |
| neg zero-mask | 10 | `\|`→`&`/`^` in zero detection | Needs field elements with a zero internal limb |
| Uncompressed deser | 8 | from_uncompressed flag/shift | Wycheproof only tests compressed encoding |
| Optimization paths | ~20 | batch_normalize, wnaf, Sum/Sub | Internal optimization APIs not in BLS verify path |
| from_u768 | 4 | Internal conversion | Not in deserialization path |

### Security Assessment of Remaining Misses

**Equivalent mutants (14):** False positives. The `|`→`^` mutation in the
`square` doubling step cannot change behavior because `(t << 1)` always
clears bit 0, making `| carry` and `^ carry` identical.

**ct_eq `&`→`|` (8):** These ARE security-relevant but not testable through
the Wycheproof API surface. They require constructing two Scalar/Fp values
that differ but share an internal Montgomery limb. Library-internal
property-based tests are the right solution.

**subtract_p / neg (16):** Security-relevant carry propagation bugs, but
triggering them requires specific bit patterns in the internal Montgomery
representation. The roundtrip test catches many corruption paths but not
all. Fuzzing the deserialization path would catch these probabilistically.

## gnark-crypto: Detailed Analysis

### Trailmark Code Graph

```
Functions: 7 (verifier), 13 (generator)
Key functions by cyclomatic complexity:
  Decoder.Decode          CC=76  marshal.go:74
  Encoder.encode          CC=34  marshal.go:480
  G2Affine.setBytes       CC=22  marshal.go:1162
  G1Affine.setBytes       CC=19  marshal.go:895
  verifyAggregate         CC=15  (verifier harness)
  verifySingleSig         CC=11  (verifier harness)
```

### Baseline vs Wycheproof (Full Package)

| Metric | Baseline | w/ Wycheproof | Delta |
|--------|----------|---------------|-------|
| Killed | 820 | 3353 | +2533 |
| Lived | 0 | 476 | +476 |
| Not Covered | 710 | 710 | 0 |
| Timed Out | 3144 | 135 | -3009 |
| Test Efficacy | 100% | 87.57% | -12.43% |
| Mutator Coverage | 53.59% | 84.36% | +30.77% |

**Explanation of the delta:** The Wycheproof test increases total test runtime,
which changes gremlins' timeout calibration. Previously-timed-out mutants now
resolve as either killed (2533) or lived (476). The efficacy drop from 100%
to 87.6% reveals 476 surviving mutants that were hidden behind timeouts.

### BLS-Specific Files: No Change

For the core BLS files (`marshal.go`, `pairing.go`, `g1.go`, `g2.go`,
`hash_to_g2.go`, `bls12-381.go`):

| Category | Count | Files |
|----------|-------|-------|
| Killed | 469 | All BLS files |
| Not Covered | 53 | marshal.go (27), pairing.go (8), g1.go (8), g2.go (8), hash_to_g2 (2) |

The 53 not-covered mutants are identical in both runs. These represent
code paths that neither gnark-crypto's own tests nor the Wycheproof
vectors exercise.

### 53 Not-Covered BLS Mutants (Potential Coverage Gaps)

#### marshal.go (27 mutants)
Lines exercising the `Encoder`/raw encoding paths (lines 117-1343) — these
are the `io.Writer`-based serialization APIs. The Wycheproof vectors test
`SetBytes`/`Bytes` (direct byte slice), not the streaming encoder/decoder.

#### pairing.go (8 mutants)
Lines 352-394 — the `MillerLoop` internal computation paths. The pairing
check goes through `PairingCheck` which wraps these, but the mutations at
these specific arithmetic lines are not covered by any test's execution path.

#### g1.go / g2.go (8 each)
- Lines 68/75: `clearCofactor` boundary checks
- Lines 184/191: `phi` endomorphism arithmetic (used in multi-scalar multiplication)
- Lines 467/472: `batchNormalize` boundary checks

These are optimization paths (endomorphism, batched operations) that the
basic BLS verification flow doesn't exercise.

## blst (Rust): Detailed Analysis

### Baseline: 0 caught, 41 missed, 2 timeout
### With Wycheproof: 0 caught, 39 missed, 2 timeout

The blst Rust crate delegates all cryptographic operations to C via FFI.
Cargo-mutants can only mutate Rust code, making it structurally unable to
test the actual BLS implementation. Notable missed mutants:

| Mutant | Why Missed |
|--------|-----------|
| `PartialEq` for point types → always true/false | Equality checks happen in C |
| `miller_loop_n` arithmetic replacements | Rust wrapper; real logic in C |
| `finalverify → false` | C function does the verification |
| `Pairing::raw_aggregate → ()` | C handles aggregation |

**Recommendation:** Mutation testing blst requires mutating the C source
(`blst/src/*.c`), not the Rust bindings. Use Mull or similar C mutation
framework for meaningful coverage analysis.

## False Positives

| File | Line | Mutation | Reason | Source |
|------|------|----------|--------|--------|
| marshal.go | 117-122 | CONDITIONALS_NEGATION | Encoder path, not used by BLS verify | gnark mutation |
| marshal.go | 316-352 | Various | Streaming encoder, not byte-slice API | gnark mutation |
| marshal.go | 605-767 | Various | G1Affine raw encoding (uncompressed) | gnark mutation |
| marshal.go | 1018-1343 | Various | G2Affine raw encoding + endianness | gnark mutation |
| scalar.rs | 26, 37 | fmt return value | Debug/Display formatting only | zkcrypto mutation |
| scalar.rs | 352-356 | `\|`→`^` in square | Equivalent mutant (bit 0 always 0) | zkcrypto mutation |
| fp.rs | 635-643 | `\|`→`^` in square | Equivalent mutant (same reason) | zkcrypto mutation |
| lib.rs | * (all 39) | Various Rust wrapper mutations | FFI crate, logic in C | blst mutation |

## Missing Test Coverage

| File | Line | Function | CC | Suggested Test | Source |
|------|------|----------|----|----------------|--------|
| g1.go | 68 | clearCofactor | - | Test cofactor clearing with non-trivial cofactor points | gnark mutation |
| g1.go | 184 | phi (endomorphism) | - | Test GLV scalar multiplication edge cases | gnark mutation |
| g2.go | 75, 191 | clearCofactor, phi | - | Same as G1 equivalents | gnark mutation |
| pairing.go | 352-394 | MillerLoop internals | - | Direct miller_loop test with known answer | gnark mutation |
| fp.rs | 371-376 | subtract_p | - | Fuzz decompress with values near p | zkcrypto mutation |
| fp.rs | 406 | neg (zero mask) | - | Test neg with field elements having zero limbs | zkcrypto mutation |
| scalar.rs | 50-52 | ct_eq (`&`→`\|`) | - | Montgomery-aware limb comparison tests | zkcrypto mutation |

## Fuzzing Targets

| File | Function | CC | Rationale | Source |
|------|----------|----|-----------|--------|
| marshal.go:74 | Decoder.Decode | 76 | Highest CC in codebase, handles all point types | gnark graph |
| marshal.go:1162 | G2Affine.setBytes | 22 | Compressed point deser, complex validation | gnark graph |
| marshal.go:895 | G1Affine.setBytes | 19 | Compressed point deser, subgroup check | gnark graph |
| marshal.go:480 | Encoder.encode | 34 | Not covered by any test | gnark graph+mutation |
| fp.rs:371 | subtract_p | - | 6 surviving carry propagation mutations | zkcrypto mutation |
| fp.rs:406 | neg | - | 10 surviving zero-mask mutations | zkcrypto mutation |

## Conclusions

1. **The Wycheproof vectors add no new code coverage to gnark-crypto's BLS
   files.** gnark-crypto already has comprehensive tests for the same paths.
   The value of Wycheproof vectors is cross-implementation validation (catching
   semantic bugs), not code coverage improvement.

2. **The Wycheproof vectors revealed 476 LIVED mutants** by resolving timeouts —
   these are in subpackages (bandersnatch, ecdsa, fflonk, fr) that are
   *indirectly* exercised. This suggests gnark-crypto's own tests for these
   subpackages may have weak assertions.

3. **Mutation testing FFI crates (blst) is ineffective.** The Rust layer is
   structurally unmutatable because the real logic is in C/assembly. C-level
   mutation testing (Mull) would be needed.

4. **Targeted Wycheproof tests killed 98 additional mutants in zkcrypto**
   (745→843, +13.2% improvement). The most impactful additions were:
   - Negative flag assertions (killed all P1 from_compressed_unchecked mutations)
   - Roundtrip compress/decompress checks (killed field arithmetic mutations)
   - Per-limb scalar ct_eq tests (killed `&`→`^` mutations)

5. **14 "survived" mutations in Scalar::square and Fp::square are equivalent
   mutants** — the `|`→`^` change cannot alter behavior because the bit
   being combined is always 0 after a left shift.

6. **The remaining security-relevant gaps** (ct_eq `&`→`|`, subtract_p,
   neg zero-mask) require library-internal tests or fuzzing. They are not
   reachable through the Wycheproof byte-level API because they depend on
   specific internal Montgomery representation bit patterns.

7. **The 53 not-covered BLS mutants in gnark-crypto** are in optimization paths
   (endomorphism, batch normalization, streaming encoder) that BLS signature
   verification doesn't exercise. These represent reasonable fuzzing targets,
   especially `Decoder.Decode` (CC=76).
