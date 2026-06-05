# ML-DSA

This document explains how to apply Wycheproof test vectors to an ML-DSA
implementation.

> [!TIP]
> This document can double as an LLM "skill" if you ask an agent to apply it.

For each parameter set (ML-DSA-44, ML-DSA-65, ML-DSA-87), there are three test
vector files:

- `testvectors_v1/mldsa_{KL}_sign_noseed_test.json`
- `testvectors_v1/mldsa_{KL}_sign_seed_test.json`
- `testvectors_v1/mldsa_{KL}_verify_test.json`

The `sign_noseed` vectors are for testing implementations that support importing
semi-expanded private keys (which is not recommended and exposes the
implementation to a lot more edge cases). They can be ignored by implementations
that only support "seed" private keys.

### Key generation

Key generation can be tested with the sign vectors, by providing the seed to
ML-DSA.KeyGen_internal, and checking the resulting public key is correct.

### Signing

ML-DSA provides two orthogonal axis over which signing interfaces can vary:

1. deterministic or randomized signing; and
2. (message, context) or precomputed μ signing.

To test deterministic signing interfaces, use vectors without a `rnd` property.

To test randomized signing interfaces, use *both* vectors with a `rnd` property,
and those without, by passing 32 zero bytes as the random value for the latter.

For testing randomized signing interfaces, you can use one of the following
approaches:

1. implement an internal API that accepts (message, context, random) as input;
   or
2. implement an internal API that matches ML-DSA.Sign_internal and convert
   message and context to M'; or
3. intercept the single randomness read from ML-DSA.Sign and feed it with the
   provided random value.

To test precomputed μ ("External Mu") signing interfaces, use the `mu` property
instead of the `msg` and `ctx` properties. To test randomized precomputed μ
signing interfaces, use strategies 1 or 3 above. If precomputed μ signing is not
supported, you can ignore the `mu` property.

Unfortunately, some vectors (with flag `Internal`) only provide `mu` and not
`msg` and `ctx`, so can only be used with precomputed μ signing interfaces.
These vectors were provided by NIST as M' values, without accompanying message
and context, and are particularly hard to recompute.

If you expose the ability to compute μ values, you can test it by taking message
and context from the vectors, and checking the computed μ matches the `mu`
property. If `mu` is missing, the context length is invalid, and computing μ is
expected to fail.

You should also verify all signatures after computing them.

### Verification

Verification can be tested with the verify vectors, by checking that signatures
verify or fail as expected.

## Additional test vectors

CCTV provides [two sets of "accumulated" test vectors](https://github.com/C2SP/CCTV/tree/main/ML-DSA/accumulated).

The first can be used to perform 100 (suitable for interactive testing), 10 000
(suitable for CI), or 60 000 000 (suitable for one-time checks) iterations of
randomized testing of key generation, signing, and verification.

The second can be used to perform *exhaustive* testing of low-level field
operations.
