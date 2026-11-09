# HPKE

This document explains how to apply Wycheproof test vectors to an
implementation of HPKE ([RFC 9180][]), including its ML-KEM extension
([draft-ietf-hpke-pq-05][]).

The vectors cover only the base mode (`mode_base`), and these KEMs:

- `x25519`: DHKEM(X25519, HKDF-SHA256), KEM id `0x0020`
- `mlkem512`: ML-KEM-512, KEM id `0x0040`
- `mlkem768`: ML-KEM-768, KEM id `0x0041`
- `mlkem1024`: ML-KEM-1024, KEM id `0x0042`

For each KEM, there are three test vector files:

- `testvectors_v1/hpke_{KEM}_encap_test.json`
- `testvectors_v1/hpke_{KEM}_decrypt_test.json`
- `testvectors_v1/hpke_{KEM}_sequence_test.json`

Each test group fixes one ciphersuite, given by its `kemId`, `kdfId`, and
`aeadId`. The schemas describe every property, and the `notes` of each file
explain every flag.

### Encapsulation

Encapsulation can be tested with the encap vectors, by running
`SetupBaseS(pkRm, info)` and then `Seal(aad, pt)`.

For `valid` vectors, this must succeed. If the implementation supports
deterministic encapsulation (see below), check that it produces exactly `enc`
and `ct`; otherwise, check that `enc` and `ct` open to `pt` with `skRm`, when
present. For `invalid` vectors, either importing `pkRm` or `SetupBaseS` must
fail. For `acceptable` vectors, the implementation may fail, but if it
succeeds, the results must be the same as for `valid` vectors.

All encap vectors, including `invalid` ones, carry `ikmE`. If you encapsulate
through a deterministic test hook, check that it rejects `invalid` keys too:
some implementations check the key only on the randomized path.

### Decryption

Decryption can be tested with the decrypt vectors, by running
`SetupBaseR(enc, skRm, info)` and then `Open(aad, ct)`. For `valid` vectors,
this must succeed and return `pt`. For `invalid` vectors, either step must
fail. For `acceptable` vectors, the implementation may fail, but if it
succeeds, it must return `pt`.

Some `valid` ML-KEM vectors (with flags `ImplicitRejection`, `Strcmp`, or
`MalleableCiphertext`) have an `enc` that ML-KEM implicitly rejects, and a
`ct` sealed under the resulting implicit-rejection secret. `Open` must succeed
on them, so an implementation that returns an error on implicit rejection
fails them.

If the API takes `enc` and `ct` as a single buffer, the vectors with flags
`WrongLengthEnc` and `EncTrailingByteInContext` still fail, but no longer
test the `enc` length check.

### Sequential decryption

The sequence vectors test that `Open` is stateful. Run `SetupBaseR` once, then
call `Open` once for each entry of `decryptions`, in order, on the same
context. Each entry must succeed or fail as its `result` says. A failed `Open`
must not advance the sequence number, so the next entry is opened at the same
one.

Implementations that discard the context after any failed `Open` can skip the
vectors with flag `RetryAfterFailedOpen`.

### Deterministic encapsulation

Vectors that were sealed honestly carry `ikmE`, the encapsulation randomness
used in RFC 9180 Appendix A (`EncapDerand` in [draft-ietf-hpke-hpke-05][]):

- for DHKEM(X25519), `ikmE` is the input to `DeriveKeyPair`, and `skEm` is the
  resulting ephemeral private key, for test hooks that take the key directly;
- for ML-KEM, `ikmE` is the randomness `m` passed to
  `ML-KEM.Encaps_internal`, and there is no `skEm`.

If the implementation exposes deterministic encapsulation, run `SetupBaseS`
with `ikmE` (or `skEm`) and `Seal`, and check that the results match `enc`
and `ct`. This also tests the sender side of the decrypt and sequence vectors
that carry `ikmE`.

### X25519 private keys

`skRm` and `skEm` are the 32-byte strings that `DeriveKeyPair` returns, which
are *not* clamped. This matches the values in RFC 9180 Appendix A and
draft-ietf-hpke-hpke-05 Section 7.1.2. (RFC 9180 Section 7.1.2 says the
opposite, which [Erratum 7121][] points out; draft-ietf-hpke-hpke dropped the
clamping requirement in [hpkewg/hpke#42][hpke-clamp].)

X25519 clamps scalars internally, so clamped and unclamped keys behave the
same, but their serializations differ. Some implementations, like Go's
`crypto/hpke` and [rust-hpke][rust-hpke-clamp] since 0.15.0, clamp on
serialization, so compare public keys or decryption results instead of
re-serialized private keys. Other APIs, like wolfSSL's
`wc_curve25519_make_pub`, reject unclamped scalars, so clamp `skRm` and `skEm`
before importing them.

## Not covered

The following are not covered by these vectors:

- the PSK, Auth, and AuthPSK modes;
- other KEMs, including the other DHKEMs and the hybrid KEMs of
  draft-ietf-hpke-pq-05;
- `DeriveKeyPair` from `ikmR`;
- the secret export interface (`Export`);
- `MessageLimitReachedError`, which requires setting the sequence number
  directly.

[RFC 9180]: https://www.rfc-editor.org/rfc/rfc9180
[draft-ietf-hpke-pq-05]: https://datatracker.ietf.org/doc/html/draft-ietf-hpke-pq-05
[draft-ietf-hpke-hpke-05]: https://datatracker.ietf.org/doc/html/draft-ietf-hpke-hpke-05
[Erratum 7121]: https://www.rfc-editor.org/errata/eid7121
[hpke-clamp]: https://github.com/hpkewg/hpke/pull/42
[rust-hpke-clamp]: https://github.com/rozbb/rust-hpke/pull/122
