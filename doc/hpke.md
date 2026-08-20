# HPKE

Hybrid Public Key Encryption is specified in [RFC 9180][],
and extended by [draft-ietf-hpke-pq][] to post-quantum KEMs.

We include vectors for *only* the base mode and the following *subset* of KEMs:
- ML-KEM-512  (KEM id `0x0040`)
- ML-KEM-768  (KEM id `0x0041`)
- ML-KEM-1024 (KEM id `0x0042`)
- DHKEM(X25519, HKDF-SHA256) (KEM id `0x0020`)

For each of these KEMs, we have two test vector files:

- `hpke_{KEM}_encap_test.json`
- `hpke_{KEM}_decrypt_test.json`

Each test group fixes one HPKE ciphersuite. `kem`, `kdf`, and `aead` give the
human-readable names; `kemId`, `kdfId`, and `aeadId` give the two-byte
identifiers from the IANA HPKE registries. All vectors use base mode
(`mode_base`).

### Encapsulation Test Vectors

The `hpke_{KEM}_encap_test.json` files
(schema [`hpke_encap_test_schema.json`](../schemas/hpke_encap_test_schema.json))
exercise base-mode encapsulation (`SetupBaseS`) and validate the recipient
encapsulation key `pkRm`, the subject of each case. Deserialize `pkRm`, run
`SetupBaseS(pkRm, info)` seeded by `ikmE`, then `Seal(aad, pt)`:

- `valid` succeeds and reproduces `enc` and `ct`. When `skRm` is present, the
  sealed `enc || ct` also opens back to `pt`.
- `invalid` carries a malformed `pkRm` that `SetupBaseS` MUST reject, either at
  key import or at encapsulation (an HPKE `EncapError`); `enc`, `ct`, and `pt`
  are empty.

The reject reason is KEM-specific:

- **ML-KEM**: the encapsulation-key check (FIPS 203 Section 7.2) rejects a
  coefficient at or past the modulus, or the key has the wrong length. An
  all-zero ML-KEM key is `valid` — every coefficient is 0, below the modulus,
  so the check passes and `SetupBaseS` must succeed; rejecting it is
  over-strict.
- **DHKEM(X25519)**: HPKE is stricter than plain X25519 here. A small-order
  `pkRm` whose Diffie-Hellman output is all-zero MUST be rejected, because
  RFC 9180 Section 5.1.1 requires `DH` to abort on an all-zero shared secret —
  a check RFC 7748 leaves optional (`x25519_test.json` labels such keys
  `acceptable`). Wrong-length keys are rejected too.

The ML-KEM encapsulation files are a single-implementation canary: among the
implementations used to cross-validate these vectors, only AWS-LC implements
ML-KEM in HPKE.

| Field  | Meaning |
| ------ | ------- |
| `pkRm` | Recipient encapsulation key under test; malformed for `invalid` cases. |
| `ikmE` | Optional. Sender encapsulation randomness; present for `valid` cases so encapsulation is deterministic. |
| `skRm` | Optional. Recipient private key matching `pkRm`, when one exists; lets a consumer additionally open `enc \|\| ct` back to `pt`. |
| `info` | HPKE info string bound into the key schedule. |
| `aad`  | Additional authenticated data passed to `Seal`. |
| `pt`   | Plaintext sealed for `valid` cases; empty otherwise. |
| `enc`  | KEM encapsulated key for `valid` cases; empty otherwise. |
| `ct`   | AEAD sealed message (ciphertext `\|\|` tag) for `valid` cases; empty otherwise. |

### Decryption Test Vectors

The `hpke_{KEM}_decrypt_test.json` files
(schema [`hpke_decrypt_test_schema.json`](../schemas/hpke_decrypt_test_schema.json))
exercise single-shot `Open` in base mode. Each case carries `info`, `aad`,
`enc` (the KEM encapsulated key), `ct` (AEAD ciphertext followed by tag), and
`pt`. Run `SetupBaseR(enc, skR, info)` then `Open(aad, ct)`:

- `valid` recovers exactly `pt`.
- `invalid` fails, with empty `pt`. The KEM rejects a wrong-length `enc` (and,
  for DHKEM(X25519), a small-order `enc`; see
  [Encapsulation Test Vectors](#encapsulation-test-vectors)). Otherwise a
  tampered `enc`, `ct`, `aad`, or `info` fails at the AEAD tag: a modified
  `enc` yields a different shared secret — ML-KEM implicit rejection, or a
  different DHKEM ephemeral — so `Open` still fails at the tag.

An implementation that keeps `enc` and `ct` as one blob concatenates
`enc || ct`; one with a separate setup/open API passes them individually.

`skRm` is the serialized recipient private key (`SerializePrivateKey`): the
64-byte `d || z` seed for the ML-KEM KEMs (`Nsk = 64`, the expanded key
re-derived via `ML-KEM.KeyGen_internal`), and the 32-byte scalar for
DHKEM(X25519) (`Nsk = 32`). `pkRm` is the serialized public (encapsulation)
key; it can also be derived from `skRm`.

Valid decryption cases also carry `ikmE`, the 32-byte seed that fixes the
sender's ephemeral key: for ML-KEM the encapsulation randomness, for
DHKEM(X25519) the ephemeral private key `skEm` (what a deterministic-
encapsulation hook consumes, not RFC 9180's `DeriveKeyPair` ikm). With `ikmE`
fixed, encapsulation is deterministic, so an implementation with such a hook
can also check the sender direction: run `SetupBaseS(pkRm, info)` seeded with
`ikmE`, `Seal` `pt` with `aad`, and confirm `enc` and `ct` reproduce byte for
byte. The recorded values were produced this way against AWS-LC's test API.
Without such a hook, test by round-trip: `Seal` to `pkRm`, then `Open` and
check it recovers the message. Negative cases carry no `ikmE`.

| Field  | Meaning |
| ------ | ------- |
| `skRm` | Serialized recipient private key (`d \|\| z` seed for ML-KEM, scalar for DHKEM). |
| `pkRm` | Serialized recipient public key; derivable from `skRm`, provided for convenience. |
| `ikmE` | Optional. Seed fixing the sender's ephemeral key; present for `valid` cases, absent for negative cases. |
| `info` | HPKE info string bound into the key schedule. |
| `aad`  | Additional authenticated data passed to `Open`. |
| `enc`  | KEM encapsulated key consumed by `SetupBaseR`. |
| `ct`   | AEAD sealed message (ciphertext `\|\|` tag). |
| `pt`   | Expected recovered plaintext for `valid` cases; empty otherwise. |

### Additional Test Vectors

None yet. Every current case is generated by Wycheproof (`source.name =
"wycheproof"`). The published specifications carry their own worked examples —
RFC 9180 Appendix A for the classical DHKEM ciphersuites, and the
[draft-ietf-hpke-pq][] test vectors for the ML-KEM KEMs — which would make a
good independent cross-check. Importing them (with `source` pointing at the
spec) is a planned addition; this section is a placeholder until then.

[RFC 9180]: https://www.rfc-editor.org/rfc/rfc9180
[draft-ietf-hpke-pq]: https://datatracker.ietf.org/doc/draft-ietf-hpke-pq/
