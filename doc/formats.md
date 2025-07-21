# Wycheproof formats for test vectors

## Overview

This document contains a general overview over the formats used and conventions
used for all test test vectors. Test types have specific formats, which are
defined in [types.md](types.md). The test files and the tests intended with
these test files are described in [files.md](files.md). In a number of cases
there are distinct tests for distinct output formats. E.g. DSA and ECDSA
signatures both have separate test vector files for ASN encoded signatures and
P1363 encoded signatures.

## Test vectors

The latest test vectors have version 0.9. This version differs from previous
versions in a number of places and is anticipated to be used for version 1.0. A
significant difference is that the new test vectors contain more information
about the test that is performed with the test vector. This information contains
links to CVEs, papers and tries to classify potential bugs by type and effect.
The old test vectors are in the directory `wycheproof/testvectors/`, while the
new test vectors are in `wycheproof/testvectors_v1/`.

## JSON schemas

All test vector files contain valid JSON. The root structure contains the field
"schema", which is the file name of the JSON schema for this file. The JSON
schemas are in the directory `wycheproof/schemas/`. The JSON schemas are still
in an experimental state. Being unfamiliar with JSON schemas it is often not
clear which syntax is well supported. Hence some changes in the schemas should
be expected in the future.

However, the plan is that major changes in the format of a test vector file will
be reflected by a changed JSON schema file.

## General conventions

*   The data included in the header of the test vector file and the test groups
    are always well formatted. Only inputs contained in the individual tests may
    be malformed.
*   The file name for test vectors has typically the format
    `<algorithm>_<parameters>_test.json`.
*   The header of testGroups often contains a key in multiple formats. All
    formats encode the same key. Hence a tester can use the format that is
    supported by the library that is tested.

## Naming of primitives and algebraic structures

### Hash functions

Wycheproof uses the following strings to denote hash functions: SHA-1, SHA-224,
SHA-256, SHA-384, SHA-512, SHA3-224, SHA3-256, SHA3-384, SHA3-512, SHA-512/224
SHA-512/256, SHAKE128 and SHAKE256. Some protocols use the variants of SHA-3,
namely KECCAK-224, KECCAK-256, KECCAK-384 and KECCAK-512.

### Elliptic curves

The following names for elliptic curves are used in Wycheproof. Some of the
curves have a jwk equivalent. Weak curves are curves with a security level below
112-bits. These curves are typically not tested.

**Curve name**  | **jwk name** | **oid**               | **comments and references**
:-------------- | :----------- | :-------------------- | :--------------------------
secp160k1       |              | 1.3.132.0.9           | weak curve
secp160r1       |              | 1.3.132.0.8           | weak curve
secp160r2       |              | 1.3.132.0.30          | weak curve
secp192k1       |              | 1.3.132.0.31          | weak curve
secp192r1       |              | 1.2.840.10045.3.1.1   | [RFC 3279], weak curve
secp224k1       |              | 1.3.132.0.32          |
secp224r1       |              | 1.3.132.0.33          | [RFC 5480]
secp256r1       | P-256        | 1.2.840.10045.3.1.7   | [RFC 3279]
secp256k1       | secp256k1    | 1.3.132.0.10          | the name P-256K was previously proposed in https://tools.ietf.org/html/draft-jones-webauthn-secp256k1-00
secp384r1       | P-384        | 1.3.132.0.34          | [RFC 5480]
secp521r1       | P-521        | 1.3.132.0.35          | [RFC 5480]
brainpoolP224r1 |              | 1.3.36.3.3.2.8.1.1.5  | [RFC 5639]
brainpoolP224t1 |              | 1.3.36.3.3.2.8.1.1.6  | [RFC 5639]
brainpoolP256r1 |              | 1.3.36.3.3.2.8.1.1.7  | [RFC 5639]
brainpoolP256t1 |              | 1.3.36.3.3.2.8.1.1.8  | [RFC 5639]
brainpoolP320r1 |              | 1.3.36.3.3.2.8.1.1.9  | [RFC 5639]
brainpoolP320t1 |              | 1.3.36.3.3.2.8.1.1.10 | [RFC 5639]
brainpoolP384r1 |              | 1.3.36.3.3.2.8.1.1.11 | [RFC 5639]
brainpoolP384t1 |              | 1.3.36.3.3.2.8.1.1.12 | [RFC 5639]
brainpoolP512r1 |              | 1.3.36.3.3.2.8.1.1.13 | [RFC 5639]
brainpoolP512t1 |              | 1.3.36.3.3.2.8.1.1.14 | [RFC 5639]
curve25519      |              |                       | Section 4.1 [RFC 7748]
curve448        |              |                       | Section 4.2 [RFC 7748]
edwards25519    | Ed25519      |                       | A curve that is used in Eddsa. It is isomorphic to curve25519. See [RFC 8032], [RFC 8037]
edwards448      | Ed448        |                       | A curve that is used in Eddsa. It is isomorphic to curve448. See [RFC 8032], [RFC 8037]

## Test groups and tests

Test vectors are divided into several test groups. A test group is a list of
test vectors that use some common parameters (e.g. the same public key and
algorithm)

## Data types

Some data types that don't have an exact match in Json use a specific format as
described below

**Type** | **Representation**
:------- | :-----------------
HexBytes | This is an array of bytes represented as by hexadecimal string.
BigInt   | An integer in hexadecimal representation using a twos complement representation and big-endian order. The integer is negative if the first byte is greater character is greater than 7. Starting with verion 0.7 the size is always a multiple of 2. This simplifies conversion to an array of bytes. Examples: 259: "0103", -192: "ff40", 0: "00", 255: "00ff"
Asn      | A hexadecimal encoded array of bytes. This may be a valid or invalid ASN encoding.
Der      | A valid DER encoding represented as a hexadecimal string.
Pem      | A valid PEM encoded key

## General format

This is the format for a file with test vectors.

**Field name**   | **Type**    | **Explanation**
:--------------- | :---------- | :--------------
algorithm        | str         | The name of the algorithm
schema           | str         | The name of the JSON schema defining the format of the test vectors.
generatorVersion | str         | The version of the generator that generated the test vectors.
numberOfTests    | int         | the number of test cases in the test vector file.
header           | list of str | description of the file
notes            | dictionary  | A dictionary describing flags. (modified in v. 0.9)
testGroups       | list        | a list of test groups. The format of the test group depends on the algorithm that is tested.

The `generatorVersion` is currently at 0.9. This version includes a large
fraction of the changes from previous versions that are planned for version 1.0.

A flag tries to give information about the nature of the test vector. Much of
the information is experimental and may need to be changed in future versions. A
description of a flag in notes can have the following fields:

**Field name** | **Type**    | **Explanation**
:------------- | :---------- | :----------------------------------------------
description    | str         | A description of the flag
bugType        | str         | The type of the bug tested for.
effect         | str         | The expected effect of failing the test vector.
links          | list of str | A list of potentially related references
cves           | list of str | A list of potentially related CVEs

The list of fields may be extended if useful. The field `bugType` explains what
the goal of the test is. This may simplify debugging. However, one should note
that the goal of a failing test does not necessarily determine the cause and
effect of a potential bug.

Currently `bugType` may have the following values:

*   **BASIC**: A test vector that contains a basic test vector. The test vector
    tries to avoid any special cases. The main purpose of such test vectors is
    to check if the primitive is supported and that the test itself is correctly
    setup.

*   **AUTH_BYPASS**: A test vector with an invalid integrity check. Failing such
    a test vector does not necessarily indicate a vulnerability, but it
    indicates a bug that needs attention.

*   **CONFIDENTIALITY**: A test vector that checks for bugs that may leak
    material of plaintext. A typical example are invalid ephemeral public keys
    in ECDH, which can lead to invalid curve attacks when not properly checked.

*   **LEGACY**: A test vector that checks for legacy behaviour. Sometimes
    libraries accept slightly wrong formats. This is often done for
    compatibility. Typically neither accepting or rejecting such formats is a
    failure. An example for such legacy test vectors is
    https://bugs.openjdk.org/browse/JDK-8213493 . Jdk encoded XDH keys
    incorrectly. For compatibility reasons some other providers (e.g.,
    BouncyCastle) now accept the incorrectly encoded keys.

*   **FUNCTIONALITY**: A test vector for uncommon parameter sizes. Many
    libraries limit parameters such as key size, nonce size or input size to
    commonly used ranges. An example is key wrapping with KW. Different
    standards disagree whether keys smaller than 16 bytes should be accepted.

*   **WEAK_PARAMS**: The test vector uses parameters that are below NIST
    recommendation (e.g. below 112-bit). Frequently libraries reject keys using
    such weak parameters.

*   **CAN_OF_WORMS**: A test vector that check for a small bug in a situation
    where minor problems can add up to a vulnerability. A typical case is RSA
    PKCS#1 signatures, where the verification of the padding uses a sloppy DER
    parsers. Accepting a few alternative BER encodings is a bug that may not be
    exploitable. However, the use of a parser by itself is a questionable
    practice an can easily contain additional undiscovered bugs.

*   **MALLEABILITY**: A test vector with a ciphertext of (ephemeral) key that
    was slightly modified. For example, it is sometimes possible to prepend
    additional 0's to an RSA encrypted message. Such modified ciphertexts are
    invalid but may be decrypted to the same value as the unmodified ciphertext.
    While such bugs are benign in some situations, they may be used in other
    situations to watermark messages.

*   **SIGNATURE_MALLEABILITY**: A test vector with a slightly modified
    signature, but unchanged message. While such bugs are frequently benign,
    there are cases where they can cause a vulnerability. One example is if a
    protocol assumes that signatures are unique.

*   **BER_ENCODING**: A test vector where BER encoding is used in a place where
    DER encoding is expected. This bug type is being used in situations where a
    BER encoding does not lead to severe bugs, but where CVEs are issued.
    Examples are ECDSA or DSA signatures.

*   **EDGE_CASE**: A test vector that was specifically constructed to cover edge
    cases. For example it is possible to find keys and messages such that there
    is a valid ECDSA signature (r, s) where both r and s are small integers.
    Failing to accept edge cases indicates a bug in the implementation. When
    edge cases fail, then it is often unclear how serious the bug is. The main
    question often is whether an attacker can construct inputs that trigger the
    faulty edge cases and thereby gain information.

*   **MISSING_STEP**: A test vector that has been constructed by skipping a step
    in the implementation. Such steps can for example include truncation or a
    modular reduction.

*   **KNOWN_BUG**: A test for a known bug. The cause for previous failures in
    other libraries may explain the failure in the tested library.

*   **WRONG_PRIMITIVE**: A test vector that uses the wrong primitive. For
    example it is important that a signature scheme only accepts signatures
    generated with the specified hash function. If an implementation accepts
    multiple hashes then an attacker can target the weakest hash.

*   **MODIFIED_PARAMETER**: A test vector containing a modified algorithm
    parameter. Typically we expect that cryptographic primitives perform
    sufficient parameter checks to detect such modifications.

*   **DEFINED**: A test vector with an edge case that normally should not
    happen, but nonetheless has defined behavior. For example, XDH defines a
    shared secret for ephemeral public keys with points on the twist. The
    expectation is that a library either rejects such edge cases or implements
    them according to expectation.

Example:

```json
{
  "algorithm" : "AES-EAX",
  "schema" : "aead_test_schema.json",
  "generatorVersion" : "0.9",
  "numberOfTests" : 240,
  "header" : [
     "text",
     "more text",
     ...
  ],
  "notes" : {
    "Ktv" : {
      "bugType" : "BASIC",
      "description" : "Known test vector from eprint.iacr.org/2003/069"
    },
  },
  "testGroups" : [
    {
      "type" : "AeadTest",
      "keySize" : 128,
      "ivSize" : 128,
      "tagSize" : 128,
      "tests" : [
        {
          "tcId" : 1,
          "comment" : "eprint.iacr.org/2003/069",
          "flags" : [
            "Ktv"
          ],
          "key" : "233952dee4d5ed5f9b9c6d6ff80ff478",
          "iv" : "62ec67f9c3a4a407fcb2a8c49031a8b3",
          "aad" : "6bfb914fd07eae6b",
          "msg" : "",
          "ct" : "",
          "tag" : "e037830e8389f27b025a2d6527e79d01",
          "result" : "valid"
        },
    ...
  ]
}
```
