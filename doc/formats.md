# Wycheproof formats for test vectors

[TOC]

## Overview

This document contains a general overview over the formats used and conventions
used for all test test vectors. Test types have specific formats, which are
defined in [types.md](types.md). The test files and the tests intended with
these test files are described in [files.md](files.md).

## General conventions

*   All files contain valid JSON. The root structure contains the field
    "schema", which is the file name of the JSON schema for this file. The JSON
    schemas are in the directory `wycheproof/schemas/`. Changes in the format of
    a test vector file that break compatibility will be reflected by a changed
    JSON schema file.
*   The data included in the header of the test vector file and the test groups
    are always well formatted. Only inputs contained in the individual tests may
    be malformed.
*   The file name for test vectors has typically the format
    `<algorithm>_<parameters>_test.json`.
*   The header of testGroups often contains a key in multiple formats. All
    formats encode the same key. Hence a tester can use the format that is
    supported by the library that is tested.

## Naming of primitives and algebraic structures

### Hash functions {#HashFunctions}

Wycheproof uses the following strings to denote hash functions: SHA-1, SHA-224,
SHA-256, SHA-384, SHA-512, SHA3-224, SHA3-256, SHA3-384, SHA3-512

### Elliptic curves {#EcCurve}

The following names for elliptic curves are used in Wycheproof. Some of the
curves have a jwk equivalent.

**Curve name**  | **jwk name** | **comments and references**
:-------------- | :----------- | :--------------------------
secp224r1       |              |
secp256r1       | P-256        |
secp384r1       | P-384        |
secp521r1       | P-521        |
secp256k1       | P-256K       | jwk name is proposed in tools.ietf.org/html/draft-jones-webauthn-secp256k1-00
brainpoolP256r1 |              | [RFC 5639]
brainpoolP320r1 |              | [RFC 5639]
brainpoolP384r1 |              | [RFC 5639]
brainpoolP512r1 |              | [RFC 5639]
brainpoolP256t1 |              | [RFC 5639]
brainpoolP320t1 |              | [RFC 5639]
brainpoolP384t1 |              | [RFC 5639]
brainpoolP512t1 |              | [RFC 5639]
curve25519      |              | Section 4.1 [RFC 7748]
curve448        |              | Section 4.2 [RFC 7748]
edwards25519    | Ed25519      | A curve that is used in Eddsa. It is isomorphic to curve25519. See [RFC 8032], [RFC 8037]
edwards448      | Ed448        | A curve that is used in Eddsa. It is isomorphic to curve448. See [RFC 8032], [RFC 8037]

## Test groups and tests

Test vectors are divided into several test groups. A test group is a list of
test vectors that use some common parameters (e.g. the same public key and
algorithm)

## Representation of some data types {#DataTypes}

Some data types that don't have an exact match in Json use a specific format as
described below

| **Type** | **Representation**                                                |
| :------- | :---------------------------------------------------------------- |
| HexBytes | This is an array of bytes represented as by hexadecimal string.   |
| BigInt   | An integer in hexadecimal representation using a twos complement  |
:          : representation and big-endian order. The integer is negative if   :
:          : the first byte is greater character is greater than 7. Examples\: :
:          : 259\: "103", -192\: "f40", 0\: "0"                                :
| Asn      | A hexadecimal encoded array of bytes. This may be a valid or      |
:          : invalid ASN encoding.                                             :
| Der      | A valid DER encoding represented as a hexadecimal string.         |
| Pem      | A valid PEM encoded key                                           |

## General format

This is the format for a file with test vectors.

| **Field name**   | **Type**    | **Explanation**                             |
| :--------------- | :---------- | :------------------------------------------ |
| algorithm        | str         | The name of the algorithm                   |
| schema           | str         | The name of the JSON schema defining the    |
:                  :             : format of the test vectors.                 :
| generatorVersion | str         | The version of the generator that generated |
:                  :             : the test vectors. For releases this has the :
:                  :             : format “major.minor”, where changes in the  :
:                  :             : format will be reflected by incrementing    :
:                  :             : major.                                      :
| numberOfTests    | int         | the number of test cases in the test vector |
:                  :             : file.                                       :
| header           | list of str | description of the file                     |
| notes            | dictionary  | A dictionary describing flags. (modified in |
:                  :             : v. 0.3)                                     :
| testGroups       | list        | a list of test groups. The format of the    |
:                  :             : test group depends on the algorithm that is :
:                  :             : tested.                                     :

Example:

```
{
  "algorithm" : "AES-EAX",
  "schema" : "aead\_test\_schema.json",
  "generatorVersion" : "0.7",
  "numberOfTests" : 143,
  "header" : [
     "text",
     "more text",
     "maybe some references"
  ],
  "notes" : [
     "label1" : "Description of label1",
     ...
  ]
  "testGroups" : [ ... ]
}
```
