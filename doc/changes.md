## Changes

### Version 0.6

*   Added test vectors for RSA-OAEP decryption. The files are:
    `rsa_oaep_<keysize>_<hash>_<mgf>_test.json`.
*   Added test vectors for ECDSA signatures with P1363 encoding. The files are:
    `ecdsa_<curve>_<hash>_p1363_test.json`
*   Added test vectors for XDH with ASN encoded keys. The files are:
    `x25519_asn_test.json` and `x448_asn_test.json`
*   Added test vectors for RSA-PKCS #1 signature generation. The current test
    vectors for RSA-PKCS #1 are meant for testing signature verification. These
    test vectors for signature generation include a private key. The files are:
    `rsa_sig_gen_misc_test.json`
*   Removed a duplicate field "curve" in the test vectors for X25519. The
    "curve" field always describes the curve of the private key. All test
    vectors in the same test group (and in fact the same test file) use the same
    curve.
*   Adding labels for all test vectors with status "acceptable". Test vectors
    have a status "acceptable" when it is unclear if a library should or should
    not accept them. This happens when the parameters are weak (e.g. using SHA-1
    for signatures) or when the encoding is slightly non-standard.

### Version 0.7

Format changes\:

*   All test vector files contain a new field `"schema"`, which points to a JSON
    schema definition in the directory `wycheproof/schema/`.
*   More consistent type definition: E.g. the field `"type"` in a `testGroup` is
    now describing the type of the test the vectors are intended for
    [types.md](types.md). The type of the test defines formatting (e.g. whether
    signatures use P1363 encoding or ASN encoding) and the tested operation
    (e.g. whether the test vectors signatures are primarily are meant for
    verification or signature generation).
*   RSA keys have been extended to use multi prime variants. The key material
    is now in a separate structure.
*   The format of test vectors have been slightly unified: In particular,
    RSA-PKCS#1 v1.5 signatures no longer have a field "padding".
*   Public and private keys in jwk format were added to other formats when the
    jwk format for these keys is defined.
*   The size of the encoding of a BigInteger is now always a multiple of 2 to
    make the enoding closer to the encoding used in ASN.1. (It still uses
    twos complement, bigendian, hexadecimal endoding).

Additional test vectors\:

*   Added vectors for edge cases that can occur in ECDH computations with
    projective or Jacobian coordinates. In particular this implement a detection
    for the attack in "Zero-Value Point Attacks on Elliptic Curve Cryptosystem"
    by T.Akishita and T Takagi, ISC 2003.
*   Added more edge cases for Xdh.
*   Added more test cases for ASN parsing (e.g. high number tags)
*   Added test vectors for CVE-2017-18330 to CCM and EAX.
*   Added more edge cases for poly1305.
*   Added test vectors for HKDF.
*   Added new test vectors for ED448.
*   Added some test vectors using SHA-3.
*   Added documentation of the tests intended by the test vector files:
    [files.md](files.md)
*   Added test vectors using three prime RSA keys.
*   Removed some duplicates in the test vectors.

### Some potential plans for version 0.8

*   Adding a component for the analysis of key generation and signature
    generation. Currently, such tests only run against Java providers. The goal
    is to allow any library to be tested.
*   Testing RSA-key generation. E.g. generate some RSA keys, then check if the
    keys have patterns that can be used by special case factoring algorithms.
*   Extending tests for timing differences. So far there are only a limited
    number of tests against Java providers. The statistical analysis of the
    measurments are relatively simple and could probably be improved. One goal
    is to separate measuring the timings and doing the statistical analysis by
    defining a JSON structure for storing the measurements.
*   Adding test vectors for long hashes and MACs. I.e. the inputs are strings
    and number of repetitions. This allows to add tests for primitives like
    HMAC('a' * (2**32+12345)).
*   New algorithms: PMAC, X963KDF

### Some potential plans for later versions
*   Adding code for capabilities of the providers. Currently this is written in
    unstructured form into the logs. Better would be a standalone binary that
    writes, JSON or html or text.
*   alternative protocols: PKCS #11, AMD SEV, ...

