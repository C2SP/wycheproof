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

### Some plans for version 0.7

*   Adding JSON schemas for the test vectors.
*   Adding documentation. In particular, there needs to be a definition
    for usages of the  vectors.
*   Adding some tests and test vectors using SHA-3.
*   Adding new primitives, e.g. HKDF, X963KDF, ED448 ...
