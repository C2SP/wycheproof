<!-- AUTO-GENERATED FILE; DO NOT MODIFY -->

# Test vector files

## AeadTest {#AeadTest}

Test vectors of type AeadTest test authenticated encryption with additional
data. The test vectors are intended for testing both encryption and decryption.

Test vectors with "result" \: "valid" are valid encryptions. Test vectors with
"result" \: "invalid" are using invalid parameters or contain an invalid
ciphertext or tag. Test vectors with "result" \: "acceptable" are using weak
parameters.

JSON schema\: aead_test_schema.json

Type of the test group\: [AeadTestGroup](types.md#AeadTestGroup)

Type of the test vectors\: [AeadTestVector](types.md#AeadTestVector)

**name**                     | **tests** | **validity** | **algorithm** {.sortable}
---------------------------- | --------- | ------------ | -------------
aead_aes_siv_cmac_test.json  | 828       | 180, 0, 648  | AEAD-AES-SIV-CMAC
aegis128L_test.json          | 462       | 350, 0, 112  | AEGIS128L
aegis128_test.json           | 465       | 357, 0, 108  | AEGIS128
aegis256_test.json           | 460       | 348, 0, 112  | AEGIS256
aes_ccm_test.json            | 510       | 366, 0, 144  | AES-CCM
aes_eax_test.json            | 171       | 78, 12, 81   | AES-EAX
aes_gcm_siv_test.json        | 155       | 88, 0, 67    | AES-GCM-SIV
aes_gcm_test.json            | 256       | 139, 30, 87  | AES-GCM
chacha20_poly1305_test.json  | 300       | 233, 0, 67   | CHACHA20-POLY1305
xchacha20_poly1305_test.json | 284       | 220, 0, 64   | XCHACHA20-POLY1305

## DaeadTest {#DaeadTest}

Test vectors of type DaeadTest are intended for verifying encryption and
decryption of deterministic authenticated encryption with additional data.

Unlike the test vectors for AEAD the tag is included in the ciphertext, since
deterministic authenticated encryption frequently uses a synthetic IV (SIV) that
is used both as IV and MAC, and since the position of the SIV often depends on
the primitive.

JSON schema\: daead_test_schema.json

Type of the test group\: [DaeadTestGroup](types.md#DaeadTestGroup)

Type of the test vectors\: [DaeadTestVector](types.md#DaeadTestVector)

**name**               | **tests** | **validity** | **algorithm** {.sortable}
---------------------- | --------- | ------------ | -------------
aes_siv_cmac_test.json | 442       | 118, 0, 324  | AES-SIV-CMAC

## DsaVerify {#DsaVerify}

Test vectors of test DsaVerify are intended for checking the signature
verification of DSA signatures.

Test vectors with "result" \: "valid" are valid signatures. Test vectors with
"result" \: "invalid" are invalid. Test vectors with "result" \: "acceptable"
are signatures that may be rejected for a number of reasons\: they can be
signatures with valid values for r and s, but with an invalid or non-standard
encoding. They can be signatures with weak or non-standard parameters. All the
test vectors of this type have a label describing the abnomaly.

JSON schema\: dsa_verify_schema.json

Type of the test group\: [DsaTestGroup](types.md#DsaTestGroup)

Type of the test vectors\:
[AsnSignatureTestVector](types.md#AsnSignatureTestVector)

**name**      | **tests** | **validity** | **algorithm** {.sortable}
------------- | --------- | ------------ | -------------
dsa_test.json | 888       | 33, 3, 852   | DSA

## EcPublicKeyVerify {#EcPublicKeyVerify}

Test vectors of type EcPublicKeyVerify are intended for test that check the
verification of EC public key.

In particular, implementations are expected to verify that the public key uses a
correct encoding, that the public key point is on the curve, that the point is
not a point of low order. If the public key encodes additional parameters e.g.
cofactor and order then the test expects that these parameters are verified.

JSON schema\: ec_public_key_verify_schema.json

Type of the test group\: [EcPublicKeyTestGroup](types.md#EcPublicKeyTestGroup)

Type of the test vectors\:
[EcPublicKeyTestVector](types.md#EcPublicKeyTestVector)

**name**        | **tests** | **validity** | **algorithm**   {.sortable}
--------------- | --------- | ------------ | ---------------
eckey_test.json | 19        | 14, 0, 5     | EcPublicKeyTest

## EcdhEcpointTest {#EcdhEcpointTest}

Test vectors of type EcdhWebTest are intended for testing an ECDH
implementations where the public key is just an ASN encoded point.

JSON schema\: ecdh_ecpoint_test_schema.json

Type of the test group\: [EcdhEcpointTestGroup](types.md#EcdhEcpointTestGroup)

Type of the test vectors\:
[EcdhEcpointTestVector](types.md#EcdhEcpointTestVector)

**name**                         | **tests** | **validity** | **algorithm** {.sortable}
-------------------------------- | --------- | ------------ | -------------
ecdh_secp224r1_ecpoint_test.json | 96        | 77, 1, 18    | ECDH
ecdh_secp256r1_ecpoint_test.json | 216       | 191, 1, 24   | ECDH
ecdh_secp384r1_ecpoint_test.json | 182       | 163, 1, 18   | ECDH
ecdh_secp521r1_ecpoint_test.json | 237       | 208, 1, 28   | ECDH

## EcdhTest {#EcdhTest}

Test vectors of type EcdhTest are intended for testing an ECDH implementations
using X509 encoded public keys and integers for private keys. Test vectors of
this format are useful for testing Java providers.

JSON schema\: ecdh_test_schema.json

Type of the test group\: [EcdhTestGroup](types.md#EcdhTestGroup)

Type of the test vectors\: [EcdhTestVector](types.md#EcdhTestVector)

**name**                       | **tests** | **validity**   | **algorithm** {.sortable}
------------------------------ | --------- | -------------- | -------------
ecdh_brainpoolP224r1_test.json | 475       | 205, 219, 51   | ECDH
ecdh_brainpoolP256r1_test.json | 521       | 253, 219, 49   | ECDH
ecdh_brainpoolP320r1_test.json | 426       | 159, 219, 48   | ECDH
ecdh_brainpoolP384r1_test.json | 365       | 85, 219, 61    | ECDH
ecdh_brainpoolP512r1_test.json | 377       | 115, 217, 45   | ECDH
ecdh_secp224r1_test.json       | 339       | 77, 219, 43    | ECDH
ecdh_secp256k1_test.json       | 445       | 181, 219, 45   | ECDH
ecdh_secp256r1_test.json       | 459       | 191, 219, 49   | ECDH
ecdh_secp384r1_test.json       | 426       | 163, 219, 44   | ECDH
ecdh_secp521r1_test.json       | 479       | 208, 217, 54   | ECDH
ecdh_test.json                 | 2989      | 2126, 120, 743 | ECDH

## EcdhWebcryptoTest {#EcdhWebcryptoTest}

Test vectors of type EcdhWebTest are intended for testing an ECDH
implementations using jwk encoded public and private keys.

JSON schema\: ecdh_webcrypto_test_schema.json

Type of the test group\:
[EcdhWebcryptoTestGroup](types.md#EcdhWebcryptoTestGroup)

Type of the test vectors\:
[EcdhWebcryptoTestVector](types.md#EcdhWebcryptoTestVector)

**name**                 | **tests** | **validity** | **algorithm** {.sortable}
------------------------ | --------- | ------------ | -------------
ecdh_webcrypto_test.json | 833       | 743, 0, 90   | ECDH

## EcdsaBitcoinVerify {#EcdsaBitcoinVerify}

Test vectors of type EcdsaBitcoinVerify are meant for the verification of a
ECDSA variant used for bitcoin, that add signature non-malleability.

The bitcoin protocol requires that the signature scheme is non-malleable. It
must not be possible to format the same signature in multiple ways. This variant
is described in https\://github.com/bitcoin/bips/blob/master/bip-0066.mediawiki

Test vectors with "result" \: "valid" are valid signatures. Test vectors with
"result" \: "invalid" are invalid. Test vectors with "result" \: "acceptable"
are signatures that may or may not be rejected.

Compared to normal ECDSA signatures, all alternative BER encodings of the
signature are invalid. The value s in the signature must be a positive integer
smaller than n/2.

JSON schema\: ecdsa_bitcoin_verify_schema.json

Type of the test group\: [EcdsaBitcoinTestGroup](types.md#EcdsaBitcoinTestGroup)

Type of the test vectors\:
[AsnSignatureTestVector](types.md#AsnSignatureTestVector)

**name**                                 | **tests** | **validity** | **algorithm** {.sortable}
---------------------------------------- | --------- | ------------ | -------------
ecdsa_secp256k1_sha256_bitcoin_test.json | 374       | 140, 0, 234  | ECDSA

## EcdsaP1363Verify {#EcdsaP1363Verify}

Test vectors of type EcdsaVerify are meant for the verification of IEEE P1363
encoded ECDSA signatures.

IEEE P1363 encoded signatures are the concatenation of the values r and s
encoded as unsigned integers in bigendian order using a fixed size equal to the
length of the field order.

Test vectors with "result" \: "valid" are valid signatures. Test vectors with
"result" \: "invalid" are invalid. Test vectors with "result" \: "acceptable"
are signatures that may or may not be rejected. The reasons for potential
rejection are described with labels. Weak parameters such as small curves, hash
functions weaker than the security of the curve are potential reasons.

JSON schema\: ecdsa_p1363_verify_schema.json

Type of the test group\: [EcdsaP1363TestGroup](types.md#EcdsaP1363TestGroup)

Type of the test vectors\: [SignatureTestVector](types.md#SignatureTestVector)

**name**                                     | **tests** | **validity** | **algorithm** {.sortable}
-------------------------------------------- | --------- | ------------ | -------------
ecdsa_brainpoolP224r1_sha224_p1363_test.json | 190       | 120, 3, 67   | ECDSA
ecdsa_brainpoolP256r1_sha256_p1363_test.json | 220       | 149, 3, 68   | ECDSA
ecdsa_brainpoolP320r1_sha384_p1363_test.json | 223       | 152, 3, 68   | ECDSA
ecdsa_brainpoolP384r1_sha384_p1363_test.json | 251       | 180, 3, 68   | ECDSA
ecdsa_brainpoolP512r1_sha512_p1363_test.json | 294       | 224, 3, 67   | ECDSA
ecdsa_secp224r1_sha224_p1363_test.json       | 187       | 117, 3, 67   | ECDSA
ecdsa_secp224r1_sha256_p1363_test.json       | 215       | 145, 3, 67   | ECDSA
ecdsa_secp224r1_sha512_p1363_test.json       | 284       | 214, 3, 67   | ECDSA
ecdsa_secp256k1_sha256_p1363_test.json       | 211       | 141, 3, 67   | ECDSA
ecdsa_secp256k1_sha512_p1363_test.json       | 280       | 210, 3, 67   | ECDSA
ecdsa_secp256r1_sha256_p1363_test.json       | 219       | 146, 4, 69   | ECDSA
ecdsa_secp256r1_sha512_p1363_test.json       | 288       | 215, 4, 69   | ECDSA
ecdsa_secp384r1_sha384_p1363_test.json       | 239       | 167, 3, 69   | ECDSA
ecdsa_secp384r1_sha512_p1363_test.json       | 276       | 204, 3, 69   | ECDSA
ecdsa_secp521r1_sha512_p1363_test.json       | 277       | 205, 3, 69   | ECDSA
ecdsa_webcrypto_test.json                    | 362       | 270, 10, 82  | ECDSA

## EcdsaVerify {#EcdsaVerify}

Test vectors of type EcdsaVerify are meant for the verification of ASN encoded
ECDSA signatures.

Test vectors with "result" \: "valid" are valid signatures. Test vectors with
"result" \: "invalid" are invalid. Test vectors with "result" \: "acceptable"
are signatures that may or may not be rejected. The reasons for potential
rejection are described with labels. Weak parameters such as small curves, hash
functions weaker than the security of the curve are potential reasons.
Non-standard BER encodings are other reasons.

JSON schema\: ecdsa_verify_schema.json

Type of the test group\: [EcdsaTestGroup](types.md#EcdsaTestGroup)

Type of the test vectors\:
[AsnSignatureTestVector](types.md#AsnSignatureTestVector)

**name**                               | **tests** | **validity** | **algorithm** {.sortable}
-------------------------------------- | --------- | ------------ | -------------
ecdsa_brainpoolP224r1_sha224_test.json | 353       | 121, 2, 230  | ECDSA
ecdsa_brainpoolP256r1_sha256_test.json | 383       | 150, 0, 233  | ECDSA
ecdsa_brainpoolP320r1_sha384_test.json | 386       | 153, 1, 232  | ECDSA
ecdsa_brainpoolP384r1_sha384_test.json | 414       | 181, 0, 233  | ECDSA
ecdsa_brainpoolP512r1_sha512_test.json | 456       | 225, 0, 231  | ECDSA
ecdsa_secp224r1_sha224_test.json       | 350       | 118, 1, 231  | ECDSA
ecdsa_secp224r1_sha256_test.json       | 378       | 146, 0, 232  | ECDSA
ecdsa_secp224r1_sha3_224_test.json     | 378       | 146, 2, 230  | ECDSA
ecdsa_secp224r1_sha3_256_test.json     | 386       | 154, 2, 230  | ECDSA
ecdsa_secp224r1_sha3_512_test.json     | 451       | 219, 2, 230  | ECDSA
ecdsa_secp224r1_sha512_test.json       | 447       | 215, 1, 231  | ECDSA
ecdsa_secp256k1_sha256_test.json       | 374       | 142, 1, 231  | ECDSA
ecdsa_secp256k1_sha3_256_test.json     | 382       | 150, 1, 231  | ECDSA
ecdsa_secp256k1_sha3_512_test.json     | 447       | 215, 1, 231  | ECDSA
ecdsa_secp256k1_sha512_test.json       | 443       | 211, 1, 231  | ECDSA
ecdsa_secp256r1_sha256_test.json       | 381       | 147, 1, 233  | ECDSA
ecdsa_secp256r1_sha3_256_test.json     | 389       | 155, 1, 233  | ECDSA
ecdsa_secp256r1_sha3_512_test.json     | 454       | 220, 2, 232  | ECDSA
ecdsa_secp256r1_sha512_test.json       | 450       | 216, 1, 233  | ECDSA
ecdsa_secp384r1_sha384_test.json       | 402       | 168, 1, 233  | ECDSA
ecdsa_secp384r1_sha3_384_test.json     | 412       | 178, 0, 234  | ECDSA
ecdsa_secp384r1_sha3_512_test.json     | 443       | 209, 2, 232  | ECDSA
ecdsa_secp384r1_sha512_test.json       | 439       | 205, 2, 232  | ECDSA
ecdsa_secp521r1_sha3_512_test.json     | 443       | 210, 0, 233  | ECDSA
ecdsa_secp521r1_sha512_test.json       | 441       | 206, 0, 235  | ECDSA
ecdsa_test.json                        | 1559      | 1007, 5, 547 | ECDSA

## EddsaVerify {#EddsaVerify}

Test vectors of type EddsaVerify are intended for testing the verification of
Eddsa signatures.

JSON schema\: eddsa_verify_schema.json

Type of the test group\: [EddsaTestGroup](types.md#EddsaTestGroup)

Type of the test vectors\: [SignatureTestVector](types.md#SignatureTestVector)

**name**        | **tests** | **validity** | **algorithm** {.sortable}
--------------- | --------- | ------------ | -------------
ed448_test.json | 86        | 17, 0, 69    | EDDSA
eddsa_test.json | 111       | 50, 0, 61    | EDDSA

## HkdfTest {#HkdfTest}

Test vector of type HkdfTest are intended for the verification of HKDF.

HKDF differs from other key derivation function because the function accepts
more parameters. I.e. the input for HKDF is a tuple (ikm, salt, info, size).

JSON schema\: hkdf_test_schema.json

Type of the test group\: [HkdfTestGroup](types.md#HkdfTestGroup)

Type of the test vectors\: [HkdfTestVector](types.md#HkdfTestVector)

**name**              | **tests** | **validity** | **algorithm** {.sortable}
--------------------- | --------- | ------------ | -------------
hkdf_sha1_test.json   | 61        | 61, 0, 0     | HKDF-SHA-1
hkdf_sha256_test.json | 60        | 60, 0, 0     | HKDF-SHA-256
hkdf_sha512_test.json | 57        | 57, 0, 0     | HKDF-SHA-512

## IndCpaTest {#IndCpaTest}

Test vectors of type IndCpaTest are intended for test that verify encryption and
decryption of symmetric ciphers without authentication.

JSON schema\: ind_cpa_test_schema.json

Type of the test group\: [IndCpaTestGroup](types.md#IndCpaTestGroup)

Type of the test vectors\: [IndCpaTestVector](types.md#IndCpaTestVector)

**name**                | **tests** | **validity** | **algorithm** {.sortable}
----------------------- | --------- | ------------ | -------------
aes_cbc_pkcs5_test.json | 183       | 72, 0, 111   | AES-CBC-PKCS5

## KeywrapTest {#KeywrapTest}

Test vectors of type Keywrap are intended for tests checking the wrapping and
unwrapping of key material.

Invalid test vectors may contain vectors with invalid sizes, or invalid
paddings. This is not ideal for testing whether unwrapping allows some padding
oracle. If there are key wrapping primitives that can be attacked when padding
oracles are present then we might add additional files just for checking against
padding attacks.

JSON schema\: keywrap_test_schema.json

Type of the test group\: [KeywrapTestGroup](types.md#KeywrapTestGroup)

Type of the test vectors\: [KeywrapTestVector](types.md#KeywrapTestVector)

**name**      | **tests** | **validity** | **algorithm** {.sortable}
------------- | --------- | ------------ | -------------
kw_test.json  | 162       | 36, 0, 126   | KW
kwp_test.json | 254       | 20, 60, 174  | KWP

## MacTest {#MacTest}

Test vectors of type MacTest are intended for testing the generation and
verification of MACs.

Test vectors with invalid MACs may contain vectors that contain invalid tags,
invalid parameters or invalid formats. Hence they are not ideal for testing if
an implementation is susceptible to padding attacks. Future version might
include separate files to simplify such tests.

JSON schema\: mac_test_schema.json

Type of the test group\: [MacTestGroup](types.md#MacTestGroup)

Type of the test vectors\: [MacTestVector](types.md#MacTestVector)

**name**           | **tests** | **validity** | **algorithm** {.sortable}
------------------ | --------- | ------------ | -------------
aes_cmac_test.json | 290       | 42, 0, 248   | AES-CMAC

## RsaPublicKeyAsnTest {#RsaPublicKeyAsnTest}

Test vectors of type RsaKeyTest are intended for checking the decoding of X509
encoded RSA public keys.

JSON schema\: rsa_public_key_asn_test_schema.json

Type of the test group\:
[RsaPublicKeyAsnTestGroup](types.md#RsaPublicKeyAsnTestGroup)

Type of the test vectors\:
[RsaPublicKeyAsnTestVector](types.md#RsaPublicKeyAsnTestVector)

**name**      | **tests** | **validity** | **algorithm** {.sortable}
------------- | --------- | ------------ | -------------
rsa_test.json | 335       | 1, 334, 0    | RSA

## RsaesOaepDecrypt {#RsaesOaepDecrypt}

Test vectors of type RsaOeapDecrypt are intended to check the decryption of RSA
encrypted ciphertexts.

The test vectors contain ciphertexts with invalid format (i.e. incorrect size)
and test vectors with invalid padding. Hence the test vectors are a bit
inconvenient to detect padding oracles. One potential plan is to generate
separate, new files that only contain ciphertexts with invalid paddings.

JSON schema\: rsaes_oaep_decrypt_schema.json

Type of the test group\: [RsaesOaepTestGroup](types.md#RsaesOaepTestGroup)

Type of the test vectors\: [RsaesOaepTestVector](types.md#RsaesOaepTestVector)

**name**                                               | **tests** | **validity** | **algorithm** {.sortable}
------------------------------------------------------ | --------- | ------------ | -------------
rsa_oaep_2048_sha1_mgf1sha1_test.json                  | 34        | 17, 0, 17    | RSAES-OAEP
rsa_oaep_2048_sha224_mgf1sha1_test.json                | 29        | 13, 0, 16    | RSAES-OAEP
rsa_oaep_2048_sha224_mgf1sha224_test.json              | 33        | 17, 0, 16    | RSAES-OAEP
rsa_oaep_2048_sha256_mgf1sha1_test.json                | 29        | 13, 0, 16    | RSAES-OAEP
rsa_oaep_2048_sha256_mgf1sha256_test.json              | 35        | 18, 0, 17    | RSAES-OAEP
rsa_oaep_2048_sha384_mgf1sha1_test.json                | 29        | 13, 0, 16    | RSAES-OAEP
rsa_oaep_2048_sha384_mgf1sha384_test.json              | 32        | 16, 0, 16    | RSAES-OAEP
rsa_oaep_2048_sha512_mgf1sha1_test.json                | 29        | 13, 0, 16    | RSAES-OAEP
rsa_oaep_2048_sha512_mgf1sha512_test.json              | 31        | 14, 0, 17    | RSAES-OAEP
rsa_oaep_3072_sha256_mgf1sha1_test.json                | 30        | 13, 0, 17    | RSAES-OAEP
rsa_oaep_3072_sha256_mgf1sha256_test.json              | 35        | 18, 0, 17    | RSAES-OAEP
rsa_oaep_3072_sha512_mgf1sha1_test.json                | 29        | 13, 0, 16    | RSAES-OAEP
rsa_oaep_3072_sha512_mgf1sha512_test.json              | 31        | 15, 0, 16    | RSAES-OAEP
rsa_oaep_4096_sha256_mgf1sha1_test.json                | 30        | 13, 0, 17    | RSAES-OAEP
rsa_oaep_4096_sha256_mgf1sha256_test.json              | 35        | 18, 0, 17    | RSAES-OAEP
rsa_oaep_4096_sha512_mgf1sha1_test.json                | 29        | 13, 0, 16    | RSAES-OAEP
rsa_oaep_4096_sha512_mgf1sha512_test.json              | 34        | 17, 0, 17    | RSAES-OAEP
rsa_oaep_misc_test.json                                | 775       | 460, 315, 0  | RSAES-OAEP
rsa_three_primes_oaep_2048_sha1_mgf1sha1_test.json     | 34        | 17, 0, 17    | RSAES-OAEP
rsa_three_primes_oaep_3072_sha224_mgf1sha224_test.json | 35        | 19, 0, 16    | RSAES-OAEP
rsa_three_primes_oaep_4096_sha256_mgf1sha256_test.json | 35        | 18, 0, 17    | RSAES-OAEP

## RsaesPkcs1Decrypt {#RsaesPkcs1Decrypt}

Test vectors of type RsaesPkcs1Decrypt are intended to check the decryption of
RSA encrypted ciphertexts.

The test vectors contain ciphertexts with invalid format (i.e. incorrect size)
and test vectors with invalid padding. Hence the test vectors are a bit
inconvenient to detect padding oracles. One potential plan is to generate
separate, new files that only contain ciphertexts with invalid paddings.

JSON schema\: rsaes_pkcs1_decrypt_schema.json

Type of the test group\: [RsaesPkcs1TestGroup](types.md#RsaesPkcs1TestGroup)

Type of the test vectors\: [RsaesPkcs1TestVector](types.md#RsaesPkcs1TestVector)

**name**                 | **tests** | **validity** | **algorithm** {.sortable}
------------------------ | --------- | ------------ | -------------
rsa_pkcs1_2048_test.json | 65        | 42, 0, 23    | RSAES-PKCS1-v1_5
rsa_pkcs1_3072_test.json | 65        | 41, 0, 24    | RSAES-PKCS1-v1_5
rsa_pkcs1_4096_test.json | 65        | 41, 0, 24    | RSAES-PKCS1-v1_5

## RsassaPkcs1Generate {#RsassaPkcs1Generate}

Test vectors of class RsassaPkcs1Generate are intended for checking the
generation of RSA PKCS #1 v 1.5 signatures.

The test vectors only provide limited coverage for signature verification, since
a frequent flaw in implementations is to only check the padding partially.

JSON schema\: rsassa_pkcs1_generate_schema.json

Type of the test group\:
[RsassaPkcs1GenTestGroup](types.md#RsassaPkcs1GenTestGroup)

Type of the test vectors\: [SignatureTestVector](types.md#SignatureTestVector)

**name**                                | **tests** | **validity** | **algorithm** {.sortable}
--------------------------------------- | --------- | ------------ | -------------
rsa_sig_gen_misc_test.json              | 158       | 80, 78, 0    | RSASSA-PKCS1-v1_5
rsa_sig_gen_misc_three_primes_test.json | 32        | 24, 8, 0     | RSASSA-PKCS1-v1_5

## RsassaPkcs1Verify {#RsassaPkcs1Verify}

Test vectors of class RsassaPkcs1Verify are intended for checking the
verification of RSA PKCS #1 v 1.5 signatures.

RSA signature verification should generally be very strict about checking the
padding. Because of this most RSA signatures with a slightly modified padding
have "result" \: "invalid". Only a small number of RSA signatures implementing
legacy behaviour (such as a missing NULL in the encoding) have "result" \:
"acceptable".

JSON schema\: rsassa_pkcs1_verify_schema.json

Type of the test group\: [RsassaPkcs1TestGroup](types.md#RsassaPkcs1TestGroup)

Type of the test vectors\: [SignatureTestVector](types.md#SignatureTestVector)

**name**                            | **tests** | **validity** | **algorithm** {.sortable}
----------------------------------- | --------- | ------------ | -------------
rsa_signature_2048_sha224_test.json | 241       | 7, 1, 233    | RSASSA-PKCS1-v1_5
rsa_signature_2048_sha256_test.json | 240       | 7, 3, 230    | RSASSA-PKCS1-v1_5
rsa_signature_2048_sha512_test.json | 240       | 7, 2, 231    | RSASSA-PKCS1-v1_5
rsa_signature_3072_sha256_test.json | 239       | 7, 2, 230    | RSASSA-PKCS1-v1_5
rsa_signature_3072_sha384_test.json | 239       | 7, 1, 231    | RSASSA-PKCS1-v1_5
rsa_signature_3072_sha512_test.json | 240       | 7, 2, 231    | RSASSA-PKCS1-v1_5
rsa_signature_4096_sha384_test.json | 239       | 7, 1, 231    | RSASSA-PKCS1-v1_5
rsa_signature_4096_sha512_test.json | 239       | 7, 1, 231    | RSASSA-PKCS1-v1_5
rsa_signature_test.json             | 377       | 84, 63, 230  | RSASSA-PKCS1-v1_5

## RsassaPssVerify {#RsassaPssVerify}

Test vectors of class RsassaPssVerify are intended for checking the verification
of RSASSA-PSS signatures.

RSA signature verification should generally be very strict about checking the
padding. Because of this RSASSA-PSS signatures with a modified padding have
"result" \: "invalid".

JSON schema\: rsassa_pss_verify_schema.json

Type of the test group\: [RsassaPssTestGroup](types.md#RsassaPssTestGroup)

Type of the test vectors\: [RsassaPssTestVector](types.md#RsassaPssTestVector)

**name**                                     | **tests** | **validity** | **algorithm** {.sortable}
-------------------------------------------- | --------- | ------------ | -------------
rsa_pss_2048_sha1_mgf1_20_test.json          | 49        | 0, 9, 40     | RSASSA-PSS
rsa_pss_2048_sha256_mgf1_0_test.json         | 46        | 7, 0, 39     | RSASSA-PSS
rsa_pss_2048_sha256_mgf1_32_params_test.json | 49        | 9, 0, 40     | RSASSA-PSS
rsa_pss_2048_sha256_mgf1_32_test.json        | 49        | 9, 0, 40     | RSASSA-PSS
rsa_pss_3072_sha256_mgf1_32_test.json        | 49        | 9, 0, 40     | RSASSA-PSS
rsa_pss_4096_sha256_mgf1_32_test.json        | 49        | 9, 0, 40     | RSASSA-PSS
rsa_pss_4096_sha512_mgf1_32_test.json        | 48        | 9, 0, 39     | RSASSA-PSS
rsa_pss_misc_params_test.json                | 150       | 120, 30, 0   | RSASSA-PSS
rsa_pss_misc_test.json                       | 150       | 120, 30, 0   | RSASSA-PSS

## XdhAsnComp {#XdhAsnComp}

Test vectors of type XdhComp are intended for tests that verify the computation
of and Xdh key exchange.

Public and private keys are ASN encoded.

JSON schema\: xdh_asn_comp_schema.json

Type of the test group\: [XdhAsnTestGroup](types.md#XdhAsnTestGroup)

Type of the test vectors\: [XdhAsnTestVector](types.md#XdhAsnTestVector)

**name**             | **tests** | **validity** | **algorithm** {.sortable}
-------------------- | --------- | ------------ | -------------
x25519_asn_test.json | 176       | 62, 98, 16   | XDH
x448_asn_test.json   | 151       | 60, 75, 16   | XDH

## XdhComp {#XdhComp}

Test vectors of type XdhComp are intended for tests that verify the computation
of and Xdh key exchange.

Both public and private key in the test vectors are just raw bytes. There are
separate files, where the keys are ASN.1 encoded or use the webcrypto encoding.

JSON schema\: xdh_comp_schema.json

Type of the test group\: [XdhTestGroup](types.md#XdhTestGroup)

Type of the test vectors\: [XdhTestVector](types.md#XdhTestVector)

**name**         | **tests** | **validity** | **algorithm** {.sortable}
---------------- | --------- | ------------ | -------------
x25519_test.json | 160       | 62, 98, 0    | XDH
x448_test.json   | 135       | 60, 75, 0    | XDH

## XdhJwkComp {#XdhJwkComp}

Test vectors of type XdhComp are intended for tests that verify the computation
of and Xdh key exchange.

The public and private keys in these test vectors use the webcrypto encoding.

JSON schema\: xdh_jwk_comp_schema.json

Type of the test group\: [XdhJwkTestGroup](types.md#XdhJwkTestGroup)

Type of the test vectors\: [XdhJwkTestVector](types.md#XdhJwkTestVector)

**name**             | **tests** | **validity** | **algorithm** {.sortable}
-------------------- | --------- | ------------ | -------------
x25519_jwk_test.json | 173       | 62, 98, 13   | XDH
x448_jwk_test.json   | 148       | 60, 75, 13   | XDH
