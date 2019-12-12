<!-- AUTO-GENERATED FILE; DO NOT MODIFY -->

# Test vector files

## AeadTest

Test vectors of type AeadTest test authenticated encryption with additional
data. The test vectors are intended for testing both encryption and decryption.

Test vectors with "result" \: "valid" are valid encryptions. Test vectors with
"result" \: "invalid" are using invalid parameters or contain an invalid
ciphertext or tag. Test vectors with "result" \: "acceptable" are using weak
parameters.

JSON schema\: aead_test_schema.json

Type of the test group\: [AeadTestGroup](types.md#aeadtestgroup)

Type of the test vectors\: [AeadTestVector](types.md#aeadtestvector)

**name**                     | **tests** | **validity** | **algorithm** {.sortable}
---------------------------- | --------- | ------------ | -------------
aead_aes_siv_cmac_test.json  | 828       | 180, 0, 648  | AEAD-AES-SIV-CMAC
aegis128L_test.json          | 462       | 350, 0, 112  | AEGIS128L
aegis128_test.json           | 469       | 361, 0, 108  | AEGIS128
aegis256_test.json           | 464       | 352, 0, 112  | AEGIS256
aes_ccm_test.json            | 510       | 366, 0, 144  | AES-CCM
aes_eax_test.json            | 171       | 78, 12, 81   | AES-EAX
aes_gcm_siv_test.json        | 155       | 88, 0, 67    | AES-GCM-SIV
aes_gcm_test.json            | 256       | 139, 30, 87  | AES-GCM
chacha20_poly1305_test.json  | 300       | 233, 0, 67   | CHACHA20-POLY1305
xchacha20_poly1305_test.json | 284       | 220, 0, 64   | XCHACHA20-POLY1305

## DaeadTest

Test vectors of type DaeadTest are intended for verifying encryption and
decryption of deterministic authenticated encryption with additional data.

Unlike the test vectors for AEAD the tag is included in the ciphertext, since
deterministic authenticated encryption frequently uses a synthetic IV (SIV) that
is used both as IV and MAC, and since the position of the SIV often depends on
the primitive.

JSON schema\: daead_test_schema.json

Type of the test group\: [DaeadTestGroup](types.md#daeadtestgroup)

Type of the test vectors\: [DaeadTestVector](types.md#daeadtestvector)

**name**               | **tests** | **validity** | **algorithm** {.sortable}
---------------------- | --------- | ------------ | -------------
aes_siv_cmac_test.json | 442       | 118, 0, 324  | AES-SIV-CMAC

## DsaP1363Verify

Test vectors of type DsaP1363Verify are meant for the verification of IEEE P1363
encoded DSA signatures.

IEEE P1363 encoded signatures are the concatenation of the values r and s
encoded as unsigned integers in bigendian order using a fixed size equal to the
length of the field order. The tests expect that all signatures with other sizes
(e.g. additional appended bytes) are rejected. (Though there are not a lot of
test vectors verifying this).

Test vectors with "result" \: "valid" are valid signatures. Test vectors with
"result" \: "invalid" are invalid. Test vectors with "result" \: "acceptable"
are signatures that may or may not be rejected. The reasons for potential
rejection are described with labels.

JSON schema\: dsa_p1363_verify_schema.json

Type of the test group\: [DsaP1363TestGroup](types.md#dsap1363testgroup)

Type of the test vectors\: [SignatureTestVector](types.md#signaturetestvector)

**name**                            | **tests** | **validity** | **algorithm** {.sortable}
----------------------------------- | --------- | ------------ | -------------
dsa_2048_224_sha224_p1363_test.json | 127       | 38, 0, 89    | DSA
dsa_2048_224_sha256_p1363_test.json | 155       | 66, 0, 89    | DSA
dsa_2048_256_sha256_p1363_test.json | 155       | 66, 0, 89    | DSA
dsa_3072_256_sha256_p1363_test.json | 155       | 66, 0, 89    | DSA

## DsaVerify

Test vectors of test DsaVerify are intended for checking the signature
verification of DSA signatures.

Test vectors with "result" \: "valid" are valid signatures. Test vectors with
"result" \: "invalid" are invalid. Test vectors with "result" \: "acceptable"
are signatures that may be rejected for a number of reasons\: they can be
signatures with valid values for r and s, but with an invalid or non-standard
encoding. They can be signatures with weak or non-standard parameters. All the
test vectors of this type have a label describing the abnomaly.

JSON schema\: dsa_verify_schema.json

Type of the test group\: [DsaTestGroup](types.md#dsatestgroup)

Type of the test vectors\:
[AsnSignatureTestVector](types.md#asnsignaturetestvector)

**name**                      | **tests** | **validity** | **algorithm** {.sortable}
----------------------------- | --------- | ------------ | -------------
dsa_2048_224_sha224_test.json | 330       | 39, 1, 290   | DSA
dsa_2048_224_sha256_test.json | 358       | 67, 1, 290   | DSA
dsa_2048_256_sha256_test.json | 358       | 67, 1, 290   | DSA
dsa_3072_256_sha256_test.json | 358       | 67, 1, 290   | DSA
dsa_test.json                 | 906       | 33, 3, 870   | DSA

## EcdhEcpointTest

Test vectors of type EcdhWebTest are intended for testing an ECDH
implementations where the public key is just an ASN encoded point.

JSON schema\: ecdh_ecpoint_test_schema.json

Type of the test group\: [EcdhEcpointTestGroup](types.md#ecdhecpointtestgroup)

Type of the test vectors\:
[EcdhEcpointTestVector](types.md#ecdhecpointtestvector)

**name**                         | **tests** | **validity** | **algorithm** {.sortable}
-------------------------------- | --------- | ------------ | -------------
ecdh_secp224r1_ecpoint_test.json | 96        | 77, 1, 18    | ECDH
ecdh_secp256r1_ecpoint_test.json | 216       | 191, 1, 24   | ECDH
ecdh_secp384r1_ecpoint_test.json | 182       | 163, 1, 18   | ECDH
ecdh_secp521r1_ecpoint_test.json | 237       | 208, 1, 28   | ECDH

## EcdhTest

Test vectors of type EcdhTest are intended for testing an ECDH implementations
using X509 encoded public keys and integers for private keys. Test vectors of
this format are useful for testing Java providers.

JSON schema\: ecdh_test_schema.json

Type of the test group\: [EcdhTestGroup](types.md#ecdhtestgroup)

Type of the test vectors\: [EcdhTestVector](types.md#ecdhtestvector)

**name**                       | **tests** | **validity**   | **algorithm** {.sortable}
------------------------------ | --------- | -------------- | -------------
ecdh_brainpoolP224r1_test.json | 476       | 205, 219, 52   | ECDH
ecdh_brainpoolP256r1_test.json | 522       | 253, 219, 50   | ECDH
ecdh_brainpoolP320r1_test.json | 427       | 159, 219, 49   | ECDH
ecdh_brainpoolP384r1_test.json | 366       | 85, 219, 62    | ECDH
ecdh_brainpoolP512r1_test.json | 378       | 115, 217, 46   | ECDH
ecdh_secp224r1_test.json       | 340       | 77, 219, 44    | ECDH
ecdh_secp256k1_test.json       | 446       | 181, 219, 46   | ECDH
ecdh_secp256r1_test.json       | 460       | 191, 219, 50   | ECDH
ecdh_secp384r1_test.json       | 427       | 163, 219, 45   | ECDH
ecdh_secp521r1_test.json       | 480       | 208, 217, 55   | ECDH
ecdh_test.json                 | 3100      | 2169, 128, 803 | ECDH

## EcdhWebcryptoTest

Test vectors of type EcdhWebTest are intended for testing an ECDH
implementations using jwk encoded public and private keys.

JSON schema\: ecdh_webcrypto_test_schema.json

Type of the test group\:
[EcdhWebcryptoTestGroup](types.md#ecdhwebcryptotestgroup)

Type of the test vectors\:
[EcdhWebcryptoTestVector](types.md#ecdhwebcryptotestvector)

**name**                 | **tests** | **validity** | **algorithm** {.sortable}
------------------------ | --------- | ------------ | -------------
ecdh_webcrypto_test.json | 833       | 743, 0, 90   | ECDH

## EcdsaP1363Verify

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

Type of the test group\: [EcdsaP1363TestGroup](types.md#ecdsap1363testgroup)

Type of the test vectors\: [SignatureTestVector](types.md#signaturetestvector)

**name**                                     | **tests** | **validity** | **algorithm** {.sortable}
-------------------------------------------- | --------- | ------------ | -------------
ecdsa_brainpoolP224r1_sha224_p1363_test.json | 190       | 120, 3, 67   | ECDSA
ecdsa_brainpoolP256r1_sha256_p1363_test.json | 220       | 149, 3, 68   | ECDSA
ecdsa_brainpoolP320r1_sha384_p1363_test.json | 224       | 152, 3, 69   | ECDSA
ecdsa_brainpoolP384r1_sha384_p1363_test.json | 251       | 180, 3, 68   | ECDSA
ecdsa_brainpoolP512r1_sha512_p1363_test.json | 294       | 224, 3, 67   | ECDSA
ecdsa_secp224r1_sha224_p1363_test.json       | 187       | 117, 3, 67   | ECDSA
ecdsa_secp224r1_sha256_p1363_test.json       | 216       | 145, 3, 68   | ECDSA
ecdsa_secp224r1_sha512_p1363_test.json       | 285       | 214, 3, 68   | ECDSA
ecdsa_secp256k1_sha256_p1363_test.json       | 211       | 141, 3, 67   | ECDSA
ecdsa_secp256k1_sha512_p1363_test.json       | 281       | 210, 3, 68   | ECDSA
ecdsa_secp256r1_sha256_p1363_test.json       | 219       | 146, 4, 69   | ECDSA
ecdsa_secp256r1_sha512_p1363_test.json       | 289       | 215, 4, 70   | ECDSA
ecdsa_secp384r1_sha384_p1363_test.json       | 239       | 167, 3, 69   | ECDSA
ecdsa_secp384r1_sha512_p1363_test.json       | 277       | 204, 3, 70   | ECDSA
ecdsa_secp521r1_sha512_p1363_test.json       | 277       | 205, 3, 69   | ECDSA
ecdsa_webcrypto_test.json                    | 362       | 270, 10, 82  | ECDSA

## EcdsaVerify

Test vectors of type EcdsaVerify are meant for the verification of ASN encoded
ECDSA signatures.

Test vectors with "result" \: "valid" are valid signatures. Test vectors with
"result" \: "invalid" are invalid. Test vectors with "result" \: "acceptable"
are signatures that may or may not be rejected. The reasons for potential
rejection are described with labels. Weak parameters such as small curves, hash
functions weaker than the security of the curve are potential reasons.
Non-standard BER encodings are other reasons.

JSON schema\: ecdsa_verify_schema.json

Type of the test group\: [EcdsaTestGroup](types.md#ecdsatestgroup)

Type of the test vectors\:
[AsnSignatureTestVector](types.md#asnsignaturetestvector)

**name**                               | **tests** | **validity** | **algorithm** {.sortable}
-------------------------------------- | --------- | ------------ | -------------
ecdsa_brainpoolP224r1_sha224_test.json | 359       | 121, 2, 236  | ECDSA
ecdsa_brainpoolP256r1_sha256_test.json | 389       | 150, 0, 239  | ECDSA
ecdsa_brainpoolP320r1_sha384_test.json | 393       | 153, 1, 239  | ECDSA
ecdsa_brainpoolP384r1_sha384_test.json | 420       | 181, 0, 239  | ECDSA
ecdsa_brainpoolP512r1_sha512_test.json | 462       | 225, 0, 237  | ECDSA
ecdsa_secp224r1_sha224_test.json       | 356       | 118, 1, 237  | ECDSA
ecdsa_secp224r1_sha256_test.json       | 385       | 146, 0, 239  | ECDSA
ecdsa_secp224r1_sha3_224_test.json     | 384       | 146, 2, 236  | ECDSA
ecdsa_secp224r1_sha3_256_test.json     | 393       | 154, 2, 237  | ECDSA
ecdsa_secp224r1_sha3_512_test.json     | 458       | 219, 2, 237  | ECDSA
ecdsa_secp224r1_sha512_test.json       | 454       | 215, 1, 238  | ECDSA
ecdsa_secp256k1_sha256_test.json       | 380       | 142, 1, 237  | ECDSA
ecdsa_secp256k1_sha3_256_test.json     | 388       | 150, 1, 237  | ECDSA
ecdsa_secp256k1_sha3_512_test.json     | 454       | 215, 1, 238  | ECDSA
ecdsa_secp256k1_sha512_test.json       | 450       | 211, 1, 238  | ECDSA
ecdsa_secp256r1_sha256_test.json       | 387       | 147, 1, 239  | ECDSA
ecdsa_secp256r1_sha3_256_test.json     | 395       | 155, 1, 239  | ECDSA
ecdsa_secp256r1_sha3_512_test.json     | 461       | 220, 2, 239  | ECDSA
ecdsa_secp256r1_sha512_test.json       | 457       | 216, 1, 240  | ECDSA
ecdsa_secp384r1_sha384_test.json       | 408       | 168, 1, 239  | ECDSA
ecdsa_secp384r1_sha3_384_test.json     | 418       | 178, 0, 240  | ECDSA
ecdsa_secp384r1_sha3_512_test.json     | 450       | 209, 2, 239  | ECDSA
ecdsa_secp384r1_sha512_test.json       | 446       | 205, 2, 239  | ECDSA
ecdsa_secp521r1_sha3_512_test.json     | 449       | 210, 0, 239  | ECDSA
ecdsa_secp521r1_sha512_test.json       | 447       | 206, 0, 241  | ECDSA
ecdsa_test.json                        | 1575      | 1011, 5, 559 | ECDSA

## EddsaVerify

Test vectors of type EddsaVerify are intended for testing the verification of
Eddsa signatures.

JSON schema\: eddsa_verify_schema.json

Type of the test group\: [EddsaTestGroup](types.md#eddsatestgroup)

Type of the test vectors\: [SignatureTestVector](types.md#signaturetestvector)

**name**        | **tests** | **validity** | **algorithm** {.sortable}
--------------- | --------- | ------------ | -------------
ed448_test.json | 86        | 17, 0, 69    | EDDSA
eddsa_test.json | 145       | 84, 0, 61    | EDDSA

## HkdfTest

Test vector of type HkdfTest are intended for the verification of HKDF.

HKDF differs from other key derivation function because the function accepts
more parameters. I.e. the input for HKDF is a tuple (ikm, salt, info, size).

JSON schema\: hkdf_test_schema.json

Type of the test group\: [HkdfTestGroup](types.md#hkdftestgroup)

Type of the test vectors\: [HkdfTestVector](types.md#hkdftestvector)

**name**              | **tests** | **validity** | **algorithm** {.sortable}
--------------------- | --------- | ------------ | -------------
hkdf_sha1_test.json   | 106       | 103, 0, 3    | HKDF-SHA-1
hkdf_sha256_test.json | 105       | 102, 0, 3    | HKDF-SHA-256
hkdf_sha384_test.json | 102       | 99, 0, 3     | HKDF-SHA-384
hkdf_sha512_test.json | 102       | 99, 0, 3     | HKDF-SHA-512

## IndCpaTest

Test vectors of type IndCpaTest are intended for test that verify encryption and
decryption of symmetric ciphers without authentication.

JSON schema\: ind_cpa_test_schema.json

Type of the test group\: [IndCpaTestGroup](types.md#indcpatestgroup)

Type of the test vectors\: [IndCpaTestVector](types.md#indcpatestvector)

**name**                | **tests** | **validity** | **algorithm** {.sortable}
----------------------- | --------- | ------------ | -------------
aes_cbc_pkcs5_test.json | 183       | 72, 0, 111   | AES-CBC-PKCS5

## KeywrapTest

Test vectors of type Keywrap are intended for tests checking the wrapping and
unwrapping of key material.

Invalid test vectors may contain vectors with invalid sizes, or invalid
paddings. This is not ideal for testing whether unwrapping allows some padding
oracle. If there are key wrapping primitives that can be attacked when padding
oracles are present then we might add additional files just for checking against
padding attacks.

JSON schema\: keywrap_test_schema.json

Type of the test group\: [KeywrapTestGroup](types.md#keywraptestgroup)

Type of the test vectors\: [KeywrapTestVector](types.md#keywraptestvector)

**name**      | **tests** | **validity** | **algorithm** {.sortable}
------------- | --------- | ------------ | -------------
kw_test.json  | 162       | 36, 0, 126   | KW
kwp_test.json | 254       | 20, 60, 174  | KWP

## MacTest

Test vectors of type MacTest are intended for testing the generation and
verification of MACs.

Test vectors with invalid MACs may contain vectors that contain invalid tags,
invalid parameters or invalid formats. Hence they are not ideal for testing if
an implementation is susceptible to padding attacks. Future version might
include separate files to simplify such tests.

JSON schema\: mac_test_schema.json

Type of the test group\: [MacTestGroup](types.md#mactestgroup)

Type of the test vectors\: [MacTestVector](types.md#mactestvector)

**name**                | **tests** | **validity** | **algorithm** {.sortable}
----------------------- | --------- | ------------ | -------------
aes_cmac_test.json      | 308       | 60, 0, 248   | AES-CMAC
hmac_sha1_test.json     | 170       | 66, 0, 104   | HMACSHA1
hmac_sha224_test.json   | 172       | 66, 0, 106   | HMACSHA224
hmac_sha256_test.json   | 174       | 66, 0, 108   | HMACSHA256
hmac_sha384_test.json   | 174       | 66, 0, 108   | HMACSHA384
hmac_sha3_224_test.json | 172       | 66, 0, 106   | HMACSHA3-224
hmac_sha3_256_test.json | 174       | 66, 0, 108   | HMACSHA3-256
hmac_sha3_384_test.json | 174       | 66, 0, 108   | HMACSHA3-384
hmac_sha3_512_test.json | 174       | 66, 0, 108   | HMACSHA3-512
hmac_sha512_test.json   | 174       | 66, 0, 108   | HMACSHA512

## MacWithIvTest

MacWithIvTest is intended for testing MACs that use an IV for randomization.

In some cases the MAC is only secure if each MAC computation uses a distinct IV.
Reusing the same IV multiple times may leak key material. Examples are GMAC and
VMAC.

JSON schema\: mac_with_iv_test_schema.json

Type of the test group\: [MacWithIvTestGroup](types.md#macwithivtestgroup)

Type of the test vectors\: [MacWithIvTestVector](types.md#macwithivtestvector)

**name**           | **tests** | **validity** | **algorithm** {.sortable}
------------------ | --------- | ------------ | -------------
gmac_test.json     | 449       | 102, 0, 347  | AES-GMAC
vmac_128_test.json | 764       | 424, 0, 340  | VMAC-AES
vmac_64_test.json  | 764       | 508, 0, 256  | VMAC-AES

## PrimalityTest

Test vector of type PrimalityTest are intended for testing primality tests.

JSON schema\: primality_test_schema.json

Type of the test group\: [PrimalityTestGroup](types.md#primalitytestgroup)

Type of the test vectors\: [PrimalityTestVector](types.md#primalitytestvector)

**name**            | **tests** | **validity** | **algorithm** {.sortable}
------------------- | --------- | ------------ | -------------
primality_test.json | 280       | 66, 8, 206   | PrimalityTest

## RsaesOaepDecrypt

Test vectors of type RsaOeapDecrypt are intended to check the decryption of RSA
encrypted ciphertexts.

The test vectors contain ciphertexts with invalid format (i.e. incorrect size)
and test vectors with invalid padding. Hence the test vectors are a bit
inconvenient to detect padding oracles. One potential plan is to generate
separate, new files that only contain ciphertexts with invalid paddings.

JSON schema\: rsaes_oaep_decrypt_schema.json

Type of the test group\: [RsaesOaepTestGroup](types.md#rsaesoaeptestgroup)

Type of the test vectors\: [RsaesOaepTestVector](types.md#rsaesoaeptestvector)

**name**                                  | **tests** | **validity** | **algorithm** {.sortable}
----------------------------------------- | --------- | ------------ | -------------
rsa_oaep_2048_sha1_mgf1sha1_test.json     | 34        | 17, 0, 17    | RSAES-OAEP
rsa_oaep_2048_sha224_mgf1sha1_test.json   | 29        | 13, 0, 16    | RSAES-OAEP
rsa_oaep_2048_sha224_mgf1sha224_test.json | 33        | 17, 0, 16    | RSAES-OAEP
rsa_oaep_2048_sha256_mgf1sha1_test.json   | 29        | 13, 0, 16    | RSAES-OAEP
rsa_oaep_2048_sha256_mgf1sha256_test.json | 35        | 18, 0, 17    | RSAES-OAEP
rsa_oaep_2048_sha384_mgf1sha1_test.json   | 29        | 13, 0, 16    | RSAES-OAEP
rsa_oaep_2048_sha384_mgf1sha384_test.json | 32        | 16, 0, 16    | RSAES-OAEP
rsa_oaep_2048_sha512_mgf1sha1_test.json   | 29        | 13, 0, 16    | RSAES-OAEP
rsa_oaep_2048_sha512_mgf1sha512_test.json | 31        | 14, 0, 17    | RSAES-OAEP
rsa_oaep_3072_sha256_mgf1sha1_test.json   | 30        | 13, 0, 17    | RSAES-OAEP
rsa_oaep_3072_sha256_mgf1sha256_test.json | 35        | 18, 0, 17    | RSAES-OAEP
rsa_oaep_3072_sha512_mgf1sha1_test.json   | 29        | 13, 0, 16    | RSAES-OAEP
rsa_oaep_3072_sha512_mgf1sha512_test.json | 31        | 15, 0, 16    | RSAES-OAEP
rsa_oaep_4096_sha256_mgf1sha1_test.json   | 30        | 13, 0, 17    | RSAES-OAEP
rsa_oaep_4096_sha256_mgf1sha256_test.json | 35        | 18, 0, 17    | RSAES-OAEP
rsa_oaep_4096_sha512_mgf1sha1_test.json   | 29        | 13, 0, 16    | RSAES-OAEP
rsa_oaep_4096_sha512_mgf1sha512_test.json | 34        | 17, 0, 17    | RSAES-OAEP
rsa_oaep_misc_test.json                   | 775       | 460, 315, 0  | RSAES-OAEP

## RsaesPkcs1Decrypt

Test vectors of type RsaesPkcs1Decrypt are intended to check the decryption of
RSA encrypted ciphertexts.

The test vectors contain ciphertexts with invalid format (i.e. incorrect size)
and test vectors with invalid padding. Hence the test vectors are a bit
inconvenient to detect padding oracles. One potential plan is to generate
separate, new files that only contain ciphertexts with invalid paddings.

JSON schema\: rsaes_pkcs1_decrypt_schema.json

Type of the test group\: [RsaesPkcs1TestGroup](types.md#rsaespkcs1testgroup)

Type of the test vectors\: [RsaesPkcs1TestVector](types.md#rsaespkcs1testvector)

**name**                 | **tests** | **validity** | **algorithm** {.sortable}
------------------------ | --------- | ------------ | -------------
rsa_pkcs1_2048_test.json | 65        | 42, 0, 23    | RSAES-PKCS1-v1_5
rsa_pkcs1_3072_test.json | 65        | 41, 0, 24    | RSAES-PKCS1-v1_5
rsa_pkcs1_4096_test.json | 65        | 41, 0, 24    | RSAES-PKCS1-v1_5

## RsassaPkcs1Generate

Test vectors of class RsassaPkcs1Generate are intended for checking the
generation of RSA PKCS #1 v 1.5 signatures.

The test vectors only provide limited coverage for signature verification, since
a frequent flaw in implementations is to only check the padding partially.

JSON schema\: rsassa_pkcs1_generate_schema.json

Type of the test group\:
[RsassaPkcs1GenTestGroup](types.md#rsassapkcs1gentestgroup)

Type of the test vectors\: [SignatureTestVector](types.md#signaturetestvector)

**name**                   | **tests** | **validity** | **algorithm** {.sortable}
-------------------------- | --------- | ------------ | -------------
rsa_sig_gen_misc_test.json | 158       | 80, 78, 0    | RSASSA-PKCS1-v1_5

## RsassaPkcs1Verify

Test vectors of class RsassaPkcs1Verify are intended for checking the
verification of RSA PKCS #1 v 1.5 signatures.

RSA signature verification should generally be very strict about checking the
padding. Because of this most RSA signatures with a slightly modified padding
have "result" \: "invalid". Only a small number of RSA signatures implementing
legacy behaviour (such as a missing NULL in the encoding) have "result" \:
"acceptable".

JSON schema\: rsassa_pkcs1_verify_schema.json

Type of the test group\: [RsassaPkcs1TestGroup](types.md#rsassapkcs1testgroup)

Type of the test vectors\: [SignatureTestVector](types.md#signaturetestvector)

**name**                                | **tests** | **validity** | **algorithm** {.sortable}
--------------------------------------- | --------- | ------------ | -------------
rsa_signature_2048_sha224_test.json     | 241       | 7, 1, 233    | RSASSA-PKCS1-v1_5
rsa_signature_2048_sha256_test.json     | 240       | 7, 3, 230    | RSASSA-PKCS1-v1_5
rsa_signature_2048_sha384_test.json     | 252       | 7, 1, 244    | RSASSA-PKCS1-v1_5
rsa_signature_2048_sha3_224_test.json   | 249       | 7, 1, 241    | RSASSA-PKCS1-v1_5
rsa_signature_2048_sha3_256_test.json   | 248       | 7, 1, 240    | RSASSA-PKCS1-v1_5
rsa_signature_2048_sha3_384_test.json   | 249       | 7, 1, 241    | RSASSA-PKCS1-v1_5
rsa_signature_2048_sha3_512_test.json   | 249       | 7, 1, 241    | RSASSA-PKCS1-v1_5
rsa_signature_2048_sha512_224_test.json | 252       | 7, 1, 244    | RSASSA-PKCS1-v1_5
rsa_signature_2048_sha512_256_test.json | 251       | 7, 1, 243    | RSASSA-PKCS1-v1_5
rsa_signature_2048_sha512_test.json     | 240       | 7, 2, 231    | RSASSA-PKCS1-v1_5
rsa_signature_3072_sha256_test.json     | 239       | 7, 2, 230    | RSASSA-PKCS1-v1_5
rsa_signature_3072_sha384_test.json     | 239       | 7, 1, 231    | RSASSA-PKCS1-v1_5
rsa_signature_3072_sha3_256_test.json   | 248       | 7, 1, 240    | RSASSA-PKCS1-v1_5
rsa_signature_3072_sha3_384_test.json   | 249       | 7, 1, 241    | RSASSA-PKCS1-v1_5
rsa_signature_3072_sha3_512_test.json   | 249       | 7, 1, 241    | RSASSA-PKCS1-v1_5
rsa_signature_3072_sha512_256_test.json | 251       | 7, 1, 243    | RSASSA-PKCS1-v1_5
rsa_signature_3072_sha512_test.json     | 240       | 7, 2, 231    | RSASSA-PKCS1-v1_5
rsa_signature_4096_sha384_test.json     | 239       | 7, 1, 231    | RSASSA-PKCS1-v1_5
rsa_signature_4096_sha512_256_test.json | 251       | 7, 1, 243    | RSASSA-PKCS1-v1_5
rsa_signature_4096_sha512_test.json     | 239       | 7, 1, 231    | RSASSA-PKCS1-v1_5
rsa_signature_test.json                 | 377       | 84, 63, 230  | RSASSA-PKCS1-v1_5

## RsassaPssVerify

Test vectors of class RsassaPssVerify are intended for checking the verification
of RSASSA-PSS signatures.

RSA signature verification should generally be very strict about checking the
padding. Because of this RSASSA-PSS signatures with a modified padding have
"result" \: "invalid".

JSON schema\: rsassa_pss_verify_schema.json

Type of the test group\: [RsassaPssTestGroup](types.md#rsassapsstestgroup)

Type of the test vectors\: [RsassaPssTestVector](types.md#rsassapsstestvector)

**name**                                  | **tests** | **validity** | **algorithm** {.sortable}
----------------------------------------- | --------- | ------------ | -------------
rsa_pss_2048_sha1_mgf1_20_test.json       | 82        | 0, 42, 40    | RSASSA-PSS
rsa_pss_2048_sha256_mgf1_0_test.json      | 100       | 61, 0, 39    | RSASSA-PSS
rsa_pss_2048_sha256_mgf1_32_test.json     | 103       | 63, 0, 40    | RSASSA-PSS
rsa_pss_2048_sha512_256_mgf1_28_test.json | 50        | 9, 0, 41     | RSASSA-PSS
rsa_pss_2048_sha512_256_mgf1_32_test.json | 49        | 9, 0, 40     | RSASSA-PSS
rsa_pss_3072_sha256_mgf1_32_test.json     | 103       | 63, 0, 40    | RSASSA-PSS
rsa_pss_4096_sha256_mgf1_32_test.json     | 103       | 63, 0, 40    | RSASSA-PSS
rsa_pss_4096_sha512_mgf1_32_test.json     | 171       | 132, 0, 39   | RSASSA-PSS
rsa_pss_misc_test.json                    | 150       | 120, 30, 0   | RSASSA-PSS

## XdhAsnComp

Test vectors of type XdhComp are intended for tests that verify the computation
of and Xdh key exchange.

Public and private keys are ASN encoded.

JSON schema\: xdh_asn_comp_schema.json

Type of the test group\: [XdhAsnTestGroup](types.md#xdhasntestgroup)

Type of the test vectors\: [XdhAsnTestVector](types.md#xdhasntestvector)

**name**             | **tests** | **validity** | **algorithm** {.sortable}
-------------------- | --------- | ------------ | -------------
x25519_asn_test.json | 535       | 265, 253, 17 | XDH
x448_asn_test.json   | 527       | 253, 257, 17 | XDH

## XdhComp

Test vectors of type XdhComp are intended for tests that verify the computation
of and Xdh key exchange.

Both public and private key in the test vectors are just raw bytes. There are
separate files, where the keys are ASN.1 encoded or use the webcrypto encoding.

JSON schema\: xdh_comp_schema.json

Type of the test group\: [XdhTestGroup](types.md#xdhtestgroup)

Type of the test vectors\: [XdhTestVector](types.md#xdhtestvector)

**name**         | **tests** | **validity** | **algorithm** {.sortable}
---------------- | --------- | ------------ | -------------
x25519_test.json | 518       | 265, 253, 0  | XDH
x448_test.json   | 510       | 253, 257, 0  | XDH

## XdhJwkComp

Test vectors of type XdhComp are intended for tests that verify the computation
of and Xdh key exchange.

The public and private keys in these test vectors use the webcrypto encoding.

JSON schema\: xdh_jwk_comp_schema.json

Type of the test group\: [XdhJwkTestGroup](types.md#xdhjwktestgroup)

Type of the test vectors\: [XdhJwkTestVector](types.md#xdhjwktestvector)

**name**             | **tests** | **validity** | **algorithm** {.sortable}
-------------------- | --------- | ------------ | -------------
x25519_jwk_test.json | 531       | 265, 253, 13 | XDH
x448_jwk_test.json   | 523       | 253, 257, 13 | XDH

## XdhPemComp

Test vectors of type XdhPemComp are intended for verifying XDH.

Public and private keys are PEM encoded. The tests inlcude vectors generated for
edge cases, arithmetic overflows, points on twists and public keys for the wrong
curve. The tests do not include invalid PEM formats, though such tests may be
added in the future.

JSON schema\: xdh_pem_comp_schema.json

Type of the test group\: [XdhPemTestGroup](types.md#xdhpemtestgroup)

Type of the test vectors\: [XdhPemTestVector](types.md#xdhpemtestvector)

**name**             | **tests** | **validity** | **algorithm** {.sortable}
-------------------- | --------- | ------------ | -------------
x25519_pem_test.json | 518       | 265, 253, 0  | XDH
x448_pem_test.json   | 510       | 253, 257, 0  | XDH
