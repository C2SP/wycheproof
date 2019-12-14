<!-- AUTO-GENERATED FILE; DO NOT MODIFY -->

# Test vector types

Version\: 0.8rc21

[TOC]

## AeadTestGroup

A test group for authenticated encryption with additional data.

Fields in AeadTestGroup are\:

**name** | **type**                                          | **desc**                                                                                                                                                                                                                                                                                                         | **enum**
-------- | ------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------
ivSize   | int                                               | The IV size in bits. All IV sizes are multiple of 8 bits.                                                                                                                                                                                                                                                        |
keySize  | int                                               | the keySize in bits                                                                                                                                                                                                                                                                                              |
tagSize  | int                                               | The expected size of the tag in bits. This is the size that should be used to initialize instance of the cipher. The actual tag in the test vector may have a different size. Such a test vector is always invalid and an implementation is expected to reject such tags. All tag sizes are multiples of 8 bits. |
type     | str                                               | the type of the test                                                                                                                                                                                                                                                                                             | '[AeadTest](files.md#aeadtest)'
tests    | List of [AeadTestVector](types.md#aeadtestvector) | a list of test vectors                                                                                                                                                                                                                                                                                           |

## AeadTestVector

A test vector for authenticated encryption with additional data.

Fields additional to the fields in TestVector are\:

**name** | **type**                          | **desc**
-------- | --------------------------------- | --------
key      | [HexBytes](formats.md#data-types) | the key
iv       | [HexBytes](formats.md#data-types) | the nonce
aad      | [HexBytes](formats.md#data-types) | additional authenticated data
msg      | [HexBytes](formats.md#data-types) | the plaintext
ct       | [HexBytes](formats.md#data-types) | the ciphertext (without iv and tag)
tag      | [HexBytes](formats.md#data-types) | The authenticatian tag. Most encryption append the tag to the ciphertext. Encryption results in the concatenation ct \|\| tag and decryption expects ct \|\| tag as input. There are however some exceptions. For example AEAD-AES-SIV-CMAC (RFC 5297) computes a synthetic IV (SIV), which is used to initialize the counter for AES. The typical encoding here is to prepend the SIV. I.e. implementations would expect ciphertext of the form tag \|\| ct or iv \|\| tag \|\| ct.

Used in [AeadTestGroup](#aeadtestgroup).

## AsnSignatureTestVector

A test vector with an ASN.1 encoded public key signature. For example, ECDSA and
DSA signatures are a pair of integers (r,s). These integers can be encoded in
different ways. A popular encoding is to represent the integers as an ASN
Sequence. The expectation is that any library generates only DER encoded
signatures. Some libraries are also strict in the sense that only DER encoded
signautes are accepted. Other libraries accept some signatures where the pair
(r,s) uses an alternative BER encoding assuming of course that the encoded (r,s)
is valid.

Fields additional to the fields in TestVector are\:

**name** | **type**                          | **desc**
-------- | --------------------------------- | --------------------------------
msg      | [HexBytes](formats.md#data-types) | The message to sign
sig      | Asn                               | An ASN encoded signature for msg

Used in [DsaTestGroup](#dsatestgroup),
[EcdsaBitcoinTestGroup](#ecdsabitcointestgroup),
[EcdsaTestGroup](#ecdsatestgroup).

## DaeadTestGroup

Fields in DaeadTestGroup are\:

**name** | **type**                                            | **desc**               | **enum**
-------- | --------------------------------------------------- | ---------------------- | --------
keySize  | int                                                 | the keySize in bits    |
type     | str                                                 | the type of the test   | '[DaeadTest](files.md#daeadtest)'
tests    | List of [DaeadTestVector](types.md#daeadtestvector) | a list of test vectors |

## DaeadTestVector

A test vector used for authenticated deterministic encryption with additional
data.

Fields additional to the fields in TestVector are\:

**name** | **type**                          | **desc**
-------- | --------------------------------- | -----------------------------
key      | [HexBytes](formats.md#data-types) | the key
aad      | [HexBytes](formats.md#data-types) | additional authenticated data
msg      | [HexBytes](formats.md#data-types) | the plaintext
ct       | [HexBytes](formats.md#data-types) | the ciphertext including tag

Used in [DaeadTestGroup](#daeadtestgroup).

## DsaP1363TestGroup

A test group for DSA signatures using IEEE P1363 encoding. The test vectors in
this group are meant for signature verification. The test group contains the
same public key for the signatures in multiple representations. The public keys
are valid with the sole exception that they may use short keys and weak hash
functions such as SHA-1.

Fields in DsaP1363TestGroup are\:

**name** | **type**                                                    | **desc**                       | **enum**
-------- | ----------------------------------------------------------- | ------------------------------ | --------
key      | DsaPublicKey                                                | unencoded EC public key        |
keyDer   | [Der](formats.md#data-types)                                | DER encoded public key         |
keyPem   | [Pem](formats.md#data-types)                                | Pem encoded public key         |
sha      | [MdName](formats.md#hash-functions)                         | the hash function used for DSA |
type     | str                                                         | the type of the test           | '[DsaP1363Verify](files.md#dsap1363verify)'
tests    | List of [SignatureTestVector](types.md#signaturetestvector) | a list of test vectors         |

## DsaPrivateKey

A DSA private key. This implementation of DSA must only be used for testing rsp.
for generating test vectors. It has not been checked for flaws and in some cases
may even avoid necessary checks so that it can be used for flawed test vectors.

**name** | **type**                        | **desc**                                     | **enum**
-------- | ------------------------------- | -------------------------------------------- | --------
g        | [BigInt](formats.md#data-types) | the generator of the multiplicative subgroup |
keySize  | int                             | the key size in bits                         |
p        | [BigInt](formats.md#data-types) | the modulus p                                |
q        | [BigInt](formats.md#data-types) | the order of the generator g                 |
type     | str                             | the key type                                 | 'DsaPrivateKey'
x        | [BigInt](formats.md#data-types) | the private key value                        |
y        | [BigInt](formats.md#data-types) | the public key value                         |

## DsaPublicKey

The public key for DSA.

**name** | **type**                        | **desc**                                     | **enum**
-------- | ------------------------------- | -------------------------------------------- | --------
g        | [BigInt](formats.md#data-types) | the generator of the multiplicative subgroup |
keySize  | int                             | the key size in bits                         |
p        | [BigInt](formats.md#data-types) | the modulus p                                |
q        | [BigInt](formats.md#data-types) | the order of the generator g                 |
type     | str                             | the key type                                 | 'DsaPublicKey'
y        | [BigInt](formats.md#data-types) | the public key value                         |

## DsaTestGroup

Fields in DsaTestGroup are\:

**name** | **type**                                                          | **desc**                       | **enum**
-------- | ----------------------------------------------------------------- | ------------------------------ | --------
key      | DsaPublicKey                                                      | unencoded DSA public key       |
keyDer   | [Der](formats.md#data-types)                                      | DER encoded public key         |
keyPem   | [Pem](formats.md#data-types)                                      | Pem encoded public key         |
sha      | [MdName](formats.md#hash-functions)                               | the hash function used for DSA |
type     | str                                                               | the type of the test           | '[DsaVerify](files.md#dsaverify)'
tests    | List of [AsnSignatureTestVector](types.md#asnsignaturetestvector) | a list of test vectors         |

## EcPointTestGroup

Fields in EcPointTestGroup are\:

**name** | **type**                                                | **desc**                       | **enum**
-------- | ------------------------------------------------------- | ------------------------------ | --------
curve    | [EcCurve](formats.md#elliptic-curves)                   | the name of the elliptic curve |
encoding | str                                                     | the encoding used              | 'compressed', 'uncompressed'
type     | str                                                     | the type of the test           | '[EcPointTest](files.md#ecpointtest)'
tests    | List of [EcPointTestVector](types.md#ecpointtestvector) | a list of test vectors         |

## EcPointTestVector

Fields additional to the fields in TestVector are\:

**name** | **type**                          | **desc**
-------- | --------------------------------- | -------------------------------
encoded  | [HexBytes](formats.md#data-types) | X509 encoded point on the curve
x        | [BigInt](formats.md#data-types)   | x-coordinate of the point
y        | [BigInt](formats.md#data-types)   | y-coordinate of the point

Used in [EcPointTestGroup](#ecpointtestgroup).

## EcPublicKey

An EC public key. The EC public key can specify the underlying curve parameters
in two ways. (1) as a named curve (2) as a structure containing the curve
parameters generator, order and cofactor.

**name**     | **type**                          | **desc**                                            | **enum**
------------ | --------------------------------- | --------------------------------------------------- | --------
curve        | (EcUnnamedGroup or EcNamedGroup)  | the EC group used by this public key                |
keySize      | int                               | the key size in bits                                |
type         | str                               | the key type                                        | 'EcPublicKey'
uncompressed | [HexBytes](formats.md#data-types) | X509 encoded public key point in hexadecimal format |
wx           | [BigInt](formats.md#data-types)   | the x-coordinate of the public key point            |
wy           | [BigInt](formats.md#data-types)   | the y-coordinate of the public key point            |

## EcPublicKeyOnNamedCurve

An EC public key. This data type allows only named curves to specify the
underlying EC parameters.

**name**     | **type**                          | **desc**                                            | **enum**
------------ | --------------------------------- | --------------------------------------------------- | --------
curve        | EcNamedGroup                      | the EC group used by this public key                |
keySize      | int                               | the key size in bits                                |
type         | str                               | the key type                                        | 'EcPublicKey'
uncompressed | [HexBytes](formats.md#data-types) | X509 encoded public key point in hexadecimal format |
wx           | [BigInt](formats.md#data-types)   | the x-coordinate of the public key point            |
wy           | [BigInt](formats.md#data-types)   | the y-coordinate of the public key point            |

## EcPublicKeyTestGroup

Fields in EcPublicKeyTestGroup are\:

**name** | **type**                                                        | **desc**                         | **enum**
-------- | --------------------------------------------------------------- | -------------------------------- | --------
encoding | str                                                             | the encoding of the encoded keys | 'asn', 'pem', 'webcrypto'
type     | str                                                             | the type of the test             | '[EcPublicKeyVerify](files.md#ecpublickeyverify)'
tests    | List of [EcPublicKeyTestVector](types.md#ecpublickeytestvector) | a list of test vectors           |

## EcPublicKeyTestVector

Draft version for test vectors that test importing of EC public keys. The test
vectors contain modified EC public keys. The goal of the test is to recognize if
importing the EC public keys notices inconsistencies and bad formatting.

Fields additional to the fields in TestVector are\:

**name** | **type**                        | **desc**
-------- | ------------------------------- | --------
encoded  | [Asn](formats.md#data-types)    | Encoded EC public key over a prime order field
p        | [BigInt](formats.md#data-types) | The order of underlying field
n        | [BigInt](formats.md#data-types) | The order of the generator
a        | [BigInt](formats.md#data-types) | The value a of the Weierstrass equation
b        | [BigInt](formats.md#data-types) | The value b of the Weierstrass equation
gx       | [BigInt](formats.md#data-types) | x-coordinate of the generator
gy       | [BigInt](formats.md#data-types) | y-coordinate of the generator
h        | (int or null)                   | [optional] the cofactor
wx       | [BigInt](formats.md#data-types) | x-coordinate of the public point
wy       | [BigInt](formats.md#data-types) | y-coordinate of the public point

Used in [EcPublicKeyTestGroup](#ecpublickeytestgroup).

## EcUnnamedGroup

An unamed EC group

**name** | **type**                        | **desc**                                                   | **enum**
-------- | ------------------------------- | ---------------------------------------------------------- | --------
a        | [BigInt](formats.md#data-types) | coefficient a of the elliptic curve equation               |
b        | [BigInt](formats.md#data-types) | coefficient b of the elliptic curve equation               |
gx       | [BigInt](formats.md#data-types) | the x-coordinate of the generator                          |
gy       | [BigInt](formats.md#data-types) | the y-coordinate of the generator                          |
h        | int                             | the cofactor                                               |
n        | [BigInt](formats.md#data-types) | the order of the generator                                 |
p        | [BigInt](formats.md#data-types) | the order of the underlying field                          |
type     | str                             | an unnamed EC group over a prime field in Weierstrass form | 'PrimeOrderCurve'

## EcdhEcpointTestGroup

Fields in EcdhEcpointTestGroup are\:

**name** | **type**                                                        | **desc**                       | **enum**                                      | **optional**
-------- | --------------------------------------------------------------- | ------------------------------ | --------------------------------------------- | ------------
curve    | [EcCurve](formats.md#elliptic-curves)                           | the curve of the private key   |                                               |
encoding | str                                                             | the encoding of the public key | 'ecpoint'                                     | True
type     | str                                                             | the type of the test           | '[EcdhEcpointTest](files.md#ecdhecpointtest)' |
tests    | List of [EcdhEcpointTestVector](types.md#ecdhecpointtestvector) | a list of test vectors         |                                               |

## EcdhEcpointTestVector

Fields additional to the fields in TestVector are\:

**name** | **type**                          | **desc**                 | **ref**
-------- | --------------------------------- | ------------------------ | -------
public   | [Asn](formats.md#data-types)      | ASN encoded public point | X9.62, Section 4.3.6
private  | [BigInt](formats.md#data-types)   | The private exponent     |
shared   | [HexBytes](formats.md#data-types) | The shared secret key    |

Used in [EcdhEcpointTestGroup](#ecdhecpointtestgroup).

## EcdhPemTestGroup

Fields in EcdhPemTestGroup are\:

**name** | **type**                                                | **desc**                     | **enum**                              | **optional**
-------- | ------------------------------------------------------- | ---------------------------- | ------------------------------------- | ------------
curve    | [EcCurve](formats.md#elliptic-curves)                   | the curve of the private key |                                       |
encoding | str                                                     | the encoding of the keys     | 'pem'                                 | True
type     | str                                                     | the type of the test         | '[EcdhPemTest](files.md#ecdhpemtest)' |
tests    | List of [EcdhPemTestVector](types.md#ecdhpemtestvector) | a list of test vectors       |                                       |

## EcdhPemTestVector

Fields additional to the fields in TestVector are\:

**name** | **type**                          | **desc**
-------- | --------------------------------- | --------
public   | [Pem](formats.md#data-types)      | Pem encoded public key. The test vectors check against invalid curve attacks. Hence some test vectors contain keys that are not on the curve, test vectors that use different curve or even public keys from different primitives.
private  | [Pem](formats.md#data-types)      | Pem encoded private key. The key is always valid.
shared   | [HexBytes](formats.md#data-types) | The shared secret key

Used in [EcdhPemTestGroup](#ecdhpemtestgroup).

## EcdhTestGroup

Fields in EcdhTestGroup are\:

**name** | **type**                                          | **desc**                                                                                                                                                                                                                                                                | **enum**                        | **optional**
-------- | ------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------- | ------------
curve    | [EcCurve](formats.md#elliptic-curves)             | the curve of the private key                                                                                                                                                                                                                                            |                                 |
encoding | str                                               | the encoding of the keys. There are test vector files for a number of encodings (raw, asn, pem, ...) to simplify testing libraries that only allow keys with certain encodings. This field however, has become somewhat redundant, since the schema defines the format. | 'asn'                           | True
type     | str                                               | the type of the test                                                                                                                                                                                                                                                    | '[EcdhTest](files.md#ecdhtest)' |
tests    | List of [EcdhTestVector](types.md#ecdhtestvector) | a list of test vectors                                                                                                                                                                                                                                                  |                                 |

## EcdhTestVector

Fields additional to the fields in TestVector are\:

**name** | **type**                          | **desc**
-------- | --------------------------------- | --------
public   | [Asn](formats.md#data-types)      | X509 encoded public key. The encoding of the public key contains the type of the public key, the curve and possibly the curve parameters. The test vectors contain cases where these fields do not match the curve in the testGroup.
private  | [BigInt](formats.md#data-types)   | the private key
shared   | [HexBytes](formats.md#data-types) | The shared secret key. Some invalid test vectors contain a shared secret, which is computed using the curve of the private key. This allows to distinguish between implementations ignoring public key info and implementations using the curve of the public key.

Used in [EcdhTestGroup](#ecdhtestgroup).

## EcdhWebcryptoTestGroup

Fields in EcdhWebcryptoTestGroup are\:

**name** | **type**                                                            | **desc**                     | **enum**                                          | **optional**
-------- | ------------------------------------------------------------------- | ---------------------------- | ------------------------------------------------- | ------------
curve    | [EcCurve](formats.md#elliptic-curves)                               | the curve of the private key |                                                   |
encoding | str                                                                 | the encoding of the keys     | 'webcrypto'                                       | True
type     | str                                                                 | the type of the test         | '[EcdhWebcryptoTest](files.md#ecdhwebcryptotest)' |
tests    | List of [EcdhWebcryptoTestVector](types.md#ecdhwebcryptotestvector) | a list of test vectors       |                                                   |

## EcdhWebcryptoTestVector

Fields additional to the fields in TestVector are\:

**name** | **type**                          | **desc**
-------- | --------------------------------- | --------
public   | Json                              | Valid or invalid public key in webcrypto format
private  | JwkEcPrivateKey                   | Private key in webcrypto format
shared   | [HexBytes](formats.md#data-types) | The shared secret key

Used in [EcdhWebcryptoTestGroup](#ecdhwebcryptotestgroup).

## EcdsaBitcoinTestGroup

A test group for the bitcoin variant of ECDSA signatures. The test vectors in
this group are meant for signature verification. The test group contains the
same public key for the signatures in multiple representations. The public keys
are valid.

Fields in EcdsaBitcoinTestGroup are\:

**name** | **type**                                                          | **desc**                         | **enum**
-------- | ----------------------------------------------------------------- | -------------------------------- | --------
key      | EcPublicKey                                                       | unencoded EC public key          |
keyDer   | [Der](formats.md#data-types)                                      | DER encoded public key           |
keyPem   | [Pem](formats.md#data-types)                                      | Pem encoded public key           |
sha      | [MdName](formats.md#hash-functions)                               | the hash function used for ECDSA | 'SHA-256'
type     | str                                                               | the type of the test             | '[EcdsaBitcoinVerify](files.md#ecdsabitcoinverify)'
tests    | List of [AsnSignatureTestVector](types.md#asnsignaturetestvector) | a list of test vectors           |

## EcdsaP1363TestGroup

A test group for ECDSA signatures using IEEE P1363 encoding. The test vectors in
this group are meant for signature verification. The test group contains the
same public key for the signatures in multiple representations. The public keys
are valid with the sole exception that they may use short keys and weak hash
functions such as SHA-1.

Fields in EcdsaP1363TestGroup are\:

**name** | **type**                                                    | **desc**                           | **optional** | **enum**
-------- | ----------------------------------------------------------- | ---------------------------------- | ------------ | --------
jwk      | JwkEcPublicKey                                              | the public key in webcrypto format | True         |
key      | EcPublicKey                                                 | unencoded EC public key            |              |
keyDer   | [Der](formats.md#data-types)                                | DER encoded public key             |              |
keyPem   | [Pem](formats.md#data-types)                                | Pem encoded public key             |              |
sha      | [MdName](formats.md#hash-functions)                         | the hash function used for ECDSA   |              |
type     | str                                                         | the type of the test               |              | '[EcdsaP1363Verify](files.md#ecdsap1363verify)'
tests    | List of [SignatureTestVector](types.md#signaturetestvector) | a list of test vectors             |              |

## EcdsaTestGroup

A test group for ECDSA signatures. The test vectors in this group are meant for
signature verification. The test group contains the same public key for the
signatures in multiple representations. The public keys are valid with the sole
exception that they may use short keys and weak hash functions such as SHA-1.

Fields in EcdsaTestGroup are\:

**name** | **type**                                                          | **desc**                         | **enum**
-------- | ----------------------------------------------------------------- | -------------------------------- | --------
key      | EcPublicKey                                                       | unencoded EC public key          |
keyDer   | [Der](formats.md#data-types)                                      | DER encoded public key           |
keyPem   | [Pem](formats.md#data-types)                                      | Pem encoded public key           |
sha      | [MdName](formats.md#hash-functions)                               | the hash function used for ECDSA |
type     | str                                                               | the type of the test             | '[EcdsaVerify](files.md#ecdsaverify)'
tests    | List of [AsnSignatureTestVector](types.md#asnsignaturetestvector) | a list of test vectors           |

## EddsaTestGroup

Fields in EddsaTestGroup are\:

**name** | **type**                                                    | **desc**                            | **since** | **ref**            | **enum**
-------- | ----------------------------------------------------------- | ----------------------------------- | --------- | ------------------ | --------
jwk      | Json                                                        | the private key in webcrypto format | 0.7       | RFC 8037 Section 2 |
key      | Json                                                        | unencoded key pair                  |           |                    |
keyDer   | [Der](formats.md#data-types)                                | Asn encoded public key              |           |                    |
keyPem   | [Pem](formats.md#data-types)                                | Pem encoded public key              |           |                    |
type     | str                                                         | the type of the test                |           |                    | '[EddsaVerify](files.md#eddsaverify)'
tests    | List of [SignatureTestVector](types.md#signaturetestvector) | a list of test vectors              |           |                    |

## HkdfTestGroup

A test group for key derivation functions that take 4 arguments (ikm, salt,
info, size) as input.

Fields in HkdfTestGroup are\:

**name** | **type**                                          | **desc**                    | **enum**
-------- | ------------------------------------------------- | --------------------------- | --------
keySize  | int                                               | the size of the ikm in bits |
type     | str                                               | the type of the test        | '[HkdfTest](files.md#hkdftest)'
tests    | List of [HkdfTestVector](types.md#hkdftestvector) | a list of test vectors      |

## HkdfTestVector

A test vector for HKDF (or any other key derivation function with input ikm,
salt, info, size

Fields additional to the fields in TestVector are\:

**name** | **type**                          | **desc**
-------- | --------------------------------- | --------
ikm      | [HexBytes](formats.md#data-types) | the key (input key material)
salt     | [HexBytes](formats.md#data-types) | the salt for the key derivation
info     | [HexBytes](formats.md#data-types) | additional information used in the key derivation
size     | int                               | the size of the output in bytes
okm      | [HexBytes](formats.md#data-types) | the generated bytes (output key material)

Used in [HkdfTestGroup](#hkdftestgroup).

## IndCpaTestGroup

Fields in IndCpaTestGroup are\:

**name** | **type**                                              | **desc**               | **enum**
-------- | ----------------------------------------------------- | ---------------------- | --------
ivSize   | int                                                   | the IV size in bits    |
keySize  | int                                                   | the keySize in bits    |
type     | str                                                   | the type of the test   | '[IndCpaTest](files.md#indcpatest)'
tests    | List of [IndCpaTestVector](types.md#indcpatestvector) | a list of test vectors |

## IndCpaTestVector

A test vector that is used for symmetric primitives that are indistinguishable
under chosen plaintext attacks. These primitives are without an integrity check
and hence without additional authenticated data. For example AES using cipher
block chaining (CBC) is tested using this format.

Fields additional to the fields in TestVector are\:

**name** | **type**                          | **desc**
-------- | --------------------------------- | -------------------------------
key      | [HexBytes](formats.md#data-types) | the key
iv       | [HexBytes](formats.md#data-types) | the initialization vector
msg      | [HexBytes](formats.md#data-types) | the plaintext
ct       | [HexBytes](formats.md#data-types) | the raw ciphertext (without IV)

Used in [IndCpaTestGroup](#indcpatestgroup).

## JwkEcPrivateKey

**name** | **type**                           | **desc**                             | **enum**
-------- | ---------------------------------- | ------------------------------------ | --------
crv      | str                                | the curve                            | 'P-256', 'P-384', 'P-521', 'P-256K'
d        | [Base64Url](formats.md#data-types) | The private multiplier               |
kid      | str                                | the key id                           |
kty      | str                                | the algorithm                        | 'EC'
use      | str                                | the purpose of the key               |
x        | [Base64Url](formats.md#data-types) | The x-coordinate of the public point |
y        | [Base64Url](formats.md#data-types) | The y-coordinate of the public point |

## JwkEcPublicKey

**name** | **type**                           | **desc**                             | **enum**
-------- | ---------------------------------- | ------------------------------------ | --------
crv      | str                                | the curve                            | 'P-256', 'P-384', 'P-521', 'P-256K'
kid      | str                                | the key id                           |
kty      | str                                | the algorithm                        | 'EC'
use      | str                                | the purpose of the key               |
x        | [Base64Url](formats.md#data-types) | The x-coordinate of the public point |
y        | [Base64Url](formats.md#data-types) | The y-coordinate of the public point |

## JwkRsaPrivateKey

**name** | **type**                           | **desc**                      | **enum**
-------- | ---------------------------------- | ----------------------------- | --------
d        | [Base64Url](formats.md#data-types) | the private exponent          |
dp       | [Base64Url](formats.md#data-types) | the value d % (p-1)           |
dq       | [Base64Url](formats.md#data-types) | the value d % (q-1)           |
e        | [Base64Url](formats.md#data-types) | the public exponent           |
kid      | str                                | the key identifier            |
kty      | str                                | the algorithm                 | 'RSA'
n        | [Base64Url](formats.md#data-types) | the modulus of the key        |
p        | [Base64Url](formats.md#data-types) | a prime factor of the modulus |
q        | [Base64Url](formats.md#data-types) | a prime factor of the modulus |
qi       | [Base64Url](formats.md#data-types) | the CRT value q^(-1) % p      |
use      | str                                | the purpose of the key        | 'sig', 'enc'

## JwkRsaPublicKey

**name** | **type**                           | **desc**               | **enum**
-------- | ---------------------------------- | ---------------------- | --------
e        | [Base64Url](formats.md#data-types) | the public exponent    |
kid      | str                                | the key identifier     |
kty      | str                                | the algorithm          | 'RSA'
n        | [Base64Url](formats.md#data-types) | the modulus of the key |
use      | str                                | the purpose of the key | 'sig', 'enc'

## JwkXdhPrivateKey

**name** | **type**                           | **desc**              | **enum**
-------- | ---------------------------------- | --------------------- | --------
crv      | str                                | the DH function       | 'X25519', 'X448'
d        | [Base64Url](formats.md#data-types) | the private key value |
kid      | str                                | the key identifier    |
kty      | str                                | the key type          | 'OKP'
x        | [Base64Url](formats.md#data-types) | the public key value  |

## JwkXdhPublicKey

**name** | **type**                           | **desc**             | **enum**
-------- | ---------------------------------- | -------------------- | --------
crv      | str                                | the DH function      | 'X25519', 'X448'
kid      | str                                | the key identifier   |
kty      | str                                | the key type         | 'OKP'
x        | [Base64Url](formats.md#data-types) | the public key value |

## KdfTestGroup

A test group for key derivation functions that take 2 arguments (seed, size) as
input.

Fields in KdfTestGroup are\:

**name** | **type**                                        | **desc**                     | **enum**
-------- | ----------------------------------------------- | ---------------------------- | --------
keySize  | int                                             | the size of the seed in bits |
type     | str                                             | the type of the test         | '[KdfTest](files.md#kdftest)'
tests    | List of [KdfTestVector](types.md#kdftestvector) | a list of test vectors       |

## KdfTestVector

A test vector for key derivation functions. I.e., these are deterministic
functions that take a seed and a size as input and generate a pseudorandom
output depending on the seed. (The size may simply determine the length of the
pseudorandom output or may change the pseudorandom stream).

Fields additional to the fields in TestVector are\:

**name** | **type**                          | **desc**
-------- | --------------------------------- | --------
seed     | [HexBytes](formats.md#data-types) | the seed
size     | int                               | the size of the output in bytes
okm      | [HexBytes](formats.md#data-types) | the generated bytes (output key material)

Used in [KdfTestGroup](#kdftestgroup).

## KeywrapTestGroup

Fields in KeywrapTestGroup are\:

**name** | **type**                                                | **desc**               | **enum**
-------- | ------------------------------------------------------- | ---------------------- | --------
keySize  | int                                                     | the keySize in bits    |
type     | str                                                     | the type of the test   | '[KeywrapTest](files.md#keywraptest)'
tests    | List of [KeywrapTestVector](types.md#keywraptestvector) | a list of test vectors |

## KeywrapTestVector

A test vector for key wrap primitives. Key wrap primitives are typically
symmetric encryptions that were specifically desigend for encrypting key
material. In some cases the input size is restricted to typical key sizes e.g. a
multiple of 8 bytes. The encryption may assume that the wrapped bytes have high
entropy. Hence some of the key wrap primitives are deterministic.

Fields additional to the fields in TestVector are\:

**name** | **type**                          | **desc**
-------- | --------------------------------- | ---------------------
key      | [HexBytes](formats.md#data-types) | the wrapping key
msg      | [HexBytes](formats.md#data-types) | the key bytes to wrap
ct       | [HexBytes](formats.md#data-types) | the wrapped key

Used in [KeywrapTestGroup](#keywraptestgroup).

## MacTestGroup

Fields in MacTestGroup are\:

**name** | **type**                                        | **desc**                             | **enum**
-------- | ----------------------------------------------- | ------------------------------------ | --------
keySize  | int                                             | the keySize in bits                  |
tagSize  | int                                             | the expected size of the tag in bits |
type     | str                                             | the type of the test                 | '[MacTest](files.md#mactest)'
tests    | List of [MacTestVector](types.md#mactestvector) | a list of test vectors               |

## MacTestVector

A test vector for message authentication codes (MAC).

Fields additional to the fields in TestVector are\:

**name** | **type**                          | **desc**
-------- | --------------------------------- | ----------------------
key      | [HexBytes](formats.md#data-types) | the key
msg      | [HexBytes](formats.md#data-types) | the plaintext
tag      | [HexBytes](formats.md#data-types) | the authentication tag

Used in [MacTestGroup](#mactestgroup).

## MacWithIvTestGroup

Fields in MacWithIvTestGroup are\:

**name** | **type**                                                    | **desc**                             | **enum**
-------- | ----------------------------------------------------------- | ------------------------------------ | --------
ivSize   | int                                                         | the IV size in bits                  |
keySize  | int                                                         | the key size in bits                 |
tagSize  | int                                                         | the expected size of the tag in bits |
type     | str                                                         | the type of the test                 | '[MacWithIvTest](files.md#macwithivtest)'
tests    | List of [MacWithIvTestVector](types.md#macwithivtestvector) | a list of test vectors               |

## MacWithIvTestVector

A test vector for message authentication codes (MAC) that use an IV.

Fields additional to the fields in TestVector are\:

**name** | **type**                          | **desc**
-------- | --------------------------------- | -------------------------
key      | [HexBytes](formats.md#data-types) | the key
iv       | [HexBytes](formats.md#data-types) | the initailisation vector
msg      | [HexBytes](formats.md#data-types) | the plaintext
tag      | [HexBytes](formats.md#data-types) | the authentication tag

Used in [MacWithIvTestGroup](#macwithivtestgroup).

## PbkdfTestGroup

A test group for key derivation functions that take 4 arguments (password, salt,
iteration count and output size) as input.

Fields in PbkdfTestGroup are\:

**name** | **type**                                            | **desc**               | **enum**
-------- | --------------------------------------------------- | ---------------------- | --------
type     | str                                                 | the type of the test   | '[PbkdfTest](files.md#pbkdftest)'
tests    | List of [PbkdfTestVector](types.md#pbkdftestvector) | a list of test vectors |

## PbkdfTestVector

A test vector for PBKDF (or any other key derivation function with input
password, salt, iteration count, size.

Fields additional to the fields in TestVector are\:

**name**       | **type**                          | **desc**
-------------- | --------------------------------- | --------
password       | [HexBytes](formats.md#data-types) | the password
salt           | [HexBytes](formats.md#data-types) | the salt
iterationCount | int                               | the iteration count
dkLen          | int                               | the intended length of the output in bytes
dk             | [HexBytes](formats.md#data-types) | the derived key

Used in [PbkdfTestGroup](#pbkdftestgroup).

## PrimalityTestGroup

A test group for primality tests.

Fields in PrimalityTestGroup are\:

**name** | **type**                                                    | **desc**               | **enum**
-------- | ----------------------------------------------------------- | ---------------------- | --------
type     | str                                                         | the type of the test   | '[PrimalityTest](files.md#primalitytest)'
tests    | List of [PrimalityTestVector](types.md#primalitytestvector) | a list of test vectors |

## PrimalityTestVector

A test vector for a primality test. The result is valid if value is prime and
invalid if it is 0, 1, -1 or composite. The status of the negative of a prime is
somewhat unlclear. Some libraries accept them as primes. Because of this the
negative of a prime has result "acceptable".

Fields additional to the fields in TestVector are\:

**name** | **type**                        | **desc**
-------- | ------------------------------- | -------------------
value    | [BigInt](formats.md#data-types) | the integer to test

Used in [PrimalityTestGroup](#primalitytestgroup).

## RsaPrivateKey

Describes an RSA private key. The data type is based on the RSAPrivateKey type
defined in Section A.1.2 of RFC 8017.

**name**        | **type**                                        | **desc**                                                                                                                              | **enum**
--------------- | ----------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------- | --------
coefficient     | [BigInt](formats.md#data-types)                 | the CRT value q^(-1) % p                                                                                                              |
exponent1       | [BigInt](formats.md#data-types)                 | the value d % (p-1)                                                                                                                   |
exponent2       | [BigInt](formats.md#data-types)                 | the value d % (q-1)                                                                                                                   |
modulus         | [BigInt](formats.md#data-types)                 | the modulus of the key                                                                                                                |
otherPrimeInfos | list of list of [BigInt](formats.md#data-types) | list of triples [prime, exponent, coefficient]                                                                                        |
prime1          | [BigInt](formats.md#data-types)                 | p: a prime factor of the modulus                                                                                                      |
prime2          | [BigInt](formats.md#data-types)                 | q: a prime factor of the modulus                                                                                                      |
privateExponent | [BigInt](formats.md#data-types)                 | the private exponent                                                                                                                  |
publicExponent  | [BigInt](formats.md#data-types)                 | the public exponent                                                                                                                   |
version         | int                                             | The version of the private key. This is 0 for keys with no otherPrimeInfos and 1 for keys with otherPrimeInfos, i.e. multiprime keys. | 0, 1

## RsaPublicKey

Describes an RSA private key. The data type is based on the RSAPublicKey type
defined in Appendix C of RFC 8017.

**name**       | **type**                        | **desc**                                                                                                                              | **enum**
-------------- | ------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------- | --------
modulus        | [BigInt](formats.md#data-types) | the modulus of the key                                                                                                                |
publicExponent | [BigInt](formats.md#data-types) | the public exponent                                                                                                                   |
version        | int                             | The version of the private key. This is 0 for keys with no otherPrimeInfos and 1 for keys with otherPrimeInfos, i.e. multiprime keys. | 0, 1

## RsaPublicKeyAsnTestGroup

Fields in RsaPublicKeyAsnTestGroup are\:

**name**        | **type**                                                                | **desc**                    | **enum**
--------------- | ----------------------------------------------------------------------- | --------------------------- | --------
privateKey      | RsaPrivateKey                                                           | the private key             |
privateKeyPkcs8 | [Der](formats.md#data-types)                                            | PKCS #8 encoded private key |
publicKeyAsn    | [Der](formats.md#data-types)                                            | the X509 encoded public key |
type            | str                                                                     | the type of the test        | '[RsaPublicKeyAsnTest](files.md#rsapublickeyasntest)'
tests           | List of [RsaPublicKeyAsnTestVector](types.md#rsapublickeyasntestvector) | a list of test vectors      |

## RsaPublicKeyAsnTestVector

Fields additional to the fields in TestVector are\:

**name** | **type**                     | **desc**
-------- | ---------------------------- | ----------------------------------
encoded  | [Asn](formats.md#data-types) | a modified X509 encoded public key

Used in [RsaPublicKeyAsnTestGroup](#rsapublickeyasntestgroup).

## RsaPublicKeyPemTestGroup

Fields in RsaPublicKeyPemTestGroup are\:

**name**      | **type**                                                                | **desc**                                 | **enum**
------------- | ----------------------------------------------------------------------- | ---------------------------------------- | --------
privateKey    | RsaPrivateKey                                                           | the private key                          |
privateKeyPem | [Pem](formats.md#data-types)                                            | PEM encoded private key                  |
publicKeyPem  | [Pem](formats.md#data-types)                                            | the corresponding PEM encoded public key |
type          | str                                                                     | the type of the test                     | '[RsaPublicKeyPemTest](files.md#rsapublickeypemtest)'
tests         | List of [RsaPublicKeyPemTestVector](types.md#rsapublickeypemtestvector) | a list of test vectors                   |

## RsaPublicKeyPemTestVector

Fields additional to the fields in TestVector are\:

**name** | **type**                     | **desc**
-------- | ---------------------------- | ---------------------------------
encoded  | [Pem](formats.md#data-types) | a modified PEM encoded public key

Used in [RsaPublicKeyPemTestGroup](#rsapublickeypemtestgroup).

## RsaesOaepTestGroup

Fields in RsaesOaepTestGroup are\:

**name**        | **type**                                                    | **desc**                                                    | **since** | **optional** | **enum**
--------------- | ----------------------------------------------------------- | ----------------------------------------------------------- | --------- | ------------ | --------
d               | [BigInt](formats.md#data-types)                             | The private exponent                                        |           |              |
e               | [BigInt](formats.md#data-types)                             | The public exponent                                         |           |              |
keySize         | int                                                         | key size in bits                                            |           |              |
mgf             | str                                                         | the message generating function (e.g. MGF1)                 |           |              |
mgfSha          | [MdName](formats.md#hash-functions)                         | The hash function used for the message generating function. |           |              |
n               | [BigInt](formats.md#data-types)                             | The modulus of the key                                      |           |              |
privateKeyJwk   | JwkRsaPrivateKey                                            | JSON encoded private key                                    | 0.7       | True         |
privateKeyPem   | [Pem](formats.md#data-types)                                | Pem encoded private key                                     |           |              |
privateKeyPkcs8 | [Der](formats.md#data-types)                                | Pkcs 8 encoded private key                                  |           |              |
sha             | [MdName](formats.md#hash-functions)                         | The hash function for hashing the label.                    |           |              |
type            | str                                                         | the type of the test                                        |           |              | '[RsaesOaepDecrypt](files.md#rsaesoaepdecrypt)'
tests           | List of [RsaesOaepTestVector](types.md#rsaesoaeptestvector) | a list of test vectors                                      |           |              |

## RsaesOaepTestVector

Fields additional to the fields in TestVector are\:

**name** | **type**                          | **desc**
-------- | --------------------------------- | ---------------------------------
msg      | [HexBytes](formats.md#data-types) | The encrypted message
ct       | [HexBytes](formats.md#data-types) | An encryption of msg
label    | [HexBytes](formats.md#data-types) | The label used for the encryption

Used in [RsaesOaepTestGroup](#rsaesoaeptestgroup).

## RsaesPkcs1TestGroup

Fields in RsaesPkcs1TestGroup are\:

**name**        | **type**                                                      | **desc**                    | **since** | **optional** | **enum**
--------------- | ------------------------------------------------------------- | --------------------------- | --------- | ------------ | --------
d               | [BigInt](formats.md#data-types)                               | The private exponent        |           |              |
e               | [BigInt](formats.md#data-types)                               | The public exponent         |           |              |
keySize         | int                                                           | The key size in bits        |           |              |
n               | [BigInt](formats.md#data-types)                               | The modulus of the key      |           |              |
privateKeyJwk   | JwkRsaPrivateKey                                              | JWK encoded private key     | 0.7       | True         |
privateKeyPem   | [Pem](formats.md#data-types)                                  | Pem encoded private key     |           |              |
privateKeyPkcs8 | [Der](formats.md#data-types)                                  | Pkcs 8 encoded private key. |           |              |
type            | str                                                           | the type of the test        |           |              | '[RsaesPkcs1Decrypt](files.md#rsaespkcs1decrypt)'
tests           | List of [RsaesPkcs1TestVector](types.md#rsaespkcs1testvector) | a list of test vectors      |           |              |

## RsaesPkcs1TestVector

Fields additional to the fields in TestVector are\:

**name** | **type**                          | **desc**
-------- | --------------------------------- | ---------------------
msg      | [HexBytes](formats.md#data-types) | The encrypted message
ct       | [HexBytes](formats.md#data-types) | An encryption of msg

Used in [RsaesPkcs1TestGroup](#rsaespkcs1testgroup).

## RsassaPkcs1GenTestGroup

Fields in RsassaPkcs1GenTestGroup are\:

**name**        | **type**                                                    | **desc**                               | **ref**  | **since** | **optional** | **enum**
--------------- | ----------------------------------------------------------- | -------------------------------------- | -------- | --------- | ------------ | --------
d               | [BigInt](formats.md#data-types)                             | The private exponent                   |          |           |              |
e               | [BigInt](formats.md#data-types)                             | The public exponent                    |          |           |              |
keyAsn          | [Der](formats.md#data-types)                                | DER encoding of the sequence [n, e]    |          |           |              |
keyDer          | [Der](formats.md#data-types)                                | DER encoding of the public key         |          |           |              |
keyJwk          | JwkRsaPublicKey                                             | [Optional] public key in JWK format    | RFC 7517 | 0.7       | True         |
keyPem          | [Pem](formats.md#data-types)                                | Pem encoded public key                 |          |           |              |
keySize         | int                                                         | the size of the modulus in bits        |          |           |              |
n               | [BigInt](formats.md#data-types)                             | The modulus of the key                 |          |           |              |
privateKeyJwk   | JwkRsaPrivateKey                                            | [Optional] Private key in JWK format   | RFC 7517 | 0.7       | True         |
privateKeyPem   | Pem                                                         | Pem encoded private key                |          |           |              |
privateKeyPkcs8 | [Der](formats.md#data-types)                                | PKCS8 encoded private key              |          |           |              |
sha             | [MdName](formats.md#hash-functions)                         | the hash function used for the message |          |           |              |
type            | str                                                         | the type of the test                   |          |           |              | '[RsassaPkcs1Generate](files.md#rsassapkcs1generate)'
tests           | List of [SignatureTestVector](types.md#signaturetestvector) | a list of test vectors                 |          |           |              |

## RsassaPkcs1TestGroup

Fields in RsassaPkcs1TestGroup are\:

**name** | **type**                                                    | **desc**                                                                                                       | **ref**  | **since** | **optional** | **enum**
-------- | ----------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- | -------- | --------- | ------------ | --------
e        | [BigInt](formats.md#data-types)                             | The public exponent                                                                                            |          |           |              |
keyAsn   | [Der](formats.md#data-types)                                | ASN encoding of the sequence [n, e]                                                                            |          |           |              |
keyDer   | [Der](formats.md#data-types)                                | ASN encoding of the public key                                                                                 |          |           |              |
keyJwk   | JwkRsaPublicKey                                             | The public key in JWK format. The key is missing if the signature algorithm for the given hash is not defined. | RFC 7517 | 0.7       | True         |
keyPem   | [Pem](formats.md#data-types)                                | Pem encoded public key                                                                                         |          |           |              |
keySize  | int                                                         | the size of the modulus in bits                                                                                |          |           |              |
n        | [BigInt](formats.md#data-types)                             | The modulus of the key                                                                                         |          |           |              |
sha      | [MdName](formats.md#hash-functions)                         | the hash function used for the message                                                                         |          |           |              |
type     | str                                                         | the type of the test                                                                                           |          |           |              | '[RsassaPkcs1Verify](files.md#rsassapkcs1verify)'
tests    | List of [SignatureTestVector](types.md#signaturetestvector) | a list of test vectors                                                                                         |          |           |              |

## RsassaPssTestGroup

Fields in RsassaPssTestGroup are\:

**name** | **type**                                                    | **desc**                                                    | **enum**
-------- | ----------------------------------------------------------- | ----------------------------------------------------------- | --------
e        | [BigInt](formats.md#data-types)                             | The public exponent                                         |
keyAsn   | [Der](formats.md#data-types)                                | ASN encoding of the sequence [n, e]                         |
keyDer   | [Der](formats.md#data-types)                                | ASN encoding of the public key                              |
keyPem   | [Pem](formats.md#data-types)                                | Pem encoded public key                                      |
keySize  | int                                                         | the size of the modulus in bits                             |
mgf      | str                                                         | the message generating function (e.g. MGF1)                 |
mgfSha   | [MdName](formats.md#hash-functions)                         | The hash function used for the message generating function. |
n        | [BigInt](formats.md#data-types)                             | The modulus of the key                                      |
sLen     | int                                                         | The length of the salt in bytes                             |
sha      | [MdName](formats.md#hash-functions)                         | The hash function for hasing the message.                   |
type     | str                                                         | the type of the test                                        | '[RsassaPssVerify](files.md#rsassapssverify)'
tests    | List of [RsassaPssTestVector](types.md#rsassapsstestvector) | a list of test vectors                                      |

## RsassaPssTestVector

Fields additional to the fields in TestVector are\:

**name** | **type**                          | **desc**
-------- | --------------------------------- | -------------------
msg      | [HexBytes](formats.md#data-types) | The message to sign
sig      | [HexBytes](formats.md#data-types) | a signature for msg

Used in [RsassaPssTestGroup](#rsassapsstestgroup).

## SignatureTestVector

A test vector with a public key signature. This structure is used for public key
signatures where the primitive specifies the encoding as an array of bytes (e.g.
P1363 encoded ECDSA signatures.) Public key signatures with additional
formatting (e.g. ASN.1 encoded ECDSA signatures) have their separate types.

Fields additional to the fields in TestVector are\:

**name** | **type**                          | **desc**
-------- | --------------------------------- | -------------------
msg      | [HexBytes](formats.md#data-types) | The message to sign
sig      | [HexBytes](formats.md#data-types) | A signature for msg

Used in [DsaP1363TestGroup](#dsap1363testgroup),
[EcdsaP1363TestGroup](#ecdsap1363testgroup), [EddsaTestGroup](#eddsatestgroup),
[RsassaPkcs1GenTestGroup](#rsassapkcs1gentestgroup),
[RsassaPkcs1TestGroup](#rsassapkcs1testgroup).

## Test

The root type of each JSON file with tests. Each file contains one ore more test
groups. Each test group contains one ore more test vectors. All test vectors in
the same file have the same type and test the same cryptographic primitive.

**name**         | **type**     | **desc**                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    | **since**
---------------- | ------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------
algorithm        | str          | The primitive tested in the test file. This is mainly a brief description of the algorithm used. So far there is no formal definition of this field and its description may change.                                                                                                                                                                                                                                                                                                         |
generatorVersion | str          | The version of the test vectors. The version number has the format major.minor (or major.minor[release candidate]). The plan is to change the format of the test vectors in major versions only, once version 1.0 has been reached. Conversely, version 1.0 will be published once we think the format for the test vectors are sufficiently stable.                                                                                                                                        |
header           | list of str  | additional documentation                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
notes            | JSON         | A description of the labels used in the test vectors. Some test vectors contain labels that formally describe the test vector. It can be helpful to make test more precise. For example libraries differ in whether they accept ASN encodings different from DER. Hence many of the test vectors with alternative BER encoding are rated as acceptable. Labels allow to decide whether tests with alternatve BER encoding should be rejected or accepted when testing a particular library. |
numberOfTests    | int          | The number of test vectors in this test. Each test vector has a unique tcId in the range 1 .. tcId.                                                                                                                                                                                                                                                                                                                                                                                         |
schema           | str          | The filename of the JSON schema that defines the format of the test vectors in this file. If the format of the test vectors changes then a new schema will be generate, so that comparing the name of the schema with an expected name can be used to check for compatibility between test vectors and test code.                                                                                                                                                                           | 0.7
testGroups       | list of JSON | a list of test groups                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |

## TestGroup

TestGroup is a base class for all test groups. Each test group contains a list
of test vectors of the same type. The test group describes parameters that are
common for all the test vectors. Often some parameters are given in multiple
formats to simplify testing. For example, asymmetric private key are typically
given in a raw format, PKCS #8 encoded and in PEM format. All fields in a test
group are corretly formatted. Incorrectly formatted inputs are always in the
test vectors. The list below describes the fields that are common to all test
groups, though generally a test group contains additional fields depending on
the test for which the test vectors are intended for.

Fields in TestGroup are\:

**name** | **type** | **desc**
-------- | -------- | ----------------------
tests    | List     | a list of test vectors
type     | str      | the type of the test

## TestVector

**name** | **type**    | **desc**                                                                                                                                                                                                                                                                                                                                                                                                                    | **enum**
-------- | ----------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------
comment  | str         | A brief description of the test case                                                                                                                                                                                                                                                                                                                                                                                        |
flags    | list of str | A list of flags for a test case. Flags are described in the header of the test file.                                                                                                                                                                                                                                                                                                                                        |
result   | str         | The test result. The value determines whether the test case is valid, invalid or undefined. The value "acceptable" is typically used for legacy cases, weak parameters (such as key sizes not reaching 112-bit security) or BER encoding that are frequent. Eventually, all test vectors with "result" : "acceptable" will have flags describing the reason and allowing testers to decide how to treat these test vectors. | 'valid', 'invalid', 'acceptable'
tcId     | int         | A unique identifier of the test case in a test file. The identifiers are continuous integers. The identifiers of test vectors change between versions of the test file. Hence, the triple (filename, version, tcId) uniquely identifies a test vector.                                                                                                                                                                      |

## XdhAsnTestGroup

Fields in XdhAsnTestGroup are\:

**name** | **type**                                              | **desc**                                                                                                                                                                                                                                                                                                                  | **enum**
-------- | ----------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------
curve    | [EcCurve](formats.md#elliptic-curves)                 | The name of the curve. If test vectors encode the curve as part of the public and private key then this field describes the curve of the private key. Test vectors with such encoding can contain distinct curves. Such test vectors are of course invalid and an attempt to compute a shared secret is expected to fail. |
type     | str                                                   | the type of the test                                                                                                                                                                                                                                                                                                      | '[XdhAsnComp](files.md#xdhasncomp)'
tests    | List of [XdhAsnTestVector](types.md#xdhasntestvector) | a list of test vectors                                                                                                                                                                                                                                                                                                    |

## XdhAsnTestVector

A test vector for a key exchange using XDH. Public and private keys are ASN
encoded.

Fields additional to the fields in TestVector are\:

**name** | **type**                          | **desc**
-------- | --------------------------------- | ----------------------------
public   | [Asn](formats.md#data-types)      | X.509 encoded the public key
private  | [Der](formats.md#data-types)      | PKCS #8 encoded private key
shared   | [HexBytes](formats.md#data-types) | the shared secret

Used in [XdhAsnTestGroup](#xdhasntestgroup).

## XdhJwkTestGroup

Fields in XdhJwkTestGroup are\:

**name** | **type**                                              | **desc**                                                                                                                                                                                                                                                                                                                  | **enum**
-------- | ----------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------
curve    | [EcCurve](formats.md#elliptic-curves)                 | The name of the curve. If test vectors encode the curve as part of the public and private key then this field describes the curve of the private key. Test vectors with such encoding can contain distinct curves. Such test vectors are of course invalid and an attempt to compute a shared secret is expected to fail. |
type     | str                                                   | the type of the test                                                                                                                                                                                                                                                                                                      | '[XdhJwkComp](files.md#xdhjwkcomp)'
tests    | List of [XdhJwkTestVector](types.md#xdhjwktestvector) | a list of test vectors                                                                                                                                                                                                                                                                                                    |

## XdhJwkTestVector

A test vector for a key exchange using XDH. XDH is a Diffie-Hellman key exchange
defined in RFC 7748. Both public and private key in this test vector are using
the jwk format.

Fields additional to the fields in TestVector are\:

**name** | **type**                          | **desc**                                  | **ref**
-------- | --------------------------------- | ----------------------------------------- | -------
public   | JSON                              | valid or invalid public key in jwk format | RFC 8037
private  | JwkXdhPrivateKey                  | the private key in jwk format             | RFC 8037
shared   | [HexBytes](formats.md#data-types) | the shared secret                         |

Used in [XdhJwkTestGroup](#xdhjwktestgroup).

## XdhPemTestGroup

Fields in XdhPemTestGroup are\:

**name** | **type**                                              | **desc**                                                                                                                                                                                                                                                                                                                  | **enum**
-------- | ----------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------
curve    | [EcCurve](formats.md#elliptic-curves)                 | The name of the curve. If test vectors encode the curve as part of the public and private key then this field describes the curve of the private key. Test vectors with such encoding can contain distinct curves. Such test vectors are of course invalid and an attempt to compute a shared secret is expected to fail. |
type     | str                                                   | the type of the test                                                                                                                                                                                                                                                                                                      | '[XdhPemComp](files.md#xdhpemcomp)'
tests    | List of [XdhPemTestVector](types.md#xdhpemtestvector) | a list of test vectors                                                                                                                                                                                                                                                                                                    |

## XdhPemTestVector

A test vector for a key exchange using XDH. Public and private keys are pem
encoded.

Fields additional to the fields in TestVector are\:

**name** | **type**                          | **desc**
-------- | --------------------------------- | -----------------------
public   | [Pem](formats.md#data-types)      | PEM encoded public key
private  | [Pem](formats.md#data-types)      | PEM encoded private key
shared   | [HexBytes](formats.md#data-types) | the shared secret

Used in [XdhPemTestGroup](#xdhpemtestgroup).

## XdhTestGroup

Fields in XdhTestGroup are\:

**name** | **type**                                        | **desc**                                                                                                                                                                                                                                                                                                                  | **enum**
-------- | ----------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------
curve    | [EcCurve](formats.md#elliptic-curves)           | The name of the curve. If test vectors encode the curve as part of the public and private key then this field describes the curve of the private key. Test vectors with such encoding can contain distinct curves. Such test vectors are of course invalid and an attempt to compute a shared secret is expected to fail. |
type     | str                                             | the type of the test                                                                                                                                                                                                                                                                                                      | '[XdhComp](files.md#xdhcomp)'
tests    | List of [XdhTestVector](types.md#xdhtestvector) | a list of test vectors                                                                                                                                                                                                                                                                                                    |

## XdhTestVector

A test vector for a key exchange using XDH. XDH is a Diffie-Hellman key exchange
defined in RFC 7748. Both public and private key in this test vector are just
raw bytes. That is valid public keys and valid private keys are 32 bytes each
for X25519 and 56 bytes for X448.

Fields additional to the fields in TestVector are\:

**name** | **type**                          | **desc**
-------- | --------------------------------- | -------------------------------
public   | [HexBytes](formats.md#data-types) | the raw bytes of the public key
private  | [HexBytes](formats.md#data-types) | the raw bytes of private key
shared   | [HexBytes](formats.md#data-types) | the shared secret

Used in [XdhTestGroup](#xdhtestgroup).
