<!-- AUTO-GENERATED FILE; DO NOT MODIFY -->

# Test vector types

Version\: 0.7

[TOC]

## AeadTestGroup {#AeadTestGroup}

A test group for authenticated encryption with additional data.

Fields in AeadTestGroup are\:

**name** | **type**                                          | **desc**                                                                                                                                                                                                                                                                                                         | **enum**
-------- | ------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------
ivSize   | int                                               | The IV size in bits. All IV sizes are multiple of 8 bits.                                                                                                                                                                                                                                                        |
keySize  | int                                               | the keySize in bits                                                                                                                                                                                                                                                                                              |
tagSize  | int                                               | The expected size of the tag in bits. This is the size that should be used to initialize instance of the cipher. The actual tag in the test vector may have a different size. Such a test vector is always invalid and an implementation is expected to reject such tags. All tag sizes are multiples of 8 bits. |
type     | str                                               | the type of the test                                                                                                                                                                                                                                                                                             | '[AeadTest](files.md#AeadTest)'
tests    | List of [AeadTestVector](types.md#AeadTestVector) | a list of test vectors                                                                                                                                                                                                                                                                                           |

## AeadTestVector {#AeadTestVector}

A test vector for authenticated encryption with additional data.

Fields additional to the fields in TestVector are\:

| **name** | **type**                         | **desc**                       |
| -------- | -------------------------------- | ------------------------------ |
| key      | [HexBytes](formats.md#DataTypes) | the key                        |
| iv       | [HexBytes](formats.md#DataTypes) | the nonce                      |
| aad      | [HexBytes](formats.md#DataTypes) | additional authenticated data  |
| msg      | [HexBytes](formats.md#DataTypes) | the plaintext                  |
| ct       | [HexBytes](formats.md#DataTypes) | the ciphertext (without iv and |
:          :                                  : tag)                           :
| tag      | [HexBytes](formats.md#DataTypes) | The authenticatian tag. Most   |
:          :                                  : encryption append the tag to   :
:          :                                  : the ciphertext. Encryption     :
:          :                                  : results in the concatenation   :
:          :                                  : ct || tag and decryption       :
:          :                                  : expects ct || tag as input.    :
:          :                                  : There are however some         :
:          :                                  : exceptions. For example        :
:          :                                  : AEAD-AES-SIV-CMAC (RFC 5297)   :
:          :                                  : computes a synthetic IV (SIV), :
:          :                                  : which is used to initialize    :
:          :                                  : the counter for AES. The       :
:          :                                  : typical encoding here is to    :
:          :                                  : prepend the SIV. I.e.          :
:          :                                  : implementations would expect   :
:          :                                  : ciphertext of the form tag ||  :
:          :                                  : ct or iv || tag || ct.         :

Used in [AeadTestGroup](#AeadTestGroup).

## AsnSignatureTestVector {#AsnSignatureTestVector}

A test vector with an ASN.1 encoded public key signature. For example, ECDSA and
DSA signatures are a pair of integers (r,s). These integers can be encoded in
different ways. A popular encoding is to represent the integers as an ASN
Sequence. The expectation is that any library generates only DER encoded
signatures. Some libraries are also strict in the sense that only DER encoded
signautes are accepted. Other libraries accept some signatures where the pair
(r,s) uses an alternative BER encoding assuming of course that the encoded (r,s)
is valid.

Fields additional to the fields in TestVector are\:

**name** | **type**                         | **desc**
-------- | -------------------------------- | --------------------------------
msg      | [HexBytes](formats.md#DataTypes) | The message to sign
sig      | Asn                              | An ASN encoded signature for msg

Used in [DsaTestGroup](#DsaTestGroup), [EcdsaTestGroup](#EcdsaTestGroup).

## DaeadTestGroup {#DaeadTestGroup}

Fields in DaeadTestGroup are\:

**name** | **type**                                            | **desc**               | **enum**
-------- | --------------------------------------------------- | ---------------------- | --------
keySize  | int                                                 | the keySize in bits    |
type     | str                                                 | the type of the test   | '[DaeadTest](files.md#DaeadTest)'
tests    | List of [DaeadTestVector](types.md#DaeadTestVector) | a list of test vectors |

## DaeadTestVector {#DaeadTestVector}

A test vector used for authenticated deterministic encryption with additional
data.

Fields additional to the fields in TestVector are\:

**name** | **type**                         | **desc**
-------- | -------------------------------- | -----------------------------
key      | [HexBytes](formats.md#DataTypes) | the key
aad      | [HexBytes](formats.md#DataTypes) | additional authenticated data
msg      | [HexBytes](formats.md#DataTypes) | the plaintext
ct       | [HexBytes](formats.md#DataTypes) | the ciphertext including tag

Used in [DaeadTestGroup](#DaeadTestGroup).

## DsaPrivateKey {#DsaPrivateKey}

A DSA private key. This implementation of DSA must only be used for testing rsp.
for generating test vectors. It has not been checked for flaws and in some cases
may even avoid necessary checks so that it can be used for flawed test vectors.

| **name** | **type**                       | **desc**       | **enum**        |
| -------- | ------------------------------ | -------------- | --------------- |
| g        | [BigInt](formats.md#DataTypes) | the generator  |                 |
:          :                                : of the         :                 :
:          :                                : multiplicative :                 :
:          :                                : subgroup       :                 :
| keySize  | int                            | the key size   |                 |
:          :                                : in bits        :                 :
| p        | [BigInt](formats.md#DataTypes) | the modulus p  |                 |
| q        | [BigInt](formats.md#DataTypes) | the order of   |                 |
:          :                                : the generator  :                 :
:          :                                : g              :                 :
| type     | str                            | the key type   | 'DsaPrivateKey' |
| x        | [BigInt](formats.md#DataTypes) | the private    |                 |
:          :                                : key value      :                 :
| y        | [BigInt](formats.md#DataTypes) | the public key |                 |
:          :                                : value          :                 :

## DsaPublicKey {#DsaPublicKey}

The public key for DSA.

| **name** | **type**                       | **desc**       | **enum**       |
| -------- | ------------------------------ | -------------- | -------------- |
| g        | [BigInt](formats.md#DataTypes) | the generator  |                |
:          :                                : of the         :                :
:          :                                : multiplicative :                :
:          :                                : subgroup       :                :
| keySize  | int                            | the key size   |                |
:          :                                : in bits        :                :
| p        | [BigInt](formats.md#DataTypes) | the modulus p  |                |
| q        | [BigInt](formats.md#DataTypes) | the order of   |                |
:          :                                : the generator  :                :
:          :                                : g              :                :
| type     | str                            | the key type   | 'DsaPublicKey' |
| y        | [BigInt](formats.md#DataTypes) | the public key |                |
:          :                                : value          :                :

## DsaTestGroup {#DsaTestGroup}

Fields in DsaTestGroup are\:

**name** | **type**                                                          | **desc**                       | **enum**
-------- | ----------------------------------------------------------------- | ------------------------------ | --------
key      | DsaPublicKey                                                      | unenocded DSA public key       |
keyDer   | [Der](formats.md#DataTypes)                                       | DER encoded public key         |
keyPem   | [Pem](formats.md#DataTypes)                                       | Pem encoded public key         |
sha      | [MdName](formats.md#HashFunctions)                                | the hash function used for DSA |
type     | str                                                               | the type of the test           | '[DsaVerify](files.md#DsaVerify)'
tests    | List of [AsnSignatureTestVector](types.md#AsnSignatureTestVector) | a list of test vectors         |

## EcPointTestGroup {#EcPointTestGroup}

Fields in EcPointTestGroup are\:

**name** | **type**                                                | **desc**                       | **enum**
-------- | ------------------------------------------------------- | ------------------------------ | --------
curve    | [EcCurve](formats.md#EcCurve)                           | the name of the elliptic curve |
encoding | str                                                     | the encoding used              | 'compressed', 'uncompressed'
type     | str                                                     | the type of the test           | '[EcPointTest](files.md#EcPointTest)'
tests    | List of [EcPointTestVector](types.md#EcPointTestVector) | a list of test vectors         |

## EcPointTestVector {#EcPointTestVector}

Fields additional to the fields in TestVector are\:

**name** | **type**                         | **desc**
-------- | -------------------------------- | -------------------------------
encoded  | [HexBytes](formats.md#DataTypes) | X509 encoded point on the curve
x        | [BigInt](formats.md#DataTypes)   | x-coordinate of the point
y        | [BigInt](formats.md#DataTypes)   | y-coordiante of the point

Used in [EcPointTestGroup](#EcPointTestGroup).

## EcPublicKey {#EcPublicKey}

An EC public key. The EC public key can specify the underlying curve parameters
in two ways. (1) as a named curve (2) as a structure containing the curve
parameters generator, order and cofactor.

**name**     | **type**                                                 | **desc**                                            | **enum**
------------ | -------------------------------------------------------- | --------------------------------------------------- | --------
curve        | typing.Union[ecutil.EcUnnamedGroup, ecutil.EcNamedGroup] | the EC group used by this public key                |
keySize      | int                                                      | the key size in bits                                |
type         | str                                                      | the key type                                        | 'EcPublicKey'
uncompressed | [HexBytes](formats.md#DataTypes)                         | X509 encoded public key point in hexadecimal format |
wx           | [BigInt](formats.md#DataTypes)                           | the x-coordinate of the public key point            |
wy           | [BigInt](formats.md#DataTypes)                           | the y-coordinate of the public key point            |

## EcPublicKeyOnNamedCurve {#EcPublicKeyOnNamedCurve}

An EC public key. This data type allows only named curves to specify the
underlying EC parameters.

**name**     | **type**                         | **desc**                                            | **enum**
------------ | -------------------------------- | --------------------------------------------------- | --------
curve        | EcNamedGroup                     | the EC group used by this public key                |
keySize      | int                              | the key size in bits                                |
type         | str                              | the key type                                        | 'EcPublicKey'
uncompressed | [HexBytes](formats.md#DataTypes) | X509 encoded public key point in hexadecimal format |
wx           | [BigInt](formats.md#DataTypes)   | the x-coordinate of the public key point            |
wy           | [BigInt](formats.md#DataTypes)   | the y-coordinate of the public key point            |

## EcPublicKeyTestGroup {#EcPublicKeyTestGroup}

Fields in EcPublicKeyTestGroup are\:

**name** | **type**                                                        | **desc**                         | **enum**
-------- | --------------------------------------------------------------- | -------------------------------- | --------
encoding | str                                                             | the encoding of the encoded keys | 'asn', 'pem', 'webcrypto'
type     | str                                                             | the type of the test             | '[EcPublicKeyVerify](files.md#EcPublicKeyVerify)'
tests    | List of [EcPublicKeyTestVector](types.md#EcPublicKeyTestVector) | a list of test vectors           |

## EcPublicKeyTestVector {#EcPublicKeyTestVector}

Draft version for test vectors that test importing of EC public keys. The test
vectors contain modified EC public keys. The goal of the test is to recognize if
importing the EC public keys notices inconsistencies and bad formatting.

Fields additional to the fields in TestVector are\:

| **name** | **type**                       | **desc**                         |
| -------- | ------------------------------ | -------------------------------- |
| encoded  | [Asn](formats.md#DataTypes)    | Encoded EC public key over a     |
:          :                                : prime order field                :
| p        | [BigInt](formats.md#DataTypes) | The order of underlying field    |
| n        | [BigInt](formats.md#DataTypes) | The order of the generator       |
| a        | [BigInt](formats.md#DataTypes) | The value a of the Weierstrass   |
:          :                                : equation                         :
| b        | [BigInt](formats.md#DataTypes) | The value b of the Weierstrass   |
:          :                                : equation                         :
| gx       | [BigInt](formats.md#DataTypes) | x-coordinate of the generator    |
| gy       | [BigInt](formats.md#DataTypes) | y-coordinate of the generator    |
| h        | int                            | [optional] the cofactor          |
| wx       | [BigInt](formats.md#DataTypes) | x-coordinate of the public point |
| wy       | [BigInt](formats.md#DataTypes) | y-coordinate of the public point |

Used in [EcPublicKeyTestGroup](#EcPublicKeyTestGroup).

## EcUnnamedGroup {#EcUnnamedGroup}

An unamed EC group

| **name** | **type**                       | **desc**     | **enum**          |
| -------- | ------------------------------ | ------------ | ----------------- |
| a        | [BigInt](formats.md#DataTypes) | coefficient  |                   |
:          :                                : a of the     :                   :
:          :                                : elliptic     :                   :
:          :                                : curve        :                   :
:          :                                : equation     :                   :
| b        | [BigInt](formats.md#DataTypes) | coefficient  |                   |
:          :                                : b of the     :                   :
:          :                                : elliptic     :                   :
:          :                                : curve        :                   :
:          :                                : equation     :                   :
| gx       | [BigInt](formats.md#DataTypes) | the          |                   |
:          :                                : x-coordinate :                   :
:          :                                : of the       :                   :
:          :                                : generator    :                   :
| gy       | [BigInt](formats.md#DataTypes) | the          |                   |
:          :                                : y-coordinate :                   :
:          :                                : of the       :                   :
:          :                                : generator    :                   :
| h        | int                            | the cofactor |                   |
| n        | [BigInt](formats.md#DataTypes) | the order of |                   |
:          :                                : the          :                   :
:          :                                : generator    :                   :
| p        | [BigInt](formats.md#DataTypes) | the order of |                   |
:          :                                : the          :                   :
:          :                                : underlying   :                   :
:          :                                : field        :                   :
| type     | str                            | an unnamed   | 'PrimeOrderCurve' |
:          :                                : EC group     :                   :
:          :                                : over a prime :                   :
:          :                                : field in     :                   :
:          :                                : Weierstrass  :                   :
:          :                                : form         :                   :

## EcdhEcpointTestGroup {#EcdhEcpointTestGroup}

Fields in EcdhEcpointTestGroup are\:

**name** | **type**                                                        | **desc**                       | **enum**
-------- | --------------------------------------------------------------- | ------------------------------ | --------
curve    | [EcCurve](formats.md#EcCurve)                                   | the curve of the private key   |
encoding | str                                                             | the encoding of the public key | 'ecpoint'
type     | str                                                             | the type of the test           | '[EcdhEcpointTest](files.md#EcdhEcpointTest)'
tests    | List of [EcdhEcpointTestVector](types.md#EcdhEcpointTestVector) | a list of test vectors         |

## EcdhEcpointTestVector {#EcdhEcpointTestVector}

Fields additional to the fields in TestVector are\:

| **name** | **type**                         | **desc**     | **ref**        |
| -------- | -------------------------------- | ------------ | -------------- |
| public   | [Asn](formats.md#DataTypes)      | ASN encoded  | X9.62, Section |
:          :                                  : public point : 4.3.6          :
| private  | [BigInt](formats.md#DataTypes)   | The private  |                |
:          :                                  : exponent     :                :
| shared   | [HexBytes](formats.md#DataTypes) | The shared   |                |
:          :                                  : secret key   :                :

Used in [EcdhEcpointTestGroup](#EcdhEcpointTestGroup).

## EcdhPemTestGroup {#EcdhPemTestGroup}

Fields in EcdhPemTestGroup are\:

**name** | **type**                                                | **desc**                       | **enum**
-------- | ------------------------------------------------------- | ------------------------------ | --------
curve    | [EcCurve](formats.md#EcCurve)                           | the curve of the private key   |
encoding | str                                                     | the encoding of the public key | 'pem'
type     | str                                                     | the type of the test           | '[EcdhPemTest](files.md#EcdhPemTest)'
tests    | List of [EcdhPemTestVector](types.md#EcdhPemTestVector) | a list of test vectors         |

## EcdhPemTestVector {#EcdhPemTestVector}

Fields additional to the fields in TestVector are\:

**name** | **type**                         | **desc**
-------- | -------------------------------- | ----------------------
public   | [Pem](formats.md#DataTypes)      | Pem encoded public key
private  | [BigInt](formats.md#DataTypes)   | the private key
shared   | [HexBytes](formats.md#DataTypes) | The shared secret key

Used in [EcdhPemTestGroup](#EcdhPemTestGroup).

## EcdhTestGroup {#EcdhTestGroup}

Fields in EcdhTestGroup are\:

**name** | **type**                                          | **desc**                       | **enum**
-------- | ------------------------------------------------- | ------------------------------ | --------
curve    | [EcCurve](formats.md#EcCurve)                     | the curve of the private key   |
encoding | str                                               | the encoding of the public key | 'asn'
type     | str                                               | the type of the test           | '[EcdhTest](files.md#EcdhTest)'
tests    | List of [EcdhTestVector](types.md#EcdhTestVector) | a list of test vectors         |

## EcdhTestVector {#EcdhTestVector}

Fields additional to the fields in TestVector are\:

| **name** | **type**                         | **desc**                       |
| -------- | -------------------------------- | ------------------------------ |
| public   | [Asn](formats.md#DataTypes)      | X509 encoded public key. The   |
:          :                                  : encoding of the public key     :
:          :                                  : contains the type of the       :
:          :                                  : public key, the curve and      :
:          :                                  : possibly the curve parameters. :
:          :                                  : The test vectors contain cases :
:          :                                  : where these fields do not      :
:          :                                  : match the curve in the         :
:          :                                  : testGroup.                     :
| private  | [BigInt](formats.md#DataTypes)   | the private key                |
| shared   | [HexBytes](formats.md#DataTypes) | The shared secret key. Some    |
:          :                                  : invalid test vectors contain a :
:          :                                  : shared secret, which is        :
:          :                                  : computed using the curve of    :
:          :                                  : the private key. This allows   :
:          :                                  : to distinguish between         :
:          :                                  : implementations ignoring       :
:          :                                  : public key info and            :
:          :                                  : implementations using the      :
:          :                                  : curve of the public key.       :

Used in [EcdhTestGroup](#EcdhTestGroup).

## EcdhWebcryptoTestGroup {#EcdhWebcryptoTestGroup}

Fields in EcdhWebcryptoTestGroup are\:

**name** | **type**                                                            | **desc**                       | **enum**
-------- | ------------------------------------------------------------------- | ------------------------------ | --------
curve    | [EcCurve](formats.md#EcCurve)                                       | the curve of the private key   |
encoding | str                                                                 | the encoding of the public key | 'webcrypto'
type     | str                                                                 | the type of the test           | '[EcdhWebcryptoTest](files.md#EcdhWebcryptoTest)'
tests    | List of [EcdhWebcryptoTestVector](types.md#EcdhWebcryptoTestVector) | a list of test vectors         |

## EcdhWebcryptoTestVector {#EcdhWebcryptoTestVector}

Fields additional to the fields in TestVector are\:

**name** | **type**                         | **desc**
-------- | -------------------------------- | -------------------------------
public   | Json                             | Public key in webcrypto format
private  | Json                             | Private key in webcrypto format
shared   | [HexBytes](formats.md#DataTypes) | The shared secret key

Used in [EcdhWebcryptoTestGroup](#EcdhWebcryptoTestGroup).

## EcdsaP1363TestGroup {#EcdsaP1363TestGroup}

A test group for ECDSA signatures using IEEE P1363 encoding. The test vectors in
this group are meant for signature verification. The test group contains the
same public key for the signatures in multiple representations. The public keys
are valid with the sole exception that they may use short keys and weak hash
functions such as SHA-1.

Fields in EcdsaP1363TestGroup are\:

**name** | **type**                                                    | **desc**                                      | **enum**
-------- | ----------------------------------------------------------- | --------------------------------------------- | --------
jwk      | Json                                                        | [optional] the public key in webcrypto format |
key      | EcPublicKey                                                 | unenocded EC public key                       |
keyDer   | [Der](formats.md#DataTypes)                                 | DER encoded public key                        |
keyPem   | [Pem](formats.md#DataTypes)                                 | Pem encoded public key                        |
sha      | [MdName](formats.md#HashFunctions)                          | the hash function used for ECDSA              |
type     | str                                                         | the type of the test                          | '[EcdsaP1363Verify](files.md#EcdsaP1363Verify)'
tests    | List of [SignatureTestVector](types.md#SignatureTestVector) | a list of test vectors                        |

## EcdsaTestGroup {#EcdsaTestGroup}

A test group for ECDSA signatures. The test vectors in this group are meant for
signature verification. The test group contains the same public key for the
signatures in multiple representations. The public keys are valid with the sole
exception that they may use short keys and weak hash functions such as SHA-1.

Fields in EcdsaTestGroup are\:

**name** | **type**                                                          | **desc**                         | **enum**
-------- | ----------------------------------------------------------------- | -------------------------------- | --------
key      | EcPublicKey                                                       | unenocded EC public key          |
keyDer   | [Der](formats.md#DataTypes)                                       | DER encoded public key           |
keyPem   | [Pem](formats.md#DataTypes)                                       | Pem encoded public key           |
sha      | [MdName](formats.md#HashFunctions)                                | the hash function used for ECDSA |
type     | str                                                               | the type of the test             | '[EcdsaVerify](files.md#EcdsaVerify)'
tests    | List of [AsnSignatureTestVector](types.md#AsnSignatureTestVector) | a list of test vectors           |

## EddsaTestGroup {#EddsaTestGroup}

Fields in EddsaTestGroup are\:

**name** | **type**                                                    | **desc**                            | **since** | **ref**            | **enum**
-------- | ----------------------------------------------------------- | ----------------------------------- | --------- | ------------------ | --------
jwk      | Json                                                        | the private key in webcrypto format | 0.7       | RFC 8037 Section 2 |
key      | Json                                                        | unencoded key pair                  |           |                    |
keyDer   | [Der](formats.md#DataTypes)                                 | Asn encoded public key              |           |                    |
keyPem   | [Pem](formats.md#DataTypes)                                 | Pem encoded public key              |           |                    |
type     | str                                                         | the type of the test                |           |                    | '[EddsaVerify](files.md#EddsaVerify)'
tests    | List of [SignatureTestVector](types.md#SignatureTestVector) | a list of test vectors              |           |                    |

## HkdfTestGroup {#HkdfTestGroup}

A test group for key derivation functions that take 4 arguments (ikm, salt,
info, size) as input.

Fields in HkdfTestGroup are\:

**name** | **type**                                          | **desc**                    | **enum**
-------- | ------------------------------------------------- | --------------------------- | --------
keySize  | int                                               | the size of the ikm in bits |
type     | str                                               | the type of the test        | '[HkdfTest](files.md#HkdfTest)'
tests    | List of [HkdfTestVector](types.md#HkdfTestVector) | a list of test vectors      |

## HkdfTestVector {#HkdfTestVector}

A test vector for HKDF (or any other key derivation function with input ikm,
salt, info, size

Fields additional to the fields in TestVector are\:

| **name** | **type**                         | **desc**                       |
| -------- | -------------------------------- | ------------------------------ |
| ikm      | [HexBytes](formats.md#DataTypes) | the key (input key material)   |
| salt     | [HexBytes](formats.md#DataTypes) | the salt for the key           |
:          :                                  : derivation                     :
| info     | [HexBytes](formats.md#DataTypes) | additional information used in |
:          :                                  : the key derivation             :
| size     | int                              | the size of the output in      |
:          :                                  : bytes                          :
| okm      | [HexBytes](formats.md#DataTypes) | the generated bytes (output    |
:          :                                  : key material)                  :

Used in [HkdfTestGroup](#HkdfTestGroup).

## IndCpaTestGroup {#IndCpaTestGroup}

Fields in IndCpaTestGroup are\:

**name** | **type**                                              | **desc**                             | **enum**
-------- | ----------------------------------------------------- | ------------------------------------ | --------
ivSize   | int                                                   | the IV size in bits                  |
keySize  | int                                                   | the keySize in bits                  |
tagSize  | int                                                   | the expected size of the tag in bits |
type     | str                                                   | the type of the test                 | '[IndCpaTest](files.md#IndCpaTest)'
tests    | List of [IndCpaTestVector](types.md#IndCpaTestVector) | a list of test vectors               |

## IndCpaTestVector {#IndCpaTestVector}

A test vector that is used for symmetric primitives that are indistinguishable
under chosen plaintext attacks. These primitives are without an integrity check
and hence without additional authenticated data. For example AES using cipher
block chaining (CBC) is tested using this format.

Fields additional to the fields in TestVector are\:

**name** | **type**                         | **desc**
-------- | -------------------------------- | -------------------------------
key      | [HexBytes](formats.md#DataTypes) | the key
iv       | [HexBytes](formats.md#DataTypes) | the initialization vector
msg      | [HexBytes](formats.md#DataTypes) | the plaintext
ct       | [HexBytes](formats.md#DataTypes) | the raw ciphertext (without IV)

Used in [IndCpaTestGroup](#IndCpaTestGroup).

## KeywrapTestGroup {#KeywrapTestGroup}

Fields in KeywrapTestGroup are\:

**name** | **type**                                                | **desc**               | **enum**
-------- | ------------------------------------------------------- | ---------------------- | --------
keySize  | int                                                     | the keySize in bits    |
type     | str                                                     | the type of the test   | '[KeywrapTest](files.md#KeywrapTest)'
tests    | List of [KeywrapTestVector](types.md#KeywrapTestVector) | a list of test vectors |

## KeywrapTestVector {#KeywrapTestVector}

A test vector for key wrap primitives. Key wrap primitives are typically
symmetric encryptions that were specifically desigend for encrypting key
material. In some cases the input size is restricted to typical key sizes e.g. a
multiple of 8 bytes. The encryption may assume that the wrapped bytes have high
entropy. Hence some of the key wrap primitives are deterministic.

Fields additional to the fields in TestVector are\:

**name** | **type**                         | **desc**
-------- | -------------------------------- | ---------------------
key      | [HexBytes](formats.md#DataTypes) | the wrapping key
msg      | [HexBytes](formats.md#DataTypes) | the key bytes to wrap
ct       | [HexBytes](formats.md#DataTypes) | the wrapped key

Used in [KeywrapTestGroup](#KeywrapTestGroup).

## MacTestGroup {#MacTestGroup}

Fields in MacTestGroup are\:

**name** | **type**                                        | **desc**                             | **enum**
-------- | ----------------------------------------------- | ------------------------------------ | --------
keySize  | int                                             | the keySize in bits                  |
tagSize  | int                                             | the expected size of the tag in bits |
type     | str                                             | the type of the test                 | '[MacTest](files.md#MacTest)'
tests    | List of [MacTestVector](types.md#MacTestVector) | a list of test vectors               |

## MacTestVector {#MacTestVector}

A test vector for message authentication codes (MAC).

Fields additional to the fields in TestVector are\:

**name** | **type**                         | **desc**
-------- | -------------------------------- | ----------------------
key      | [HexBytes](formats.md#DataTypes) | the key
msg      | [HexBytes](formats.md#DataTypes) | the plaintext
tag      | [HexBytes](formats.md#DataTypes) | the authentication tag

Used in [MacTestGroup](#MacTestGroup).

## RsaKeyTestGroup {#RsaKeyTestGroup}

Fields in RsaKeyTestGroup are\:

**name** | **type**                                              | **desc**                                                                                                                                                  | **enum**
-------- | ----------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- | --------
encoding | str                                                   | The encoding of the public key in the test vectors. asn implies PKCS8 encoded public keys. pem implies a PEM encoded public key (compatible with OpenSSL. | 'asn', 'pem'
private  | Json                                                  | the private key                                                                                                                                           |
type     | str                                                   | the type of the test                                                                                                                                      | '[RsaKeyTest](files.md#RsaKeyTest)'
tests    | List of [RsaKeyTestVector](types.md#RsaKeyTestVector) | a list of test vectors                                                                                                                                    |

## RsaKeyTestVector {#RsaKeyTestVector}

Fields additional to the fields in TestVector are\:

**name** | **type**                         | **desc**
-------- | -------------------------------- | ----------------------
public   | [HexBytes](formats.md#DataTypes) | the encoded public key

Used in [RsaKeyTestGroup](#RsaKeyTestGroup).

## RsaesOaepTestGroup {#RsaesOaepTestGroup}

Fields in RsaesOaepTestGroup are\:

**name**        | **type**                                                    | **desc**                                                    | **since** | **enum**
--------------- | ----------------------------------------------------------- | ----------------------------------------------------------- | --------- | --------
d               | [BigInt](formats.md#DataTypes)                              | The private exponent                                        |           |
e               | [BigInt](formats.md#DataTypes)                              | The public exponent                                         |           |
mgf             | str                                                         | the message generating function (e.g. MGF1)                 |           |
mgfSha          | [MdName](formats.md#HashFunctions)                          | The hash function used for the message generating function. |           |
n               | [BigInt](formats.md#DataTypes)                              | The modulus of the key                                      |           |
privateKeyJwk   | JSON                                                        | [optional] JSON encoded private key                         | 0.7       |
privateKeyPem   | [Pem](formats.md#DataTypes)                                 | Pem encoded private key                                     |           |
privateKeyPkcs8 | [Der](formats.md#DataTypes)                                 | Pkcs 8 encoded private key                                  |           |
sha             | [MdName](formats.md#HashFunctions)                          | The hash function for hashing the label.                    |           |
type            | str                                                         | the type of the test                                        |           | '[RsaesOaepDecrypt](files.md#RsaesOaepDecrypt)'
tests           | List of [RsaesOaepTestVector](types.md#RsaesOaepTestVector) | a list of test vectors                                      |           |

## RsaesOaepTestVector {#RsaesOaepTestVector}

Fields additional to the fields in TestVector are\:

**name** | **type**                         | **desc**
-------- | -------------------------------- | ---------------------------------
msg      | [HexBytes](formats.md#DataTypes) | The encrypted message
ct       | [HexBytes](formats.md#DataTypes) | An encryption of msg
label    | [HexBytes](formats.md#DataTypes) | The label used for the encryption

Used in [RsaesOaepTestGroup](#RsaesOaepTestGroup).

## RsaesPkcs1TestGroup {#RsaesPkcs1TestGroup}

Fields in RsaesPkcs1TestGroup are\:

**name**        | **type**                                                      | **desc**                    | **since** | **enum**
--------------- | ------------------------------------------------------------- | --------------------------- | --------- | --------
d               | [BigInt](formats.md#DataTypes)                                | The private exponent        |           |
e               | [BigInt](formats.md#DataTypes)                                | The public exponent         |           |
n               | [BigInt](formats.md#DataTypes)                                | The modulus of the key      |           |
privateKeyJwk   | JSON                                                          | JWK encoded private key     | 0.7       |
privateKeyPem   | [Pem](formats.md#DataTypes)                                   | Pem encoded private key     |           |
privateKeyPkcs8 | [Der](formats.md#DataTypes)                                   | Pkcs 8 encoded private key. |           |
type            | str                                                           | the type of the test        |           | '[RsaesPkcs1Decrypt](files.md#RsaesPkcs1Decrypt)'
tests           | List of [RsaesPkcs1TestVector](types.md#RsaesPkcs1TestVector) | a list of test vectors      |           |

## RsaesPkcs1TestVector {#RsaesPkcs1TestVector}

Fields additional to the fields in TestVector are\:

**name** | **type**                         | **desc**
-------- | -------------------------------- | ---------------------
msg      | [HexBytes](formats.md#DataTypes) | The encrypted message
ct       | [HexBytes](formats.md#DataTypes) | An encryption of msg

Used in [RsaesPkcs1TestGroup](#RsaesPkcs1TestGroup).

## RsassaPkcs1GenTestGroup {#RsassaPkcs1GenTestGroup}

Fields in RsassaPkcs1GenTestGroup are\:

**name**      | **type**                                                    | **desc**                               | **ref**  | **since** | **enum**
------------- | ----------------------------------------------------------- | -------------------------------------- | -------- | --------- | --------
d             | [BigInt](formats.md#DataTypes)                              | The private exponent                   |          |           |
e             | [BigInt](formats.md#DataTypes)                              | The public exponent                    |          |           |
keyAsn        | [Der](formats.md#DataTypes)                                 | DER encoding of the sequence [n, e]    |          |           |
keyDer        | [Der](formats.md#DataTypes)                                 | DER encoding of the public key         |          |           |
keyJwk        | Json                                                        | [Optional] Private key in JWK format   | RFC 7517 | 0.7       |
keyPem        | [Pem](formats.md#DataTypes)                                 | Pem encoded public key                 |          |           |
keySize       | int                                                         | the size of the modulus in bits        |          |           |
n             | [BigInt](formats.md#DataTypes)                              | The modulus of the key                 |          |           |
privateKeyDer | [Der](formats.md#DataTypes)                                 | DER encoding of the private key        |          |           |
privateKeyJwk | Json                                                        | [Optional] Private key in JWK format   | RFC 7517 | 0.7       |
privateKeyPem | Pem                                                         | Pem encoded private key                |          |           |
sha           | [MdName](formats.md#HashFunctions)                          | the hash function used for the message |          |           |
type          | str                                                         | the type of the test                   |          |           | '[RsassaPkcs1Generate](files.md#RsassaPkcs1Generate)'
tests         | List of [SignatureTestVector](types.md#SignatureTestVector) | a list of test vectors                 |          |           |

## RsassaPkcs1TestGroup {#RsassaPkcs1TestGroup}

Fields in RsassaPkcs1TestGroup are\:

**name** | **type**                                                    | **desc**                                                                                                       | **ref**  | **since** | **enum**
-------- | ----------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- | -------- | --------- | --------
d        | [BigInt](formats.md#DataTypes)                              | The private exponent                                                                                           |          |           |
e        | [BigInt](formats.md#DataTypes)                              | The public exponent                                                                                            |          |           |
keyAsn   | [Der](formats.md#DataTypes)                                 | ASN encoding of the sequence [n, e]                                                                            |          |           |
keyDer   | [Der](formats.md#DataTypes)                                 | ASN encoding of the public key                                                                                 |          |           |
keyJwk   | Json                                                        | The public key in JWK format. The key is missing if the signature algorithm for the given hash is not defined. | RFC 7517 | 0.7       |
keyPem   | [Pem](formats.md#DataTypes)                                 | Pem encoded public key                                                                                         |          |           |
keySize  | int                                                         | the size of the modulus in bits                                                                                |          |           |
n        | [BigInt](formats.md#DataTypes)                              | The modulus of the key                                                                                         |          |           |
sha      | [MdName](formats.md#HashFunctions)                          | the hash function used for the message                                                                         |          |           |
type     | str                                                         | the type of the test                                                                                           |          |           | '[RsassaPkcs1Verify](files.md#RsassaPkcs1Verify)'
tests    | List of [SignatureTestVector](types.md#SignatureTestVector) | a list of test vectors                                                                                         |          |           |

## RsassaPssTestGroup {#RsassaPssTestGroup}

Fields in RsassaPssTestGroup are\:

**name** | **type**                                                    | **desc**                                                    | **enum**
-------- | ----------------------------------------------------------- | ----------------------------------------------------------- | --------
d        | [BigInt](formats.md#DataTypes)                              | The private exponent                                        |
e        | [BigInt](formats.md#DataTypes)                              | The public exponent                                         |
keyAsn   | [Der](formats.md#DataTypes)                                 | ASN encoding of the sequence [n, e]                         |
keyDer   | [Der](formats.md#DataTypes)                                 | ASN encoding of the public key                              |
keyPem   | [Pem](formats.md#DataTypes)                                 | Pem encoded public key                                      |
keySize  | int                                                         | the size of the modulus in bits                             |
mgf      | str                                                         | the message generating function (e.g. MGF1)                 |
mgfSha   | [MdName](formats.md#HashFunctions)                          | The hash function used for the message generating function. |
n        | [BigInt](formats.md#DataTypes)                              | The modulus of the key                                      |
sha      | [MdName](formats.md#HashFunctions)                          | The hash function for hasing the message.                   |
type     | str                                                         | the type of the test                                        | '[RsassaPssVerify](files.md#RsassaPssVerify)'
tests    | List of [RsassaPssTestVector](types.md#RsassaPssTestVector) | a list of test vectors                                      |

## RsassaPssTestVector {#RsassaPssTestVector}

Fields additional to the fields in TestVector are\:

**name** | **type**                         | **desc**
-------- | -------------------------------- | -------------------
msg      | [HexBytes](formats.md#DataTypes) | The message to sign
sig      | [HexBytes](formats.md#DataTypes) | a signature for msg

Used in [RsassaPssTestGroup](#RsassaPssTestGroup).

## SignatureTestVector {#SignatureTestVector}

A test vector with a public key signature. This structure is used for public key
signatures where the primitive specifies the encoding as an array of bytes (e.g.
P1363 encoded ECDSA signatures.) Public key signatures with additional
formatting (e.g. ASN.1 encoded ECDSA signatures) have their separate types.

Fields additional to the fields in TestVector are\:

**name** | **type**                         | **desc**
-------- | -------------------------------- | -------------------
msg      | [HexBytes](formats.md#DataTypes) | The message to sign
sig      | [HexBytes](formats.md#DataTypes) | A signature for msg

Used in
[EcdsaP1363TestGroup](#EcdsaP1363TestGroup), [EddsaTestGroup](#EddsaTestGroup),
[RsassaPkcs1GenTestGroup](#RsassaPkcs1GenTestGroup),
[RsassaPkcs1TestGroup](#RsassaPkcs1TestGroup).

## Test {#Test}

The root type of each JSON file with tests. Each file contains one ore more test
groups. Each test group contains one ore more test vectors. All test vectors in
the same file have the same type and test the same cryptographic primitive.

| **name**         | **type** | **desc**            | **since** |
| ---------------- | -------- | ------------------- | --------- |
| algorithm        | str      | The primitive       |           |
:                  :          : tested in the test  :           :
:                  :          : file. This is       :           :
:                  :          : mainly a brief      :           :
:                  :          : description of the  :           :
:                  :          : algorithm used. So  :           :
:                  :          : far there is no     :           :
:                  :          : formal definition   :           :
:                  :          : of this field and   :           :
:                  :          : its description may :           :
:                  :          : change.             :           :
| generatorVersion | str      | The version of the  |           |
:                  :          : test vectors. The   :           :
:                  :          : version number has  :           :
:                  :          : the format          :           :
:                  :          : major.minor (or     :           :
:                  :          : major.minor[release :           :
:                  :          : candidate]). The    :           :
:                  :          : plan is to change   :           :
:                  :          : the format of the   :           :
:                  :          : test vectors in     :           :
:                  :          : major versions      :           :
:                  :          : only, once version  :           :
:                  :          : 1.0 has been        :           :
:                  :          : reached.            :           :
:                  :          : Conversely, version :           :
:                  :          : 1.0 will be         :           :
:                  :          : published once we   :           :
:                  :          : think the format    :           :
:                  :          : for the test        :           :
:                  :          : vectors are         :           :
:                  :          : sufficiently        :           :
:                  :          : stable.             :           :
| header           | List     | additional          |           |
:                  :          : documentation       :           :
| notes            | JSON     | A description of    |           |
:                  :          : the labels used in  :           :
:                  :          : the test vectors.   :           :
:                  :          : Some test vectors   :           :
:                  :          : contain labels that :           :
:                  :          : formally describe   :           :
:                  :          : the test vector. It :           :
:                  :          : can be helpful to   :           :
:                  :          : make test more      :           :
:                  :          : precise. For        :           :
:                  :          : example libraries   :           :
:                  :          : differ in whether   :           :
:                  :          : they accept ASN     :           :
:                  :          : encodings different :           :
:                  :          : from DER. Hence     :           :
:                  :          : many of the test    :           :
:                  :          : vectors with        :           :
:                  :          : alternative BER     :           :
:                  :          : encoding are rated  :           :
:                  :          : as acceptable.      :           :
:                  :          : Labels allow to     :           :
:                  :          : decide whether      :           :
:                  :          : tests with          :           :
:                  :          : alternatve BER      :           :
:                  :          : encoding should be  :           :
:                  :          : rejected or         :           :
:                  :          : accepted when       :           :
:                  :          : testing a           :           :
:                  :          : particular library. :           :
| numberOfTests    | int      | The number of test  |           |
:                  :          : vectors in this     :           :
:                  :          : test. Each test     :           :
:                  :          : vector has a unique :           :
:                  :          : tcId in the range 1 :           :
:                  :          : .. tcId.            :           :
| schema           | str      | The filename of the | 0.7       |
:                  :          : JSON schema that    :           :
:                  :          : defines the format  :           :
:                  :          : of the test vectors :           :
:                  :          : in this file. If    :           :
:                  :          : the format of the   :           :
:                  :          : test vectors        :           :
:                  :          : changes then a new  :           :
:                  :          : schema will be      :           :
:                  :          : generate, so that   :           :
:                  :          : comparing the name  :           :
:                  :          : of the schema with  :           :
:                  :          : an expected name    :           :
:                  :          : can be used to      :           :
:                  :          : check for           :           :
:                  :          : compatibility       :           :
:                  :          : between test        :           :
:                  :          : vectors and test    :           :
:                  :          : code.               :           :
| testGroups       | List     | a list of test      |           |
:                  :          : groups              :           :

## TestVector {#TestVector}

| **name** | **type** | **desc**                  | **enum**            |
| -------- | -------- | ------------------------- | ------------------- |
| comment  | str      | A brief description of    |                     |
:          :          : the test case             :                     :
| flags    | List     | A list of flags for a     |                     |
:          :          : test case. Flags are      :                     :
:          :          : described in the header   :                     :
:          :          : of the test file.         :                     :
| result   | str      | The test result. The      | 'valid', 'invalid', |
:          :          : value determines whether  : 'acceptable'        :
:          :          : the test case is valid,   :                     :
:          :          : invalid or undefined. The :                     :
:          :          : value "acceptable" is     :                     :
:          :          : typically used for legacy :                     :
:          :          : cases, weak parameters    :                     :
:          :          : (such as key sizes not    :                     :
:          :          : reaching 112-bit          :                     :
:          :          : security) or BER encoding :                     :
:          :          : that are frequent.        :                     :
:          :          : Eventually, all test      :                     :
:          :          : vectors with "result" \:  :                     :
:          :          : "acceptable" will have    :                     :
:          :          : flags describing the      :                     :
:          :          : reason and allowing       :                     :
:          :          : testers to decide how to  :                     :
:          :          : treat these test vectors. :                     :
| tcId     | int      | A unique identifier of    |                     |
:          :          : the test case in a test   :                     :
:          :          : file. The identifiers are :                     :
:          :          : continuous integers. The  :                     :
:          :          : identifiers of test       :                     :
:          :          : vectors change between    :                     :
:          :          : versions of the test      :                     :
:          :          : file. Hence, the triple   :                     :
:          :          : (filename, version, tcId) :                     :
:          :          : uniquely identifies a     :                     :
:          :          : test vector.              :                     :

## XdhAsnTestGroup {#XdhAsnTestGroup}

Fields in XdhAsnTestGroup are\:

**name** | **type**                                              | **desc**                                                                                                                                                                                                                                                                                                                  | **enum**
-------- | ----------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------
curve    | [EcCurve](formats.md#EcCurve)                         | The name of the curve. If test vectors encode the curve as part of the public and private key then this field describes the curve of the private key. Test vectors with such encoding can contain distinct curves. Such test vectors are of course invalid and an attempt to compute a shared secret is expected to fail. |
type     | str                                                   | the type of the test                                                                                                                                                                                                                                                                                                      | '[XdhAsnComp](files.md#XdhAsnComp)'
tests    | List of [XdhAsnTestVector](types.md#XdhAsnTestVector) | a list of test vectors                                                                                                                                                                                                                                                                                                    |

## XdhAsnTestVector {#XdhAsnTestVector}

A test vector for a key exchange using XDH. Public and private keys are ASN
encoded.

Fields additional to the fields in TestVector are\:

**name** | **type**                         | **desc**
-------- | -------------------------------- | ----------------------------
public   | [Asn](formats.md#DataTypes)      | X.509 encoded the public key
private  | [Der](formats.md#DataTypes)      | PKCS #8 encoded private key
shared   | [HexBytes](formats.md#DataTypes) | the shared secret

Used in [XdhAsnTestGroup](#XdhAsnTestGroup).

## XdhJwkTestGroup {#XdhJwkTestGroup}

Fields in XdhJwkTestGroup are\:

**name** | **type**                                              | **desc**                                                                                                                                                                                                                                                                                                                  | **enum**
-------- | ----------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------
curve    | [EcCurve](formats.md#EcCurve)                         | The name of the curve. If test vectors encode the curve as part of the public and private key then this field describes the curve of the private key. Test vectors with such encoding can contain distinct curves. Such test vectors are of course invalid and an attempt to compute a shared secret is expected to fail. |
type     | str                                                   | the type of the test                                                                                                                                                                                                                                                                                                      | '[XdhJwkComp](files.md#XdhJwkComp)'
tests    | List of [XdhJwkTestVector](types.md#XdhJwkTestVector) | a list of test vectors                                                                                                                                                                                                                                                                                                    |

## XdhJwkTestVector {#XdhJwkTestVector}

A test vector for a key exchange using XDH. XDH is a Diffie-Hellman key exchange
defined in RFC 7748. Both public and private key in this test vector are using
the jwk format.

Fields additional to the fields in TestVector are\:

| **name** | **type**                         | **desc**           | **ref**  |
| -------- | -------------------------------- | ------------------ | -------- |
| public   | JSON                             | the public key in  | RFC 8037 |
:          :                                  : jwk format         :          :
| private  | JSON                             | the private key in | RFC 8037 |
:          :                                  : jwk format         :          :
| shared   | [HexBytes](formats.md#DataTypes) | the shared secret  |          |

Used in [XdhJwkTestGroup](#XdhJwkTestGroup).

## XdhTestGroup {#XdhTestGroup}

Fields in XdhTestGroup are\:

**name** | **type**                                        | **desc**                                                                                                                                                                                                                                                                                                                  | **enum**
-------- | ----------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------
curve    | [EcCurve](formats.md#EcCurve)                   | The name of the curve. If test vectors encode the curve as part of the public and private key then this field describes the curve of the private key. Test vectors with such encoding can contain distinct curves. Such test vectors are of course invalid and an attempt to compute a shared secret is expected to fail. |
type     | str                                             | the type of the test                                                                                                                                                                                                                                                                                                      | '[XdhComp](files.md#XdhComp)'
tests    | List of [XdhTestVector](types.md#XdhTestVector) | a list of test vectors                                                                                                                                                                                                                                                                                                    |

## XdhTestVector {#XdhTestVector}

A test vector for a key exchange using XDH. XDH is a Diffie-Hellman key exchange
defined in RFC 7748. Both public and private key in this test vector are just
raw bytes. That is valid public keys and valid private keys are 32 bytes each
for X25519 and 56 bytes for X448.

Fields additional to the fields in TestVector are\:

**name** | **type**                         | **desc**
-------- | -------------------------------- | -------------------------------
public   | [HexBytes](formats.md#DataTypes) | the raw bytes of the public key
private  | [HexBytes](formats.md#DataTypes) | the raw bytes of private key
shared   | [HexBytes](formats.md#DataTypes) | the shared secret

Used in [XdhTestGroup](#XdhTestGroup).
