# RSA

[TOC]

## RSA key generation

**Default size:** If a library supports a key default size for RSA keys then
this key size should be at least 2048 bits. This limit is based on the minimum
recommendation of [[NIST-SP800-57]](bib.md#nist-sp800-57) part1 revision 4,
Table 2, page 53. NIST recommends a minimal security strength of 112 bits for
keys used until 2030. 112 bit security strength translates to a minimal key size
of 2048 bits. Other organizations recommend somewhat different sizes:
[[EnisaKeySize14]](bib.md#enisakeysize14), Section 3.6 also suggests that
2048-bit RSA keys provide a security strength of about 112 bits, but recommends
a security strength of 128 bits for near term systems, hence 3072 bit RSA keys.
[[ECRYPT-II]](bib.md#ecrypt-ii), Section 13.3 suggests at least 2432 bits for
new keys.

All the references above clearly state that keys smaller than 2048 bits should
only be used in legacy cases. Therefore, it seems wrong to use a default key
size smaller than 2048 bits. If a user really wants a small RSA key then such a
choice should be made by explicitly providing the desired key length during the
initalization of a key pair generator.

According to https://docs.oracle.com/javase/7/docs/api/javax/crypto/Cipher.html
every implementation of the Java platform is required to implement RSA with both
1024 and 2048 bit key sizes. Hence a 2048 bit default should not lead to
compatibility problems.

**Private exponent:**
The private exponent d has to be an integer satisfying
$$1 \equiv d e \bmod lcm(p-1, q-1)$$ for RSA to work.
Standards add different additional restrictions for $$d$$.
RFC 8017 Section 3.2 specifies that $$1\leq d\leq n-1$$.
Hence computing $$d=e^{-1} \mod\varphi(n)$$ is acceptable.
FIPS-PUB-186-4, Appendix B.3.1 specifies that d satisfies
$$2^{nlen/2}<d<\mbox{lcm}(p-1, q-1).$$
<!--See also section A.1.1 of FIPS-186-5-draft.-->
Hence there is at most one valid $$d$$. The lower bound implies
that $$p-1$$ and $$q-1$$ share a large common factor and therefore
that factoring the modulus is typically easy.


**Cryptographically strong random numbers:** So far the tests check that
java.util.Random is not used. This needs to be extended.

**Other bugs:** The public exponent e should be larger than 1
[[CVE-1999-1444]](bib.md#cve-1999-1444)

## RSA PKCS #1 v1.5 encryption

PKCS #1 v1.5 padding is susceptible to adaptive chosen ciphertext attacks and
hence should be avoided [[Bleich98]](bib.md#bleich98). The difficulty of
exploiting protocols using PKCS #1 v1.5 encryption often depends on the amount
of information leaked after decrypting corrupt ciphertexts. Implementations
frequently leak information about the decrypted plaintext in form of error
messages. The content of the error messages are extremely helpful to potential
attackers. Bardou et al. [[BFKLSST12]](bib.md#bfklsst12) analyze the difficult
of attacks based on different types of information leakage. The paper shows that
even small information leakages can have a big impact on the required number of
chosen messages. Smart even describes an attack that only needs about 40 chosen
ciphertexts [[Smart10]](bib.md#smart10), though in this case the encryption did
not use PKCS #1 padding. NIST disallows the use of RSA PKCS #1 v1.5 for
key-agreement and key-transport after 2023
[[NIST-SP800-131A]](bib.md#nist-sp800-131a). The use of PKCS #1 v1.5 is by
itself considered to be a vulnerability (e.g., CVE-2021-41096)

The tests in Wycheproof can only check if the cryptographic primitive is
implemented correctly or if it leaks unnecessary information. The tests do not
check if the caller mishandles the decryption and thus provides a PKCS-1 oracle.

**Bugs**

Here are a few typical bugs that were contained in old versions of crypto
libraries:

*   Libraries should not throw distinguishable exceptions when the padding is
    incorrect. E.g. Bouncycastle before version 1.56 did throw either
    InvalidCipherTextException("unknown block type") or
    InvalidCipherTextException("block padding incorrect") depending on the
    location of the first error in the padding.

*   CVE-2012-5081: Java JSSE provider leaked information through exceptions and
    timing. Both the PKCS #1 padding and the OAEP padding were broken:
    http://www-brs.ub.ruhr-uni-bochum.de/netahtml/HSS/Diss/MeyerChristopher/diss.pdf

There a few bugs that are not covered by the tests:

*   Klima et al. used that OpenSSL would randomize the result of an RSA
    decryption if the ciphertext was invalid and were able to distinguish the
    randomized results from invalid paddings from non-randomized results of
    valid paddings. [[KlPoRo03]](bib.md#klporo03). This attack requires precise
    timing and a large number of measurements.

*   Timing leakages because of differences in parsing the padding are sometimes
    reported (e.g. CVE-2015-7827). Such differences are too small to be reliably
    detectable in unit tests.

**Tests**

To test whether an implementation leaks more information than necessary a test
decrypts some random ciphertexts and catches the exceptions. If the exceptions
are distinguishable then the test assumes that unnecessary information about the
padding is leaked.

Due to the nature of unit tests not every attack can be detected this way. Some
attacks require a large number of ciphertexts to be detected if random
ciphertexts are used. For example Klima et al. [[KlPoRo03]](bib.md#klporo03)
describe an implementation flaw that could not be detected with our test.

Timing leakages because of differences in parsing the padding can leak
information (e.g. [[CVE-2015-7827]](bib.md#cve-2015-1827)). Such differences are
too small to be reliably detectable in unit tests.

## RSA PKCS #1 v1.5 signatures

**Potential problems**

*   Some libraries parse PKCS #1 v1.5 padding during signature verification
    incorrectly.
*   Some libraries determine the hash function from the signature (rather than
    encoding this in the key).
*   If the verification is buggy then an attacker might be able to generate
    signatures for keys with a small (i.e. e=3) public exponent.
*   If the hash algorithm is not determined by in an authentic manner then
    preimage attacks against weak hashes are possible, even if the hashes are
    not used by the signer.

**Countermeasures**

A good way to implement RSA signature verification is described in the standard
PKCS#1 v.2.2 Section 8.2.2. This standard proposes to reconstruct the padding
during verification and compare the padded hash to the value $$s^e \bmod n$$
obtained from applying a public key exponentiation to the signature s. Since
this is a recurring bug it makes also a lot of sense to avoid small public
exponents and prefer for example e=65537 .

## RSA PSS

RSA-PSS is an RSA based signature scheme using probabilistic padding. The tests
are based on RFC 8017.

**Potential problems**

*   The verification of an RSA-PSS signature contains a number of steps, where
    the correctness of the padding has to be verified. Skipping such checks can
    lead to similar attacks as with RSA PKCS #1 v1.5 signatures. The necessary
    steps of the verification are detailed in Section 9.1.2 of RFC 8017. For
    example omitting (or incorrectly implementing) the checks in step 10 might
    allow signature forgeries with small public exponents. RSA-PSS
    implementations tend to contain less padding errors than RSA-PKCS #1 v.1.5
    signatures. Possibly this happens because of the detailed description of
    the verification in RFC 8017 and related standards.
*   A significant problem with RSASSA-PSS in java is that various provider
    differ in the way RSASSA-PSS is implemented.

**Compatibility and weak defaults**

RSA PSS requires to specify a list of parameters. In particular this is a hash
function for hashing the message, a mask generation function, which typically
requires to specify a second hash function, salt length and a trailer field. An
implementation must be very careful about these parameters. It is quite easy to
unknowingly select weak default values or to introduce incompatibilities by not
giving enough attention to these parameters.

The ASN representation is specified in Appendix C of RFC 8017.
<pre>
   RSASSA-PSS-params ::= SEQUENCE {
       hashAlgorithm      [0] HashAlgorithm      DEFAULT sha1,
       maskGenAlgorithm   [1] MaskGenAlgorithm   DEFAULT mgf1SHA1,
       saltLength         [2] INTEGER            DEFAULT 20,
       trailerField       [3] TrailerField       DEFAULT trailerFieldBC
   }
</pre>
This definition sets default values for the case when a parameter was
not encoded. These values (especially sha1 for hashAlgorithm) are
weak. They should not be used as default for any key generation.

RFC 4055 defines a number of identifiers for RSA-PSS in Section 6. The proposed
identifiers use the same hash function for the message and the mask generation.
The salt length is always 20. Using a salt length of 20, however is an uncommon
choice. Many libraries use a salt length equal to the output size of the hash
function in cases where the salt length is not specified.

**Support**

A number of libraries restrict the supported parameter sets. For example some
libraries do not support distinct hash functions for hashing the message and
for the mask generation function. A typical value for the saltLength is to
use the digest size of the hash function. Hence to increase the chance that
algorithm parameters have wide support it is generally a good idea to use the
same hash function for hashing the message and for the mask generation function
and a saltLength equal the digest size of the hash function.

**JCA algorithm names**

The JCA algorithm names for RSASSA-PSS differ from provider to provider. One
reason for the differences was the change for the standard algorithm names
proposed by Oracle. While
http://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html
initially proposed to use names such as "SHA256withRSAandMGF1" for RSASSA-PSS
this was later changed to "RSASSA-PSS" in
https://docs.oracle.com/en/java/javase/11/docs/specs/security/standard-names.html
.

This change is quite reasonable. Algorithm names like "SHA256withRSAandMGF1"
were ambiguous. They only specified the hash algorithm for the message digest,
but not the hash algorithm for the mask generation algorithm and the salt
length. The table below should give an impression of some of the algorithm names
and support thereof (note that the table does not use the latest version of each
provider). Providers select default values for many of the algorithm names.
Luckily, all the providers tested so far (BouncyCastle and Conscrypt) agree on
the default values. I.e. both hashes for hashing the message and the hash for
MGF1 are the same and the salt length is equal to the output size of the hash
function.

Algorithm name       | jdk19                     | BouncyCastle 1.71       | Conscrypt 1.0
-------------------- | ------------------------- | ----------------------- | -------------
RSASSA-PSS           | requires PSSParameterSpec | SHA1, MGF1-SHA1, 20     | no support
SHA1withRSAandMGF1   | no support                | SHA1, MGF1-SHA1, 20     | SHA1, MGF1-SHA1, 20
SHA224withRSAandMGF1 | no support                | SHA224, MGF1-SHA224, 28 | SHA224, MGF1-SHA224, 28
SHA256withRSAandMGF1 | no support                | SHA256, MGF1-SHA256, 32 | SHA256, MGF1-SHA256, 32
SHA384withRSAandMGF1 | no support                | SHA384, MGF1-SHA384, 48 | SHA384, MGF1-SHA384, 48
SHA512withRSAandMGF1 | no support                | SHA384, MGF1-SHA512, 64 | SHA512, MGF1-SHA512, 64

A few provider specific algorithm names are:

Algorithm name            | jdk19      | BouncyCastle 1.71               | Conscrypt 1.0
------------------------- | ---------- | ------------------------------- | -------------
SHA512/224withRSAandMGF1  | no support | SHA512/224, MGF1-SHA512/224, 28 | no support
SHA512/256withRSAandMGF1  | no support | SHA512/256, MGF1-SHA512/256, 32 | no support
SHA3-224withRSAandMGF1    | no support | SHA3-224, MGF1-SHA224, 28       | no support
SHA3-256withRSAandMGF1    | no support | SHA3-256, MGF1-SHA256, 32       | no support
SHA3-384withRSAandMGF1    | no support | SHA3-384, MGF1-SHA384, 48       | no support
SHA3-512withRSAandMGF1    | no support | SHA3-512, MGF1-SHA512, 64       | no support
SHA1withRSA/PSS           | no support | SHA1, MGF1-SHA1, 20             | SHA1, MGF1-SHA1, 20
SHA224withRSA/PSS         | no support | SHA224, MGF1-SHA224, 28         | SHA224, MGF1-SHA224, 28
SHA256withRSA/PSS         | no support | SHA256, MGF1-SHA256, 32         | SHA256, MGF1-SHA256, 32
SHA384withRSA/PSS         | no support | SHA384, MGF1-SHA384, 48         | SHA384, MGF1-SHA384, 48
SHA512withRSA/PSS         | no support | SHA384, MGF1-SHA512, 64         | SHA512, MGF1-SHA512, 64
SHA3-224withRSA/PSS       | no support | SHA3-224, MGF1-SHA224, 28       | no support
SHA3-256withRSA/PSS       | no support | SHA3-256, MGF1-SHA256, 32       | no support
SHA3-384withRSA/PSS       | no support | SHA3-384, MGF1-SHA384, 48       | no support
SHA3-512withRSA/PSS       | no support | SHA3-512, MGF1-SHA512, 64       | no support
SHA512(224)withRSAandMGF1 | no support | SHA512/224, MGF1-SHA512/224, 28 | no support
SHA512(256)withRSAandMGF1 | no support | SHA512/256, MGF1-SHA512/256, 32 | no support

Having a large number of algorithm name with implicit parameter choices is quite
unsatisfactory. Hence the proposed change by Oracle is cleaner. I.e., OpenJDK
only supports "RSASSA-PSS" as algorithm name and requires to specify the
algorithm parameters with an instance of PSSParameterSpec, e.g.,

```java
  Signature verifier = Signature.getInstance("RSASSA-PSS");
  PSSParameterSpec pssParams = ...
  verifier.setParameter(pssParams);
  verifier.init(publicKey);`
```

BouncyCastle supports additional algorithm names such as
`SHA256WithRSAAndSHAKE256`. Such a combination is uncommon since RFC 8702
specifies just two parameter sets: one using SHAK128 for both hash and MGF and
one using SHA256 for both functions.

**Encoding keys**

DER and PEM encoded keys contain an algorithm identifier. RFC 8017 Section A.2
defines some algorithm identifiers for RSA keys. I.e., it defines the following
identifiers:

<pre>
  PKCS1Algorithms    ALGORITHM-IDENTIFIER ::= {
   { OID rsaEncryption                PARAMETERS NULL } |
   { OID md2WithRSAEncryption         PARAMETERS NULL } |
   { OID md5WithRSAEncryption         PARAMETERS NULL } |
   { OID sha1WithRSAEncryption        PARAMETERS NULL } |
   { OID sha224WithRSAEncryption      PARAMETERS NULL } |
   { OID sha256WithRSAEncryption      PARAMETERS NULL } |
   { OID sha384WithRSAEncryption      PARAMETERS NULL } |
   { OID sha512WithRSAEncryption      PARAMETERS NULL } |
   { OID sha512-224WithRSAEncryption  PARAMETERS NULL } |
   { OID sha512-256WithRSAEncryption  PARAMETERS NULL } |
   { OID id-RSAES-OAEP   PARAMETERS RSAES-OAEP-params } |
   PKCS1PSourceAlgorithms                               |
   { OID id-RSASSA-PSS   PARAMETERS RSASSA-PSS-params },
   ...  -- Allows for future expansion --
 }
</pre>

The OID id-RSASSA-PSS can be used to specify that an RSA key should be used for
RSASSA-PSS. It allows to specify the algorithm parameters of the signature
scheme. Unfortunately, many implementations don't use this OID. Rather they use
the object identifier rsaEncryption regardless of the purpose of the key. Using
the OID id-RSASSA-PSS would be preferable, since this would make it easier to
ensure that a key is only used for a single purpose. RFC 5756 gives some guide
lines when to use RSASSA-PSS parameters in certifiates. Wycheproof contains test
vector for both key formats. The key formats are distinguised by the schema of
the file:

*   *rsassa_pss_verify_schema.json*: test vectors with this schema contain DER
    and PEM encoded RSA keys using the OID rsaEncryption. Tests using these test
    vectors need to read the algorithm parameters "sha", "mgf", "mgfSha" and
    "slen" from the test group and initialize an RSASSA-PSS verifier
    accordingly.

*   *rsassa_pss_with_parameters_verify_schema.json*: test vectors with this
    schema have RSA keys where the DER and PEM encoding use the OID
    id-RSASSA-PSS.

Unfortunately there appears to be no clear documentation how RSASSA-PSS keys
with parameters should be used in java. Java 8 added the method getParams() to
the RSAKey interface. OpenJDK subsequently added RSASSA-PSS parameters to the
key factory and the key generation. However, it seems necessary to explicitly
copy the parameters when signing or verifying. I.e., the following pattern
appears to be necessary.

```java
  RSAPrivateKey priv = ...;
  byte[] msg = ...;
  signer = Signature.getInstance("RSASSA-PSS");
  signer.initSign(priv);
  signer.setParameter(priv.getParams());
  signer.update(msg);
  byte[] signature = signer.sign();
```

**SHAKE128 and SHAKE256**

RFC 8702 adds SHAKE128 and SHAKE256 to RSASSA-PSS. Support for these functions
is currently quite small. An advantage of the new functions is that each
function only supports a single set of parameter choices.

## RSA OAEP

**Manger's attack**

Manger describes an chosen ciphertext attack against RSA in
[[Manger01]](bib.md#manger01). There are implementations that were susceptible
to Mangers attack, e.g. [[CVE-2012-5081]](bib.md#cve-2012-5081).

There is a big difference between chosen ciphertext attacks against RSA-OAEP
and RSA-PKCS #1 v.1.5: a chosen ciphertext attack against RSA-OAEP implies that
the implementation of RSA-OAEP is broken, while attacks against RSA-PKCS #1
can also happen if the caller leaks information about the decrypted ciphertext.
Hence a correct implementation of RSA-OAEP prevents chosen ciphertext attacks,
but implementations of RSA-PKCS #1 cannot achieve the same property.


**Algorithm parameters**

The algorithm parameters for RSA OAEP are described in RFC 8017 A.2.1.
<pre>
  RSAES-OAEP-params ::= SEQUENCE {
       hashAlgorithm      [0] HashAlgorithm     DEFAULT sha1,
       maskGenAlgorithm   [1] MaskGenAlgorithm  DEFAULT mgf1SHA1,
       pSourceAlgorithm   [2] PSourceAlgorithm  DEFAULT pSpecifiedEmpty
   }
</pre>
It should be noted that the mask generation algorithm requires a second hash function,
that can be different than the hash algorithm already specified. When using a library
one has to ensure that all parties involved use the same parameters.

The security of OAEP does not depend on collision resistance
(https://eprint.iacr.org/2006/223.pdf). Hence, using OAEP with SHA-1 does not
pose a security risk.

**JCE algorithm names**

The algorithm names for RSA OAEP are not uniformly used in various providers. A
few specifications can be found here:
https://docs.oracle.com/en/java/javase/18/docs/specs/security/standard-names.html
E.g., this document specifies that the preferred encryption mode is "ECB" not
"NONE". (The encryption mode is not used and does not change the ciphertexts).
Hash functions (SHA-1, SHA-256 etc. ) should contain a dash, hence algorithm
names such as "RSA/ECB/OAEPwithSHA224andMGF1Padding" are not well formed and
only supported by some providers.

The hash function for the mask generating function is not specified by the
algorithm name. This leads to a number of incompatibilities. The following table
shows a number of algorithm names for OAEP, their support among some providers
and the default values used for the algorithm parameters:

Algorithm name                        | jdk19              | BouncyCastle 1.71    | Conscrypt 1.0
------------------------------------- | ------------------ | -------------------- | -------------
RSA/ECB/OAEPPadding                   | SHA-1, MGF1-SHA1   | SHA-1, MGF1-SHA1     | SHA-1, MGF1-SHA1
RSA/ECB/OAEPwithSHA-1andMGF1Padding   | SHA-1, MGF1-SHA1   | SHA-1, MGF1-SHA1     | SHA-1, MGF1-SHA1
RSA/ECB/OAEPwithSHA-224andMGF1Padding | SHA-224, MGF1-SHA1 | SHA-224, MGF1-SHA224 | SHA-224, MGF1-SHA224
RSA/ECB/OAEPwithSHA-256andMGF1Padding | SHA-256, MGF1-SHA1 | SHA-256, MGF1-SHA256 | SHA-256, MGF1-SHA256
RSA/ECB/OAEPwithSHA-384andMGF1Padding | SHA-384, MGF1-SHA1 | SHA-384, MGF1-SHA384 | SHA-384, MGF1-SHA384
RSA/ECB/OAEPwithSHA-512andMGF1Padding | SHA-512, MGF1-SHA1 | SHA-512, MGF1-SHA512 | SHA-512, MGF1-SHA512

Some provider support additional algorithm names that do not follow the convention for standard names.
Some examples are:

Algorithm name                            | jdk19                  | BouncyCastle 1.71    | Conscrypt 1.0
----------------------------------------- | ---------------------- | -------------------- | -------------
RSA/None/OAEPPadding                      | not supported          | SHA-1, MGF1-SHA1     | SHA-1, MGF1-SHA1
RSA/None/OAEPwithSHA-1andMGF1Padding      | not supported          | SHA-1, MGF1-SHA1     | not supported
RSA/None/OAEPwithSHA-224andMGF1Padding    | not supported          | SHA-224, MGF1-SHA224 | not supported
RSA/None/OAEPwithSHA-256andMGF1Padding    | not supported          | SHA-256, MGF1-SHA256 | not supported
RSA/None/OAEPwithSHA-384andMGF1Padding    | not supported          | SHA-384, MGF1-SHA384 | not supported
RSA/None/OAEPwithSHA-512andMGF1Padding    | not supported          | SHA-512, MGF1-SHA512 | not supported
RSA/ECB/OAEPwithSHA1andMGF1Padding        | SHA-1, MGF1-SHA1       | SHA-1, MGF1-SHA1     | not supported
RSA/ECB/OAEPwithSHA224andMGF1Padding      | not supported          | SHA-224, MGF1-SHA224 | not supported
RSA/ECB/OAEPwithSHA256andMGF1Padding      | not supported          | SHA-256, MGF1-SHA256 | not supported
RSA/ECB/OAEPwithSHA384andMGF1Padding      | not supported          | SHA-384, MGF1-SHA384 | not supported
RSA/ECB/OAEPwithSHA512andMGF1Padding      | not supported          | SHA-512, MGF1-SHA512 | not supported
RSA/ECB/OAEPwithSHA-512/224andMGF1Padding | SHA-512/224, MGF1-SHA1 | not supported        | not supported
RSA/ECB/OAEPwithSHA-512/256andMGF1Padding | SHA-512/256, MGF1-SHA1 | not supported        | not supported

The main concern here is that hash function for MGF1 is not specified in the
algorithm name. While using SHA-1 currently is not a weakness, since collision
resistance is not required, it may still become an issue when NIST transitions
away from SHA-1, because these hidden defaults can lead to incompatilities.
Because of this it may be a good idea to specify the algorithm parameters
explitily. For example the following pattern should lead to compatible
implementations:

```java
  Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPPadding");
  PSource p = PSource.PSpecified.DEFAULT;
  MGF1ParameterSpec mgf1Params = new MGF1ParameterSpec("SHA-256");
  OAEPParameterSpec params = new OAEPParameterSpec("SHA-256", "MGF1", mgf1Params, p);
  cipher.init(mode, key, params);
```

**SHA-3 / SHAKE**

BouncyCastle supports additional algorithm names with SHA-3 such as
`RSA/ECB/OAEPwithSHA3-256andMGF1Padding`. It is in principle possible to
use SHAKE128 and SHAKE256 as an alternative to MGF1 (similar to RFC 8702). Since
we are not aware of any standards or RFCs makeing such a proposal, there are no
test vectors using SHA-3.

**Encoding keys** It is possible to include RSAES-OAEP parameters in DER and PEM
encoded RSA keys. To our knowledge this option is rarely used and supported.
Because of this situation all the RSA keys in our test vectors contain the
object identifier rsaEncryption and no parameters and not id-RSAES-OAEP.

