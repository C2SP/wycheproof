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
of attacks based on different types of information leakage. Smart even describes
an attack that only needs about 40 chosen ciphertexts
[[Smart10]](bib.md#smart10), though in this case the encryption did not use
PKCS #1 padding. NIST disallows the use of RSA PKCS #1 v1.5 for key-agreement
and key-transport after 2023 [[NIST-SP800-131A]](bib.md#nist-sp800-131a).

**Bugs**

*   Bouncycastle throws detailed exceptions: InvalidCipherTextException("unknown
    block type") or InvalidCipherTextException("block padding incorrect").

<!-- the SUN provider used to include that block type -->

**Tests** To test whether an implementation leaks more information than
necessary a test decrypts some random ciphertexts and catches the exceptions. If
the exceptions are distinguishable then the test assumes that unnecessary
information about the padding is leaked.

Due to the nature of unit tests not every attack can be detected this way. Some
attacks require a large number of ciphertexts to be detected if random
ciphertexts are used. For example Klima et al. [[KlPoRo03]](bib.md#klporo03)
describe an implementation flaw that could not be detected with our test.

Timing leakages because of differences in parsing the padding can leak
information (e.g. [[CVE-2015-7827]](bib.md#cve-2015-1827)). Such differences are
too small to be reliably detectable in unit tests.

## RSA OAEP

Manger describes an chosen ciphertext attack against RSA in
[[Manger01]](bib.md#manger01). There are implementations that were susceptible
to Mangers attack, e.g. [[CVE-2012-5081]](bib.md#cve-2012-5081).

## RSA PKCS #1 v1.5 signatures

**Potential problems:**

*   Some libraries parse PKCS #1 v1.5 padding during signature verification
    incorrectly.
*   Some libraries determine the hash function from the signature (rather than
    encoding this in the key) Effect:
*   If the verification is buggy then an attacker might be able to generate
    signatures for keys with a small (i.e. e=3) public exponent.
*   If the hash algorithm is not determined by in an authentic manner then
    preimage attacks against weak hashes are possible, even if the hashes are
    not used by the signer.

**Countermeasures:** A good way to implement RSA signature verification is
described in the standard PKCS#1 v.2.2 Section 8.2.2. This standard proposes to
reconstruct the padding during verification and compare the padded hash to the
value $$s^e \bmod n$$ obtained from applying a public key exponentiation to the
signature s. Since this is a recurring bug it makes also a lot of sense to avoid
small public exponents and prefer for example e=65537 .

## RSA PSS

RSA-PSS is an RSA based signature scheme using probabilistic padding. The tests
are based on RFC 8017.

**Potential problems:**

*   The verification of an RSA-PSS signature contains a number of steps, where
    the correctness of the padding has to be verified. Skipping such checks can
    lead to similar attacks as with RSA PKCS #1 v1.5 signatures. The necessary
    steps of the verification are detailed in Section 9.1.2 of RFC 8017.
    Possibly, this detailed description is preventing similar problems as with
    RSA PKCS #1 v1.5.

**Compatibility and weak defaults:**

RSA PSS requires to specify a list of parameters. In particular this is a hash
function for hashing the message, a mask generation function, which typically
requires to specify a second hash function, salt length and a trailer field.
The ASN representation is specified in Appendix C of RFC 8017.
<pre>
   RSASSA-PSS-params ::= SEQUENCE {
       hashAlgorithm      [0] HashAlgorithm      DEFAULT sha1,
       maskGenAlgorithm   [1] MaskGenAlgorithm   DEFAULT mgf1SHA1,
       saltLength         [2] INTEGER            DEFAULT 20,
       trailerField       [3] TrailerField       DEFAULT trailerFieldBC
   }
</pre>
RFC 4055 defines a number of identifiers for RSA-PSS in Section 6. The
proposed identifiers use the same hash function for the message and the mask
generation. The salt length is always 20.

These specifications lead to a number of problems, since implementations do not
always require that all parameters are specified and hence some default values
are chosen by the implementation, which of course affects compatibility.

The tests in Wycheproof do not follow the defaults and parameter sets proposed
in RFC 8017 or RFC 4055, rather the tests expect what appears to be common
behaviour in current implementations: the default mask generation algorithm is
MGF1 using the same hash as the hash algorithm used for hashing the message. If
the salt length is not specified then the salt length is equal to the size of
the hash function.

The ASN encoding of a key contains an algorithm identifier. The algorithm
identifier composed of either the OID rsaEncryption with a NULL parameter or an
OID id-RSASSA-PSS with a specification of the PSS parameters. ASN encodings with
an OID rsaEncryption is most commonly used in cryptographic libraries. The
second option will be an alternative supported by jdk11. Because of this the
test vectors in Wycheproof use the OID rsaEncryption.
