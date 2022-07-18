# Spongy Castle

<!-- We really should make an effort to deprecate this library. -->

Spongy Castle is a fork of the Bouncy Castle crypto library
https://github.com/rtyley/spongycastle. The library was introduced because the
version of Bouncy Castle available on Android only had a restricted number of
algorithm available. Spongy Castle would allow users to select cryptographic
algorithms that were not included in Bouncy Castle. However, SpongyCastle has
not been updated for years. It suffers from a large number of vulnerabilities
that are long fixed in Bouncy Castle. The library is obsolete:
https://github.com/rtyley/spongycastle/issues/34

TLDR: Implementations should no longer use Spongy Castle and
switch to a provider that is well maintained.

Below is a list of bugs and potential patches for the case where switching away
from Sponcy Castle is not possbile in a short term.

## AES-GCM

The Wycheproof tests *testByteBufferShiftedAlias* and *testLargeArrayAlias*
fail. This is mainly a bug in Java not the provider. I.e., the JCA documentation
claims that overlapping ByteBuffers as arguments are allowed, the implementation
however doesn't. Oracle hasn't fixed the problem, though some providers e.g.
ConsCrypt patched it themselves.

**Patch:** Implementations shouldn't use aliased ByteBuffers.

The AES-GCM implementation uses a weak default size for the tag (i.e. 64 bits).
Such a tag size is not adequate for many use cases.

**Patch:** The implementation should always sepcify the tag size.

The Wycheproof test *testIvReuse* fails, because Spongy Castle allows to reuse a
previous IV simply by forgetting to initialze a Cipher instance after encrypting
with it. IV resuse leaks the authentication key.

**Patch:** The implementation should always reinitialize a Cipher instance, that
is call init() with a fresh IV. Other providers check that a call to init()
happens and throw exceptions if the caller fails to reinitialize a Cipher
instance.

## AES-CCM

The Wycheproof test *testAesCcm* fails, because Sponcy Castle does not check
that the size of the tag is valid. Encrypting and decrypting with invalid tag
sizes is insecure. It may leak secret information that is useful for a variety
of attacks.

**Patch:** The implementation must ensure that only valid parameters sizes are
used.

## AESWRAP, AESRFC5649Wrap

SpongyCastle tries to implement a padding check in constant time. This leads to
a number of runtime exceptions and hence leaks more information than any
potential timing attack. The good news is that KeyWrap itself is a robust
encryption mode and information leakage through chosen ciphertext attacks are
unlikely to lead to an attack.

## DH

The Wycheproof test *testSubgroupConfinement* fails because Sponcy Castle does
not perform an adequate validation of ephemeral public keys. There exist a
number of attacks against Diffie-Hellman where the attacker tries to trick
sender or receiver into using an ephemeral public key of low order. The attacks
can be prevented by using safe primes and key validation. Key validation is
difficult because the PKCS standard does not include all the necessary
parameters (i.e. q). Hence a full key validation is not possible. Spongy Castle
fails to include even simple checks.

**Patch:** Implementations should use either ECDH or add their own key
validation. For example using predefined Diffie-Hellman groups such as the ones
proposed in RFC 5114, allow to verify that ephemeral public keys do not have a
low order.

## DSA

The test *testDefaultKeySize* fails because Spongy Castle uses a 1024 bit
default key.

**Patch:** Implementations should avoid default values and set parameters
explicitly. (This is of course a recommnedation that generally holds). In
particular, an implementation should explicitly set the key size and algorithm
in order to avoid small 1024 bit keys or to avoid weak algorithms such as
"SHA1WITHDSA".

The test *testDsa* fails because Spongy Castle is very forgiving when parsing
ASN encoded DSA signature. This leads to signature malleability, but not
signature forgery. (Signature malleability means that one can change the
signature itself, but not the message signed by the signature.)

**Patch:** don't assume non-malleable signatures

## ECDSA

Spongy Castle is very forgiving when parsing ASN encoded ECDSA signatures. This
again leads to signature malleabiltiy, but not signature forgery.

**Patch:** don't assume non-malleable signatures

## ECDH

The test *testModifiedPublic* fails because Spongy Castle accepts some modified
public keys. Accepting modified public keys can lead to invalid curve attacks,
that leak the receivers private keys.

The test *testModifiedPublicSpec* also fails. This is a test similar to the test
above but with a different data structure. Failing to verify these parameters
may allow an invalid curve attack that recovers the private key.

The test *testWrongOrderEcdhc* fails because Spongy Castle accepts public keys
where the order of the subgroup has been modified. This private key is reduced
modulo this order. Hence it is for example possible to determine the private key
with a binary search.

**Patch:** The caller should always validate the public key and its parameters.
EC computations should be forced to use the same curve of the private key and
not what the public key pretends to use.

The test *testEncode* fails because Spongy Castle uses long form encoded public
keys in some cases. Typically all keys on named curves should use the OIDs of
these curves instead of encoding the parameters of that curve. The reason is
taht some providers only accept named curves. Hence using long form encoded
public keys can lead to incompatibilities.

## ECIES

Several of the tests for ECIES fail. A significant bug is that ECIES uses ECB
mode as default. The decryption using AesCbc checks and throws exceptions when
the PKCS padding is wrong even in the case where the HMAC is invalid. Hence this
allows a padding attack. The ECIES implementation in Bouncy Castle, including
the underlying protocols have been significantly rewritten and is no longer
compatible with Spongy Castle.

**Patch:** ECIES in Spongy Castle should not be used.

## RSA

The test *RsaEncryptionTest* fails because the PKCS1 decryption leaks
information about the padding. This information makes chosen ciphertext attacks
a lot easier.

**Patch:** Generally, PKCS #1 v1.5 encryption should no longer be used. Even a
library with a correct implementation can't avoid that information leakages in
other parts of the code are possible.

The test *RsaOaepTest* because the implementation of OAEP fails to include some
of the checks described in the standard. Spongy Castle throws runtime errors
instead of checked exceptions. This may lead to denial of service attacks if the
caller does not handle runtime exception. Otherwise the bugs are probably
harmless. **Patch:** Expect runtime errors when decrypting with RSA-OAEP.

The test *RsaPssTest* fails because Spongy Castle fails to include some checks
in the signature verification. The failure appears to be harmless, since there
is not enough freedom to forge signatures.
