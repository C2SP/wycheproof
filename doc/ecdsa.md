# ECDSA

[TOC]

The elliptic curve digital signature algorithm (ECDSA) is one of three signature
schemes descripted in the digital signature standard
[[FIPS-186-4]](bib.md#fips-186-4).

## Signature generation

ECDSA requires that each signature is computed with a new one-time secret k.
This secret value should be close to uniformly distributed. If that is not the
case then ECDSA signatures can leak the private key that was used to generate
the signature. Two methods for generating the one-time secrets are described in
Section B.5.1 or B.5.2 of [[FIPS-186-4]](bib.md#fips-186-4). There is also the
possibility that the use of mismatched implementations for key generation and
signature generation are leaking the private keys.

## Signature verification

An ECDSA signature is a DER encoded tuple of two integers (r,s). To verify a
signature of a messag $$m$$ the verifier first checks $$0 < r < n$$ and $$0 < s
< n$$. The verifier computes a (potentially truncated) hash $$z$$ of the message
$$m$$ and computes.

$$u_1=zs^{-1}\bmod{n}$$

$$u_2=rs^{-1}\bmod{n}$$

$$R = u_1G + u_2Y$$, where $$G$$ is the generator of the EC group and $$Y$$ is
the point of the public key.

The signature is valid if $$r$$ is equal to the x-coordinate of R.

## Bugs

### Weak one-time keys.

An important requirement for ECDSA signatures is that an attacker cannot learn
information about the nonces $$k$$ used for the signature generation. Generating
$$k$$ in a biased manner or leaking information about $$k$$ through side
channels can easily lead to practical attacks. Collecting even a small number of
signatures with biased $$k$$ can be enough to detect the private key
(e.g.,[[HowSma99]](bib.md#howsma99), [[NguSpa03]](bib.md#nguspa03)).

Breitner and Heninger analyzed a large number of ECDSA signatures in
[[BreHen19]](bib.md#brehen19) and found many cases where ECDSA signatures used
short nonces. A remarkable fact about this paper is that it analyzed ECDSA
signatures without knowing the secret key. To determine if the one-time keys
$$k$$ are biased it is necessary to recover the private key at the same time.

Non-constant time operations and other side channels can leak information about
the signing operations. Such issues are the cause for a large number of CVEs:
e.g., CVE-2014-0076, CVE-2016-7056, CVE-2016-2849, CVE-2016-7056, CVE-2018-12436
are just a few examples.

Project Wycheproof contains a small number of tests for biased one-time keys and
timing leaks. Since these tests require signature generation they only run
against JCE providers. The tests itself are also limited. A larger number of
vulnerabilities can be detected using the LLL algorithm. Unfortunately, we are
not aware of an efficient implementation of LLL in Java. Some more advanced
detections are however implemented in
[[ProjectParanoid]](bib.md#paranoidcrypto).

### Range checks

ECDSA signatures require that $$0 < r < n$$ and $$0 < s < n$$. If a library
omits these range checks and has a couple of additional weaknesses then it may
be possible that signatures can be forged.

Madden discovered in 2022 that OpenJDK above version 15 always accepted the
signature $$(0,0)$$ as valid [[Madden22]](bib.md#madden22). Another instance of
this vulnerability was found in Stark Bank's implementation:
[Arbitrary Signature Forgery in Stark Bank ECDSA Libraries](https://research.nccgroup.com/2021/11/08/technical-advisory-arbitrary-signature-forgery-in-stark-bank-ecdsa-libraries/) (CVE-2021-43568 to CVE-2021-43572).
A more recent recurrence of the bug is CVE-2022-41340.

One observation here is that libraries fall for the attack, even though it
requires multiple incorrect or missing steps. The range check alone would not
allow signature forgeries if the modular inverse would reject non-invertible
values or if the libraries do not return 0 for the x-coordinate of the point
at infinity. It is quite unfortunate that libraries often implement underlying
functions such as modular inverses without sufficient parameters checks and
that attacks exist that require such chains of bugs.


### Arithmetic errors

Elliptic curve implementations often use specialized methods for arithmetic
operations. This is typically done to speed up the primitives and to protect the
implementation from timing leaks. But specialized implementations have the
disadvantage that they frequently contain arithmetic errors. An examples of such
a bug is CVE-2020-13895.

The typical method for detecting arithmetic errors is to generate test vectors
with edge case signatures. For example it is possible to construct test vectors
with any values for (r, s), by selecting r and s first and then computing a
matching public key. Similarly it is possible to construct test cases for other
special case values such as $$u_1$$ and $$u_2$$.

Project Wycheproof typically contains valid ECDSA signatures with edge case
values. Hence the effect of arithmetic errors is that the faulty library rejects
valid signatures. It is however important to note that the same error that
renders valid signatures invalid, may also have the effect that invalid
signatures pass as valid. Hence arithmetic errors should not be underestimated.

### Signature malleability

A signature scheme has signature malleability when it is possible to slightly
modify an existing signature for a message $$m$$ so that the modified result is
still a valid signature for the message $$m$$. One property of ECDSA is that if
a pair $$(r,s)$$ is a valid signature for a message $$m$$ then $$(r, n-s)$$ is
also a valid signature. Typically signature malleability is not a security
issue. However, when the design of a protocol is flawed then it can be possible
to exploit such properties. An example of such a protocol flaw is described in
(https://en.bitcoin.it/wiki/Transaction_malleability).

A question that poses itself is whether ASN.1 encoded signatures should require
DER encoding or if alternative BER encoding are incorrect. The encoding of ECDSA
signatures is not addressed in the DSS standard
[[FIPS-186-4]](bib.md#fips-186-4).Other references such as RFC 6979 specify that
ASN.1 encoded ECDSA signatures should use DER to generate a signature, but don't
mention verification.

Hence one has to refer to common practice. Many cryptographic libraries do
indeed expect that ECDSA signatures are DER encoded, hence generating a
signature that is not DER encoded clearly should be a bug. Common mistakes in
the DER encoding are:

*   not including a leading zero in the encoding of an integer. An additional
    leading zero byte is required for a positive integer when the most
    significant byte would otherwise have a value in the range 128 .. 255, since
    a leading byte in the range 128 .. 255 represents a negative integer.
*   including unnecessary leading zero bytes in the encoding of an integer. DER
    requires that the shortest possible representation of an integer is used.

There are some CVEs where libraries were reported that accepted other than DER
encodings: e.g., CVE-2020-14966, CVE-2020-13822, CVE-2019-14859,
CVE-2016-1000342. (Some of these CVEs whave have high vulnerability scores,
which appears to be a bit surprising).

Wycheproof test vectors for ECDSA signature verifiction with alternative BER
encoding have a "BER" flag to indicate the nature of the modification. The
motivation of such flags is to make it simpler to determine if a library suffers
from additional problems.
