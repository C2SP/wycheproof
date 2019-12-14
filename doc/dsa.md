# DSA

[TOC]

The digital signature algorithm (DSA) is one of three signature schemes
descripted in the digital signature standard [[FIPS-186-4]](bib.md#fips-186-4).

## Key generation

4.2 Selection of Parameter Sizes and Hash Functions for DSA The DSS specifies
the following choices for the pair (L,N), where L is the size of p in bits and N
is the size of q in bits:

L    | N
---: | --:
1024 | 160
2048 | 224
2048 | 256
3072 | 256

The tests expect the following properties of the parameters used during key
generation:

*   If only the parameter L is specified by the caller then N should be one of
    the options proposed in [[FIPS-186-4]](bib.md#fips-186-4).
*   If no size is specified then L should be at least 2048. This is the minimal
    key size recommended by NIST for the period up to the year 2030.

## Signature generation

The DSA signature algorithm requires that each signature is computed with a new
one-time secret k. This secret value should be close to uniformly distributed.
If that is not the case then DSA signatures can leak the private key that was
used to generate the signature. Two methods for generating the one-time secrets
are described in FIPS PUB 186-4, Section B.5.1 or B.5.2
[[FIPS-186-4]](bib.md#fips-186-4). There is also the possibility that the use of
mismatched implementations for key generation and signature generation are
leaking the private keys.

## Signature verification

A DSA signature is a DER encoded tuple of two integers (r,s). To verify a
signature the verifier first checks $$0 < r < q$$ and $$0 < s < q$$.
<!-- Some libraries don't check that r and s are integers.-->
The verifier then computes:

$$
\begin{array}{l}
w=s^{-1} \bmod q\\
u1 = w \cdot H(m) \bmod q\\
u2 = w \cdot r \bmod q\\
\end{array}
$$

and then verifies that $$r = (g^{u1}y^{u2} \bmod p) \bmod q$$

## Incorrect computations and range checks.

Some libraries return 0 as the modular inverse of 0 or q. This can happen if the
library computes the modular inverse of s as $$w=s^{q-2} \mod q$$ (gpg4browsers)
of simply if the implementations is buggy (pycrypto). if additionally to such a
bug the range of r,s is not or incorrectly tested then it might be feasible to
forge signatures with the values (r=1, s=0) or (r=1, s=q). In particular, if a
library can be forced to compute $$s^{-1} \mod q = 0$$ then the verification
would compute $$ w = u1 = u2 = 0 $$ and hence $$ (g^{u1}y^{u2} \mod p) \mod q =
1 .$$

## Timing attacks

TBD

# Some notable failures of crypto libraries.

## JDK

The jdk8 implementation of SHA1withDSA previously checked the key size as
follows:

```java
@Override
  protected void checkKey(DSAParams params)
     throws InvalidKeyException {
    int valueL = params.getP().bitLength();
    if (valueL > 1024) {
       throw new InvalidKeyException("Key is too long for this algorithm");
   }
 }
```

This check was reasonable, it partially ensures conformance with the NIST
standard. In most cases would prevent the attack described above.

However, Oracle released a patch that removed the length verification in DSA in
jdk9: http://hg.openjdk.java.net/jdk9/dev/jdk/rev/edd7a67585a5
https://bugs.openjdk.java.net/browse/JDK-8039921

The new code is here:
http://hg.openjdk.java.net/jdk9/dev/jdk/file/edd7a67585a5/src/java.base/share/classes/sun/security/provider/DSA.java

The change was further backported to jdk8:
http://hg.openjdk.java.net/jdk8u/jdk8u/jdk/rev/3212f1631643

Doing this was a serious mistake. It easily allowed incorrect implementations.
While generating 2048 bit DSA keys in jdk7 was not yet supported, doing so in
jdk8 is. To trigger this bug in jdk7 an application had to use a key generated
by a third party library (e.g. OpenSSL). Now, it is possible to trigger the bug
just using JCE. Moreover, the excessive use of default values in JCE makes it
easy to go wrong and rather difficult to spot the errors.

The bug was for example triggered by the following code snippet:

```java
    KeyPairGenerator keygen = KeyPairGenerator.getInstance("DSA");
    Keygen.initialize(2048);
    KeyPair keypair = keygen.genKeyPair();
    Signature s = Signature.getInstance("DSA");
    s.initSign(keypair.getPrivate());
```

The first three lines generate a 2048 bit DSA key. 2048 bits is currently the
smallest key size recommended by NIST.

```java
    KeyPairGenerator keygen = KeyPairGenerator.getInstance("DSA");
    Keygen.initialize(2048);
    KeyPair keypair = keygen.genKeyPair();
```

The key size specifies the size of p but not the size of q. The NIST standard
allows either 224 or 256 bits for the size of q. The selection typically depends
on the library. The Sun provider uses 224. Other libraries e.g. OpenSSL
generates by default a 256 bit q for 2048 bit DSA keys.

The next line contains a default in the initialization

```java
    Signature s = Signature.getInstance("DSA");
```

This line is equivalent to

```java
    Signature s = Signature.getInstance("SHA1withDSA");
```

Hence the code above uses SHA1 but with DSA parameters generated for SHA-224 or
SHA-256 hashes. Allowing this combination by itself is already a mistake, but a
flawed implementation made the situation even worse.

The implementation of SHA1withDSA assumeed that the parameter q is 160 bits long
and used this assumption to generate a random 160-bit k when generating a
signature instead of choosing it uniformly in the range (1,q-1). Hence, k
severely biased. Attacks against DSA with biased k are well known.
Howgrave-Graham and Smart analyzed such a situation
[[HowSma99]](bib.md#howsma99). Their results show that about 4 signatrues leak
enough information to determine the private key in a few milliseconds. Nguyen
analyzed a similar flaw in GPG [[Nguyen04]](bib.md#nguyen04). I.e., Section 3.2
of Nguyens paper describes essentially the same attack as used here. More
generally, attacks based on lattice reduction were developed to break a variety
of cryptosystems such as the knapsack cryptosystem
[[Odlyzko90]](bib.md#odlyzko90).

## Further notes

The short algorithm name “DSA” is misleading, since it hides the fact that
`Signature.getInstance(“DSA”)` is equivalent to
`Signature.getInstance(“SHA1withDSA”)`. To reduce the chance of a
misunderstanding short algorithm names should be deprecated. In JCE the hash
algorithm is defined by the algorithm. I.e. depending on the hash algorithm to
use one would call one of:

```java
  Signature.getInstance(“SHA1withDSA”);
  Signature.getInstance(“SHA224withDSA”);
  Signature.getInstance(“SHA256withDSA”);
```

A possible way to push such a change are code analysis tools. "DSA" is in good
company with other algorithm names “RSA”, “AES”, “DES”, all of which default to
weak algorithms.
