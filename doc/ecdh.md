# ECDH

[TOC]

## ECDH description:

See https://en.wikipedia.org/wiki/Elliptic_curve_Diffie%E2%80%93Hellman

## Invalid key attack

Some libraries do not check if the elliptic curve points received from another
party are points on the curve. This can often be exploited to find private keys
[[BeMeMu00]](bib.md#bememu00)), [[ABMSV03]](bib.md#abmsv03). Encodings of public
keys typically contain the curve for the public key point. If such an encoding
is used in the key exchange then it is important to check that the public and
secret key used to compute the shared ECDH secret are using the same curve.

Failing to check for these problems is a frequent problem:
[[CVE-2015-6924]](bib.md#cve-2015-6924),
[[CVE-2015-7940]](bib.md#cve-2015-7940),
[[CVE-2016-9121]](bib.md#cve-2016-9121),
[[CVE-2017-16007]](bib.md#cve-2017-16007),
[[CVE-2018-5383]](bib.md#cve-2018-5383).

The test vectors check for the following problems:

*   point is not on curve
*   point is on twist
*   curve of public key is used for ECDH
*   parameters of public key are used for ECDH

### Countermeasures

*   use point compression. Formats such as X509EncodedKeySpec in Java include
    bits that indicate whether the point is compressed or not. Hence an attacker
    can always choose to use uncompressed points as long as this option is
    incorrectly implemented.
*   check that public and private key use the same curve
*   restrict the protocol to named curves
*   reconstruct the public key explicitly using the parameters of the private
    key.

## Side channel attacks that may be detectable by Wycheproof

### Arithmetic errors

Arithmetic errors in the implementation of the elliptic curve point
multiplication can lead to attacks.

### Timing differences

Large enough timing differences can give a signal that is exploitable.

### Typical attacks

In a typical attack scenario the malicious party is able to choose the ephemeral
key, and has means to detect if the computation of the other party triggers a
special case.

One particular attack has been proposed in [[Goubin03]](bib.md#goubin03). The
author pointed out that points with a coordinate 0 keeps this property even if
the projective or Jacobian coordinates are randomized. If a point multiplication
that encounters such a point can be distinguished from other point
multiplication (e.g. because the integer arithmetic is not constant time) then
an attack is possible. The attack has been extended by Akishita and Takagi
[[AkiTak03]](bib.md#akitak03). The authors showed that other places in a point
multiplication have similar properties and hence that additional attacks are
possible. The golang library was susceptible to this attack, since doubling a
point with x-coordinate 1 typically resulted in an virtually endless loop
[[CVE-2019-6486]](bib.md#cve-2019-6486). A recent survey about timing and side
channel attaks is [[AbVaLo19]](bib.md#abvalo19)).

## Side channel attacks that are not detectable by Wycheproof

Physical side channel attacks e.g. based on power analsis or electromagnetic
emanation have been demonstrated [[GPPT16]](bib.md#gppt16). Testing for such
side channels is not possible in Wycheproof.

### Countermeasures

*   constant time implementation (does not cover arithmetic errors)
*   randomization (harder than it looks)
*   Checking that points are on the curve after point multiplication. (Detects a
    potential problem, but does not prevent it).

## Invalid encodings

Another type of bugs is the handling of invalid encodings. The damage of these
kind of bugs depends on the exception handling. A frequent consequence of not
testing encoding properly are denial of service attacks.

The test vectors contain a number of invalid encoded ephemeral keys. Some of the
test vectors contain a shared secret key. This is done so that a ECDH
computation done after importing an invalid key can be evaluate. I.e. If
importing a key is somewhat forgiving, but the ECDH compuatation is nevertheless
correct then this is less likely to lead to an attack than if the ECDH
compuation after importing an invalid key leads to an incorrect point
multiplication.
