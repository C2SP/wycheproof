
# ECDH

[TOC]

##ECDH description:
See https://en.wikipedia.org/wiki/Elliptic_curve_Diffie%E2%80%93Hellman

##Bugs
Some libraries do not check if the elliptic curve points received from another
party are points on the curve. Encodings of public keys typically contain the
curve for the public key point. If such an encoding is used in the key exchange
then it is important to check that the public and secret key used to compute
the shared ECDH secret are using the same curve.
Some libraries fail to do this check.

**Potential exploits:**
The damage done depends on the protocol that uses ECDH. E.g. if ECDH is used
with ephemeral keys then the damage is typically limited. If the EC keys are
static, i.e. used for multiple key exchanges then a failure to verify a public
point can disclose the private key used in the same protocol.
(To do: add papers describing the attack).

##Libraries
**Sun JCE provider:**
ECDH does not check if the points are on the curve.
The implementer must do this.

**Bouncycastle:**
The ECDH implementation does not check if the point is on the curve.
Furthermore, Bouncycastle does not even check if the public and private key are
on the same curve. It performs a point multiplication \\(x \cdot Y\\) over the
curve specified by the public key.

**OpenSSL:**
Point verification is done in OpenSSL if the right functions are used.
Since OpenSSL is not well documented it is a bit tricky to find the right
functions.
(To do: maybe add an example).

##Countermeasures
TODO:
* use point compression. Formats such as X509EncodedKeySpec
in Java include bits that indicate whether the point is compressed or not.
Hence an attacker can always choose to use uncompressed points as long as this
option is incorrectly implemented.
* check that public and private key use the same curve
* restrict the protocol to named curves
* reconstruct the public key explicitly using the parameters of the private
  key.

**Further recommendations:**
If possible I also check if the points are on the curve after point
multiplications on an elliptic curve in the hope to catch implementation
and hardware faults.

## Some notable bugs:
* ECDHC in bouncy castle could be broken by modifying the order of the public key.
