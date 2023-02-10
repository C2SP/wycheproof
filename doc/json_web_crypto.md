# JSON Web Crypto

A family of standards that define how to represent keys, encrypted, and signed
messages as JSON.

-   JSON Web Signature: RFC 7515
-   JSON Web Encryption: RFC 7516
-   JSON Web Key: RFC 7517
-   JSON Web Algorithms: RFC 7518
-   JSON Web Token: RFC 7519
-   Examples: RFC 7520

## Untrusted `none` alg Header

This vulnerability is tested with
`jws_aes.rejectsNoneAlgorithmAndMissingSignature`.

The compact serialization for JWS is:

```
BASE64URL(UTF8(JWS Protected Header)) || '.' ||
BASE64URL(JWS Payload) || '.' ||
BASE64URL(JWS Signature)
```

Where the `JWS Signature` input is defined as:

```
ASCII(BASE64URL(UTF8(JWS Protected Header)) || '.' || BASE64URL(JWS Payload))
```

Please note that in the compact serialization format, there's no such thing as
an unprotected header. All headers are protected by the accompanying signature.
In theory, this is secure. In practice, some libraries are set up in a way where
the developer's intention to validate a signature can be thwarted by a
maliciously modified payload. An attacker can take a valid payload, remove the
`JWS Signature` component (the empty string is valid), replace `JWS Protected
Header` with a modified one that claims the algorithm is `none`, and then mutate
the `JWS Payload` as much as they want. If the library ignores the fact that the
developer provided a verification JWK, it might accidentally accept the
malicious payload.

It's important to understand that this isn't about the developer making a
mistake and asking for the library to validate a JWS without providing a key.
This is actually providing a key but having the library silently accept the
payload as valid even though it wasn't actually signed. The JWS spec never
should have included the `none` option. Most libraries have either disabled
`none` or fixed their APIs to ban it whenever keys were provided.

## Symmetric/Asymmetric Signature Type Confusion

This vulnerability is tested with
`jws_ec.rejectsSymmetryConfusionAttacks_aesKeyFromEcVerificationKeyBytes`.

With asymmetric crypto, the assumption is the attacker has access to your public
verification key but does not have access to your private signing key. With
symmetric crypto, the attacker doesn't have access to the shared secret
signing/verification key. A problem arises when the developer uses the library
to verify an asymmetric signature but the library relies on untrusted input to
decide what type of verification to perform.

An attacker can create an arbitrary payload, obtain the public verification key
(it's public), take the bytes of the verification key and use it as a symmetric
HMAC key, produce a valid signature for their payload, and hand the malicious
payload to the unsuspecting server. If the library looks at the headers, sees
that the `alg` field indicates symmetric signing, and then proceeds to interpret
the public verification key given to it by the developer as a secret symmetric
key, it'll incorrectly conclude that the JWS is valid.

Here's an example of a vulnerable library's API signature: `boolean verify(String
serializedJws, String verificationKey)` As you can see, the developer has no way
of telling the library that they want to verify an asymmetric signature. The key
they provide is "stringly typed". The library might inspect the String and
conclude that it looks like a public RSA key and do the right thing. However, it
might also look at the as-yet-unverified `alg` field on the tampered payload,
see that the attacker says that it's an HMAC signature, and proceed to convert
the string into bytes and use it as a HMAC secret key. If the attacker
transformed the public verification key in the same way as the library just did,
the signature will verify correctly and the server will accept the malicious
payload.

## Attacker-Chosen Verification Key

This vulnerability is tested with `jws_ec.rejectsAttackerProvidedEmbeddedJwk`.

The [JWS RFC](https://tools.ietf.org/html/rfc7515#section-4.1.3) defines the JWS
header value `jwk`. This header can be included in the serialized JWS that the
server is trying to verify. Its purpose is defined as: `The "jwk" (JSON Web Key)
Header Parameter is the public key that corresponds to the key used to digitally
sign the JWS. This key is represented as a JSON Web Key [JWK]. Use of this
Header Parameter is OPTIONAL.`

In both asymmetric and symmetric crypto, choosing which verification key to use
absolutely must be under your **sole** control. The attacker can simply generate
their own keypair, use it to sign an arbitrary payload, and then send it to the
server. Normally the server would reject the JWS as invalid since the signature
didn't validate according to the verification key provided by the developer.
However, if the developer's choice is ignored in favor of the attacker's then
the whole thing falls apart.

It's essentially the same thing as being able to change the password on an
account to whatever you want before attempting to login.

There are several [examples](https://rwc.iacr.org/2017/Slides/nguyen.quan.pdf)
of this happening. One library even ignored the spec requiring that `jwk` be a
public key; it accepted symmetric keys as well.

Similar issues exist with `jku`, `x5u`, and `x5c` which simply point to the keys
that should be trusted.

## ECDH Invalid Curve Attack

This vulnerability is tested with `jwe_ec.rejectsInvalidCurvePoint`.

This is a common vulnerability that can exist in any library that deals with
ECDH. There's at least one
[example](https://rwc.iacr.org/2017/Slides/nguyen.quan.pdf) of this happening
with a JW crypto library. However, it's a common problem even outside the
context of JW crypto.

When using elliptic-curve Diffie-Hellman with the standard NIST-defined curves,
it's crucial that the library reject attacker-controlled points that are not
actually on the curve being used. If the library proceeds to use the invalid
points, it will start leaking portions of its private key since the curve may
only have a handful of points on it (instead of many like the secure curves
have).

With this attack, the attacker only has to send a few payloads using each curve
of small order until they get a "successful decryption" response. Once obtained,
they try again with another small order curve. Once enough values are collected,
they can use the Chinese Remainder Theorem to recover the secret key.

For example, if the secret key `s` is 22,040 (way too small but this is just an
example), the attacker can send at most 179 JWEs to find out that `s mod 179 =
23`. They can then send at most 2,447 JWEs to find out that `s mod 2447 = 17`.
Using the theorem, they can efficiently derive the value of `s` much quicker
than brute force.

For this attack to work, the server must use the same key multiple times, which
is exactly what `ES256` (ECDSA using P-256 and SHA-256) does.

This type of problem is typically caused by issues with the lower-level crypto
library and is something that Project Wycheproof checks for directly. However,
this particular problem is so widespread that it's been included here as well.

## JWK Keyset Mixed Symmetry

This vulnerability is tested with `jws_mixedSymmetryKeyset.rejectsValid`.

Most libraries work with single JSON Web Keys as well as JSON Web Keysets which
can contain multiple keys. Typically a keyset will contain one key during the
steady state and two keys during a period of rotation. The new key may be the
exact same kind of key as the old or it might be similar (but stronger). Rarely,
it may even contain a new kind of key (going from an RSA decryption key to an
elliptic curve decryption key).

What should never happen however is changing symmetry types or mixing secret
keys and public keys. You never want to rotate from an AES decryption key to an
RSA decryption key. Yes both are secret but they have very different properties.
This becomes obvious when considering the encryption keyset... It would need to
contain a secret AES encryption key and a public RSA encryption key. There's
just too much of a chance that that keyset will be mishandled and the AES key
leaked.

## JWE/JWS JSON Serialization

This vulnerability is tested with `jws_aes.rejectsValidJsonSerialization` and
`jwe_aes.rejectsValidJsonSerialization`.

JWE and JWS can be serialized with compact serialization or
[JSON serialization](https://tools.ietf.org/html/rfc7515#section-3.2). The
latter has several issues and should be avoided since it's much harder to get
right compared with compact serialization. An incomplete list of problems
follows.

Both JWE and JWS JSON serialization support unprotected headers. Here,
"unprotected" means the signature/MAC doesn't take their value into account and
therefore everything about them is completely changeable by an attacker and the
victim will have no way of detecting it. An attacker can:

-   Change the values of every unprotected header
-   Completely remove unprotected headers
-   Add new unprotected headers even if the original didn't include any at all

Fortunately, the RFC does state that, "The Header Parameter names in the two
locations MUST be disjoint". This sounds like it prevents the case of an
unprotected header value taking precedence over a protected header value but
opportunity for bugs abound. What if the library forgot to compare headers in
canonical form -- `"alg"` vs `"ALG"`? Any library that asks its
non-cryptographer users to decide what does and doesn't deserve integrity
protections is a bad library. The right answer is to integrity-protect the
entire message and take the guesswork out of it.

JWS JSON serialization supports multiple signatures, each with their own
protected headers. The API library authors that have chosen to support this
don't always make it clear that when 2 of 3 signatures verified, the headers
from the 1 that failed verification shouldn't be trusted.


## Chosen ciphertext attacks

JWE made a number of design choices that greatly facilitate chosen ciphertext
attacks attacks against ciphertexts encrypted with RSA.
Probably the single most devastating mistake was to include RSA encryption with
PKCS #1 padding into the standard. At the time the RFC was written, chosen
ciphertext attacks with PKCS #1 padding were well known. The large number of CVEs
document that correct implementations of RSA PKCS #1 are difficult.
RSA-OAEP had excellent support in underlying libraries. A library that only
supported RSA PKCS #1 but not RSA-OAEP could reasonable be called outdated.

Some implementations of JWE have been analyzed in the paper
[DSMMS16](bib.md#dsmms16).
The authors found a number of libraries that were succeptible to chosen
ciphertext attacks.


### Chosen ciphertext attack in jose4j

An example of a library that was recently susceptible to chosen ciphertext
attacks was jose4j. If a padding error happened during decryption then the
library would generate a random symmetric key of the expected size.
If a modified ciphertext had correct PKCS #1 padding then the encoded message
would be returned. With high probability this message had a size that is not
a valid key size. Hence valid and invalid paddings resulted in distinguishable
behavior: the exceptions thrown in the two cases were distinct. The library
would attempt to decrypt the symmetric part of the ciphertext in one case and
skip it in the other case, leading to a timing difference.

One observation here is that it is very difficult to fully remove all artefacts
in Java by using the JCE interface. Wrong PKCS #1 paddings throw an exception,
while valid paddings don't. Hence attacks using side channels such as the
ones described in [RGGSWY18](bib.md#rggswy18) may still be possible.

Test vectors in wycheproof/testvectors/json_web_encryption_test.json can be
used to test for this vulnerability. One drawback is that they are currently
provider dependent.

## Ignoring "alg" field in key

Unfortunately there are more unlucky design choices in JWE. One is to put an
"alg" field into the header of a ciphertext. The alg field defines which
encryption algorithm has been used for the encryption. A well known
cryptographic principle states that each key should be used for one purpose
(rsp. algorithm) only. 

Some key types allow multiple algorithms. The algorithm associated with
a key can be specified using the "alg" field. For example if an RSA key has
the format

```
{
        "alg": "RSA-OAEP",
        "use": "enc",
        "n": "...",
        "e": "...",
        "d": "...",
        "p": "...",
        "q": "...",
        "dp": "...",
        "dq": "...",
        "qi": "...",
        "kid": "...",
        "kty": "RSA"
}
```

and the ciphertext has a header such as

```
{"alg":"RSA1_5","enc":"..."}
```

then we expect that the ciphertext is rejected without trying any decryption.
Otherwise bugs in the RSA1_5 implementation can be exploited even if even
the receiver only intents to use RSA-OAEP.

RFC 7517 Section 4.4 declares the "alg" field in the key as optional.
This appears to be a shortcoming of the RFC. At least some applications
using JWE mitigate the danger that come with such a definition by adding
additional restrictions on valid keys. Rejecting ambiguous keys is very
reasonable. As a result Wycheproof does not include test vectors with
ambiguous keys.

For example RFC 7520 gives test vectors for JWE and JWS. Some of the
test vectors are included in the Wycheproof tests.
Some test vectors in RFC 7520 do not include an algorithm in the key.
Since we consider it very reasonable if an implementations would reject
such keys, the test vectors were modified in Wycheproof to always
include the "alg" field. Keys without an "alg" field may or may not be rejected.
