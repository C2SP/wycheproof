# AEGIS

This cipher is described in [[WuPre14]](bib.md#WuPre14). Three version of AEGIS
have been proposed: 

* AEGIS128: a slower, more conservative version with a 128-bit key, 

* AEGIS128L: a faster version with a 128-bit key,

* AEGIS256: a version that uses a 256-bit key.

AEGIS128 has been selected into the final protofolio of the CAESAR competition.

## Versions

Previous versions of the cipher differ slightly from the submission to the
CAESAR competition. E.g., https://eprint.iacr.org/2013/695.pdf computes the tag
of AEGIS128L over S[0] .. S[7], while CAESAR submission use S[0] .. S[6]. The
test vectors of AEGIS256 in the IACR paper use 6 rounds in finalize. This number
was subsequently changed to 7.

The test vectors in Wycheproof use the versions described in
[[WuPre14]](bib.md#WuPre14). The same versions of AEGIS are also used in
https://www.ietf.org/archive/id/draft-denis-aegis-aead-01.html

## Nonce reuse

AEGIS does not allow nonce reuse.

A detailed analysis of this property can be found in
[[VauViz17]](bib.md#VauViz17). The paper claims that 15 queries with reused
nonces are enough to find the internal state of Aegis128. Assuming no additional
data is authenticated, then the attack allows to decrypt any ciphertext
encrypted with the same nonce and key and allows to encrypt additional messages.

Our experiments confirm the attack and further reduce the number of queries to 9
for Aegis128 or 7 for Aegis128L.

## Releasing unauthenticated decryptions

The authors of [[WuPre14]](bib.md#WuPre14) stress that AEGIS has not been
designed, such that unverified partial partial decryptions can be released. The
paper does not give an analysis.

The attack by Serge Vaudenay and Damian Vizár above can also be used in this
situation. An attacker can learn the internal state of AEGIS with a chosen
ciphertext attack if decryption leaks unverified partial plaintext.

Leaking even small amounts of information can lead to an attack. For example, an
implementation of the attack above confirmed that leaking whether a partially
decrypted message contains non-ASCII characters was enough to recover the
internal state of AEGIS. Hence, it is important that implementations of AEGIS do
not process partially decrypted messages before the tag verification.
