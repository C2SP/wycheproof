# AES-GCM

This encryption mode is described in [[AES-GCM]](bib.md#aes-gcm).

## Nonce reuse

One of the undesirable properties of AES-GCM is that reusing the same IV for the
same key leaks the authentication key [[Joux-Gcm]](bib.md#joux-gcm). Typically,
implementations can't enforce that users don't repeat IVs unless they use
restricted interfaces. However, implementations should at least avoid features
that increase the probability of incorrect usages.

One such dangerors featur in JCA is that the default behaviour of Cipher.doFinal
is to reinitialize the cipher with the same parameters as the last encryption.
For AES-GCM this behaviour would imply that the authencation key is leaked.
Therefore, any reasonable implementation of AES-GCM should not allow two
encryptions without an explicit initialization of the IV.

The expected behaviour of OpenJDK can be derived from the tests in
jdk/test/com/sun/crypto/provider/Cipher/AES/TestGCMKeyAndIvCheck.java: OpenJDK
does not allow two consecutive initializations for encryption with the same key
and IV.

## CTR overflow with IVs of size 12

The counter value in AES-GCM wraps around after $$2^{32}$$ blocks. If a
plaintext is $$2^{32}$$ blocks or longer then the encryption would encrypt the
same counter value twice, once to encrypt a block of plaintext and once to to
compute the authentication tag. To avoid this implementations must not allow to
encrypt plaintexts longer than $$2^{32}-2$$ blocks.

## CTR overflow with IVs of sizes other than 12

### What is the problem?

Incrementing counters in AES-GCM is different than incrementing counters in
AES-CTR. AES-GCM increments counters modulo $$2^{32}$$, while AES-CTR increments
them modulo $$2^{128}$$. E.g. if the counter value for a block is

```
0xffffffffffffffffffffffffffffffff
```

then the counter for the next block in AES-GCM is

```
0xffffffffffffffffffffffff00000000
```

But for AES-CTR the counter for the next block is

```
0x00000000000000000000000000000000
```

For AES-GCM the typical IV size is 12 bytes. For this size of the IV the counter
starts as `IV || 00000001`. AES-GCM allows no ciphertexts longer than
$$2^{32}-2$$ blocks. Hence for 12 byte IVs no counter overflow happens and it
does not matter which version is used for incrementing counters. If the IV size
is different than 12 bytes then initial IV is computed by using GHASH. The
initial value can be any arbitrary 128-bit value and counter overflows are
possible for messages longer than 16 bytes.

When an implementation of AES-GCM is handling CTR overflows incorrectly (e.g.
reuses code from an AES-CTR implementation) then encrypting with an IV of size
other than 12 bytes may result in incorrect ciphertext. This happens on average
once every $$2^{32}$$ blocks of plaintext.

Encrypting with a faulty version of the code results in incorrect ciphertext,
which can be decrypted again with the same faulty version of the code. When
trying to decrypt with a correct version of AES-GCM then the authentication
passes (since the authentication tag is computed over the ciphertext and thus
unaffected by incorrect encryption), but the decrypted plaintext is incorrect.
The situation where encryption is correct, but decryption is faulty is similar:
the authentication passes, but the plaintext is wrong.

Besides returing incorrect plaintext, this bug can leak the authentication key.
One scenario where this bug is exploitable is the following: We assume that
there is a client-server scenario where either the client or the server use a
faulty encryption rsp. decryption (but not both). We assume that the client
sends AES-GCM encrypted messages of about 1 MB (i.e. $$2^{16}$$ blocks) to the
server. (The size of the message is not very relevant. Fixing a size just makes
the example a bit easier). We assume that random 16 byte IVs are used. (If the
IVs are 12 bytes then faults don't happens. If the IVs are shorter or not random
then the equations below may become dependent of each other. IVs longer than 16
bytes would complicate the equations.) We assume further that the attacker
learns the ciphertext and that the attacker learns whether the ciphertext was
corrupt or not. Under the assumptions above one out of every $$2^{16}$$ messages
is encrypted or decrypted incorrectly. The attacker waits until he has 8 or 9
rejected messages. An incorrect decryption indicates that a counter overflow
occurred, and hence that the initial counter was
`0x????????????????????ffff????`, where ? or unknown nibbles. The initial
counter J0 is computed over $$\mbox{GF}(2^{128})$$ as $$J_0 = \mbox{IV} * H^2 +
\mbox{len}(\mbox{IV})\cdot H$$ where H is the authentication key. Hence, $$J_0$$
is a linear function of H over $$\mbox{GF}(2^{128})$$. Equivalently, the
equation above is a system of 128 linear equations over $$\mbox{GF}(2)$$, i.e.
one equation for each bit of $$J_0$$. Under the assumptions above 16 bits of J0
are known for each message that is rejected. Knowing 8 or 9 rejected messages
give 128 or 144 linear equations over $$\mbox{GF}(2)$$ with the 128 bits of H as
unknowns. Hence, we expect that the system is solvable with high probability.

If the size of the encrypted messages is smaller, then less corrupt messages are
necessary but more encryptions are necessary until sufficiently many bugs occur.
The attack is a bit simpler if an attacker also learns the approx. position
where the decrypted plaintext starts to become incorrect. Overall, approx.
200-600 GB of data needs to be encrypted with the same key so that the attack
here gets enough information to derive the authentication key.

The attack above is just one way to exploit the weakness. Other attack scenarios
might be possible, but I haven't explored them. In particular the attack above
is passive. The attacker just needs the ability to observe an encrypted
connection. The tag size is irrelevant.

Under the assumption that chosen ciphertext attacks are possible it might be
possible to combine the attack above with Fergusons attack
https://csrc.nist.gov/csrc/media/projects/block-cipher-techniques/documents/bcm/comments/cwc-gcm/ferguson2.pdf
and attack connections with frequent key rotations.

### Detecting the problem

Since GHASH is linear function it easy to construct test vectors where the
counter overflow occurs within the first few increments. (I.e. one fixes $$J_0$$
and solves for a corresponding value for the IV.) An example for such a test
case is:

```
key : "00112233445566778899aabbccddeeff",
iv : "dd9d0b4a0c3d681524bffca31d907661",
aad : "",
msg : "00000000000000000000000000000000000000000000000000000000000000000000000000000000",
ct : "64b19314c31af45accdf7e3c4db79f0d948ca37a8e6649e88aeffb1c598f3607007702417ea0e0bc",
tag : "5281efc7f13ac8e14ccf5dca7bfbfdd1",
```

### Failing providers
The AES-GCM implementation in jdk9 handled CTR overflows incorrectly
[[CVE-2018-2972]](bib.md#cve-2018-2972).


## 0 size IV

AES-GCM allows IVs of bit length $$1 \ldots 2^{64}-1$$. (See
[[NIST-SP800-38d]](bib.md#nist-sp800-38d), Section 5.2.1.1)

Disallowing IVs of length 0 is necessary. If an empty IV is used then the tag is
an evaluation of a polynomial with the hash subkey as the value. Since the
polynomial can be derived from the ciphertext it is known to an attacker.
Therefore, any message encrypted with an empty IV leaks the hash subkey. In
particular, encrypting an empty plaintext with an empty IV results in a
ciphertext having a tag that is equal to the hash subkey used in AES-GCM. I.e.
both are the same as encrypting an all zero block.
