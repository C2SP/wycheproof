# Chunked encryption

This document explains how to apply Wycheproof test vectors to an
implementation of the [c2sp.org/chunked-encryption][] scheme (Cobblestone).

> [!TIP]
> This document can double as an LLM "skill" if you ask an agent to apply it.

There is one test vector file per instantiation:

- `testvectors_v1/c2sp_chunked_encryption_aes_128_gcm_test.json` for
  Cobblestone-128
- `testvectors_v1/c2sp_chunked_encryption_aes_256_gcm_test.json` for
  Cobblestone-256

The `aead` property of each test group is the underlying AEAD by IANA registry
name (`AEAD_AES_128_GCM` or `AEAD_AES_256_GCM`), and the `sha` property is the
hash function used for HKDF-Expand (`SHA-512` in both Cobblestone
instantiations).

### Ciphertext compression

The `ct` property is the ciphertext, zlib-compressed and then hex-encoded:
decode the hex, then decompress the resulting zlib stream. (Some vectors
exercise the rollover of the chunk counter past one byte, and are more than
4 MiB long. They are generated such that the ciphertext is almost entirely
zero bytes, which compresses very well.)

For example, in Python use `zlib.decompress(bytes.fromhex(ct))`, or in Go use
`compress/zlib`.

### Decryption

Decryption can be tested by decrypting `ct` with `key` as the input key and
`ctx` as the context. `ctx` is a hex-encoded byte string, and may be empty
or contain arbitrary bytes.

Decryption of `valid` vectors must succeed, and the resulting message must be
`msgLength` bytes long with SHA-512 hash `msgSha512`. (The message itself is
not included in the vectors because it can be multiple MiB long.)

Decryption of `invalid` vectors must fail. Vectors with the `InvalidKeySize`
flag must be rejected when the key is provided.

### Streaming decryption

`invalid` vectors with the `PartialPlaintext` flag start with validly
encrypted chunks: their `msgLength` and `msgSha512` properties describe the
longest valid message prefix. A streaming decryption implementation may
produce up to that prefix before detecting the error. It must not produce any
message bytes beyond the prefix, it must eventually return an error, and it
must keep returning an error (rather than e.g. a clean end-of-message
signal) if reads continue.

### Random access decryption

If random access (seeking) decryption is supported, the same vectors should be
applied through that interface: reading the whole message must succeed for
`valid` vectors and fail for `invalid` ones. Note that reading *only a range
covered by validly encrypted chunks* of an `invalid` vector may legitimately
succeed, like for streaming decryption.

Authenticating the message length by decrypting the final chunk (e.g. to seek
relative to the end of the message) must succeed for `valid` vectors and fail
for `invalid` ones, except those with the `ValidFinalChunk` flag: their final
chunk is validly encrypted at the correct index (the error is elsewhere in
the ciphertext), so length authentication may succeed.

### Raw mode

Vectors without the `HeaderFailure` flag can also be applied to
a raw mode implementation: remove the 56-byte header (the 24-byte salt and
the 32-byte commitment) from the beginning of the ciphertext, and decrypt it
with `aeadKey` and `baseNonce` directly.

### Encryption

Encryption uses a random salt, so its output can't be compared directly
against the vectors. It can be tested in one of the following ways:

1. Raw mode encryption is deterministic: decrypt a `valid` vector to recover
   the message, re-encrypt it with `aeadKey` and `baseNonce`, and check the
   result matches the ciphertext without its 56-byte header.
2. If the implementation exposes a way to inject the salt (the first 24 bytes
   of the ciphertext), re-encrypt the message of a `valid` vector with `key`,
   `ctx`, and the salt, and check the result matches `ct` entirely.
3. Otherwise, round-trip: encrypt the message of a `valid` vector and check
   that it decrypts correctly.

[c2sp.org/chunked-encryption]: https://c2sp.org/chunked-encryption
