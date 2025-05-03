# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# This is an experimental implementation of AES-GCM.
# The implementation is slow, it doesn't check for invalid input and hence
# must not be used for actual encryption.
#
# I'm using this implemementation for example to generate IVs so that
# the CTR has given values.

import aes
import gf
import util
from typing import Optional


# An element of gf.F128siv
# Currently, I can't specify that this an element of gf.F128siv
FsivElem = gf.Element
Block = util.Bytes16


def int2bytes(n: int, cnt: int) -> bytes:
  return n.to_bytes(cnt, "little")


def bytes2int(ba: bytes) -> int:
  return int.from_bytes(ba, "little")


def bytes2gf(ba: bytes) -> FsivElem:
  """Returns a element of GF(2)[x]/(x^128 + x^127 + x^126 + x^121 + 1).

  Args:
    ba: the coefficient of the element in little endian order.
        The least significant bit of the first byte is the coefficient of x^0."""
  n = 0
  for b in ba[::-1]:
    n = n * 256 + b
  return gf.F128siv(n)

def gf2bytes(p: FsivElem) -> bytes:
  """Converts an element of GF(2^128) into bytes using little endian order
     both for the bits and the bytes."""
  poly = p.poly
  res = bytearray(16)
  for i in range(16):
    res[i] = poly % 256
    poly //= 256
  return bytes(res)

invX128 = gf.F128siv(2).inverse()**128
def dot(a, b):
  return a * b * invX128

class AesGcmSiv:
  tagsize = 16
  def __init__(self, key: bytes, tagsize: int = 16):
    assert len(key) in (16, 32)
    assert tagsize == 16
    self.key = key
    self.E = aes.AES(key)

  def polyval_ref(self, h: FsivElem, ba:bytes) -> FsivElem:
    """The function POLYVAL described in Section 3 of RFC 8452.

    This is a reference implementation that is close to the RFC.
    """
    assert len(ba) % 16 == 0
    s = gf.F128siv(0)
    for i in range(0, len(ba), 16):
      x = bytes2gf(ba[i:i+16])
      s = dot(s + x, h)
    return s

  def polyval(self, h: FsivElem, ba: bytes) -> FsivElem:
    """The function POLYVAL described in Section 3 of RFC 8452.

    This implementation is slightly optimized.
    """
    assert len(ba) % 16 == 0
    g = h * invX128
    s = gf.F128siv(0)
    for i in range(0, len(ba), 16):
      x = bytes2gf(ba[i:i+16])
      s = (s + x) * g
    return s

  @util.type_check
  def derive_sub_keys(self, nonce: bytes) -> tuple[FsivElem, aes.AES]:
    if len(nonce) != 12:
      raise ValueError("Nonce of size %d is not valid" % len(nonce))
    L = [self.E.encrypt_block(bytes([i, 0, 0, 0]) + nonce)[:8]
           for i in range(2 + len(self.key) // 8)]
    key = b"".join(L[2:])
    enc = aes.AES(key)
    auth = bytes2gf(L[0] + L[1])
    return auth, enc

  @util.type_check
  def derive_sub_keys_raw(self, nonce: bytes) -> tuple[bytes, bytes]:
    if len(nonce) != 12:
      raise ValueError("Nonce of size %d is not valid" % len(nonce))
    L = [self.E.encrypt_block(bytes([i, 0, 0, 0]) + nonce)[:8]
           for i in range(2 + len(self.key) // 8)]
    enc_key = b"".join(L[2:])
    auth_key = L[0] + L[1]
    return auth_key, enc_key

  def xor(self, a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

  def ctr(self, enc: aes.AES, m: bytes, tag: bytes) -> bytes:
    c0 = bytes2int(tag[:4])
    postfix = tag[4:15] + bytes([tag[15] | 0x80])
    blocks = (m[i:i+16] for i in range(0, len(m), 16))
    ct = (self.xor(block, enc.encrypt_block(int2bytes((c0 + i) % 2**32, 4) + postfix))
          for i,block in enumerate(blocks))
    return b"".join(ct)

  def compute_tag(self, auth:FsivElem, enc:aes.AES, A:bytes, P:bytes, N:bytes) ->bytes:
    lb = int2bytes(8 * len(A), 8) + int2bytes(8 * len(P), 8)
    Ap = A + bytes(-len(A) % 16)
    Pp = P + bytes(-len(P) % 16)
    S = gf2bytes(self.polyval(auth, Ap + Pp + lb))
    taginput = self.xor(S[:12], N) + S[12:15] + bytes([S[15] & 0x7f])
    return enc.encrypt_block(taginput)

  @util.type_check
  def encrypt(self, N:bytes, A:bytes, P:bytes) -> tuple[bytes, bytes]:
    auth, enc = self.derive_sub_keys(N)
    tag = self.compute_tag(auth, enc, A, P, N)
    return self.ctr(enc, P, tag), tag

  @util.type_check
  def decrypt(self, N:bytes, A:bytes, C:bytes, tag:bytes) -> bytes:
    """Decryptes a ciphertext.

    Args:
      N: the nonce
      A: the additional data
      C: the ciphertext
      tag: the tag
    Returns:
      the plaintext if the tag was correct, None otherwise
    """
    assert len(tag) == 16
    auth, enc = self.derive_sub_keys(N)
    pt = self.ctr(enc, C, tag)
    tag2 = compute_tag(auth, enc, A, P, N)
    if tag == tag2:
      return pt

  def find_data_and_ciphertext(self, N:bytes, P:bytes, tag:bytes):
    """Finds A and C such that encrypt(N, A, P) = C, tag.

    This allows for example to generate test vectors that check for counter
    overflows.

    Args:
      N: the nonce
      P: the plaintext
      tag: the tag

    Returns: 
      A tuple A,C or None is no such values exist.
    """
    auth, enc = self.derive_sub_keys(N)
    taginput = enc.decrypt_block(tag)
    if taginput[-1] & 0x80:
      return None
    S = bytes2gf(self.xor(taginput[:12], N) + taginput[12:])
    lb = int2bytes(128, 8) + int2bytes(8 * len(P), 8)
    Pp = P + bytes(-len(P) % 16)
    A0 = bytes(16)
    I0 = A0 + Pp + lb
    S0 = self.polyval(auth, I0)
    m = (auth * invX128).inverse()
    A = gf2bytes((S + S0) * m ** (len(I0)//16))
    C,t = self.encrypt(N, A, P)
    assert t == tag
    return A, C

  def find_data_and_plaintext(self, N: bytes, C: bytes, tag: bytes
      ) -> Optional[tuple[bytes, bytes]]:
    """Finds a block A and a plaintext P such that encrypt(N, A, P) = C, tag.

    This function allows for example to generate test vectors that check for
    counter overflows.

    Args:
      N: the nonce
      C: the ciphertext
      tag: a tag
    Returns:
      A pair (A, P) or None if no such values exist."""
    auth, enc = self.derive_sub_keys(N)
    P = self.ctr(enc, C, tag)
    AC = self.find_data_and_ciphertext(N, P, tag)
    if AC:
      assert AC[1] == C
      return AC[0], P
    else:
      return None

  def find_modified_tag(self, N: bytes, C: bytes, actual_tag: bytes,
                      correct_tag: bytes):
    """Generates test vectors for modified tags.

    Finds a 16 byte data block A and a plaintext P such that
    the decryption of the the ciphertext C, actual_tag and additional data A
    gives plaintext P and correct_tag. This allows to generate test vectors
    that check whether the tags are fully verified.
    Args:
      N: the nonce
      C: the expected ciphertext,
      actual_tag: the tag that is used as SIV and is part of the ciphertext
      correct_tag: the tag that results when computing the tag over aad and
          plaintext.

    Returns: the AAD and the plaintext or None if no such values exist.
    """
    auth, enc = self.derive_sub_keys(N)
    P = self.ctr(enc, C, actual_tag)
    AC = self.find_data_and_ciphertext(N, P, correct_tag)
    if AC:
      return AC[0], P
    else:
      return None

  def modified_plaintext_blocks(self, N: bytes, A: bytes, P: bytes, tag: bytes):
    """Modifies plaintext blocks so that the tag matches.

    This could be used to recover plaintexts when the encryption
    suffered from a bit flip.

    Args:
      N: the nonce
      A: the additional data
      M: the original message
      i: the block to modify
      tag: the desired tag

    Yields:
      tuples i, B, with the property that
      changing block i in M to B gives the desired tag.
    """
    auth, enc = self.derive_sub_keys(N)
    lb = int2bytes(8 * len(A), 8) + int2bytes(8 * len(P), 8)
    A_padded = A + bytes(-len(A) % 16)
    P_padded = P + bytes(-len(P) % 16)
    S = gf2bytes(self.polyval(auth, A_padded + P_padded + lb))
    tag_input = self.xor(S[:12], N) + S[12:15] + bytes([S[15] & 0x7f])
    expected_tag_input = enc.decrypt_block(tag)
    diff1 = self.xor(tag_input, expected_tag_input)
    diff2 = diff1[:15] + bytes([diff1[15] ^ 0x80])
    res = []
    g = auth.inverse() * auth.field([auth.field.degree()])
    diffs = [bytes2gf(diff1), bytes2gf(diff2)]
    # TODO: include truncated last block
    for i in range(len(P) // 16):
      m = g ** (len(P_padded) // 16 - i + 1)
      for d in diffs:
        pt_diff = gf2bytes(d * m)
        yield i, self.xor(pt_diff, P[16*i: 16*(i+1)])

