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

# This is an experimental implementation of GCM.
# The implementation is slow, it doesn't check for invalid input and hence
# must not be used for actual encryption.
#
# I'm using this implemementation for example to generate IVs so that
# the CTR has given values.

import gf


def _inv_byte(b: int) -> int:
  res = 0
  for i in range(8):
    res = 2 * res + b % 2
    b //= 2
  return res


INVERSE_TAB = bytes(_inv_byte(i) for i in range(256))

def bytes2gf(ba:bytes) -> gf.F128:
  """Returns a element of GF(2)[x]/(x^128+x^7+x^2+x+1) where bytes

     are the coefficient of the element in little endian order.
     The most significant bit of the first byte is the coefficient of x^0.
  """
  return gf.F128(int.from_bytes(ba.translate(INVERSE_TAB), "little"))

def gf2bytes(p:gf.F128) -> bytes:
  """Converts an element of GF(2^128) into bytes using little endian order

     both for the bits and the bytes.
  """
  return p.poly.to_bytes(16, "little").translate(INVERSE_TAB)

class Ghash:
  def __init__(self, h: gf.F128):
    self.h = h

  def hash_padded(self, b: bytes) -> bytes:
    """Computes the Ghash of a padded byte array.

    Args:
      b: the padded byte array. Its length must be a multiple of 16

    Returns:
      The Ghash of b.
    """
    if len(b) % 16 != 0:
      raise ValueError("input for Ghash must be a multiple of 16")
    res = gf.F128(0)
    for i in range(0, len(b), 16):
      el = bytes2gf(b[i:i+16])
      res = (res + el) * self.h
    return gf2bytes(res)

  def __call__(self, a: bytes, c: bytes) -> bytes:
    """Computes the Ghash of a and c.

    Args:
      a: a byte array of arbitrary length
      b: a byte array of arbitrary length

    Returns:
      the Ghash of a and b.
    """
    last = (len(a) * 8).to_bytes(8, "big") + (len(c) * 8).to_bytes(8, "big")
    pad_a = bytes(-len(a) % 16)
    pad_c = bytes(-len(c) % 16)
    return self.hash_padded(a + pad_a + c + pad_c + last)

class Gcm:
  """Base class for GCM.

  Subclasses of this class must specify block_cipher. This must be a block
  cipher with a 128-bit block. E.g.,

  class AesGcm(gcm.Gcm):
    name = "AES-GCM"
    block_cipher = aes.AES
    # OIDs for key sizes in bits (RFC 5084)
    oids = {
      128: "2.16.840.1.101.3.4.1.6",
      192: "2.16.840.1.101.3.4.1.26",
      256: "2.16.840.1.101.3.4.1.46"}

  name and oids are additional information that is used for test vector
  generation.
  """
  block_cipher = None

  def __init__(self, key: bytes, tagsize: int = 16):
    if self.block_cipher is None:
      raise ValueError("block_cipher is None. Use subclass instead")
    if self.block_cipher.block_size_in_bytes != 16:
      raise ValueError("Not implemented for block sizes other than 16 bytes")
    self.key = key
    # a block cipher for the key
    self.E = self.block_cipher(key)
    zero = bytes(16)
    h = bytes2gf(self.E.encrypt_block(zero))
    self.ghash = Ghash(h)
    assert 1 <= tagsize <= 16
    self.tagsize = tagsize

  def get_j0(self, iv: bytes) -> bytes:
    """Returns the initial counter value J0.

    This value is used to compute the tag. The keystream used for the encryption
    is J0 + 1, J0 + 2, ... (where the addition wraps around at the 32 bit
    boundary.)

    Args:
      iv: the initialization vector

    Returns:
      the value J0.
    """
    if len(iv) == 12:
      return iv + bytes([0,0,0,1])
    res = self.ghash(b"", iv)
    return res

  def inc_ctr(self, ctr: bytes, increment: int = 1) -> bytes:
    """Increments a counter value.

    GCM only increments the least significant 32 bits. I.e., it reduces these 32
    bits modulo 2**32. When encrypting with a 12 byte IV no such wrap-around can
    occur. However, when encrypting with IVs of different size, then J0 can take
    any value.

    Args:
      ctr: the counter value
      increment: the increment

    Returns:
      The incremented counter
    """
    assert len(ctr) == 16
    prefix = ctr[:12]
    postfix = ctr[12:]
    c = int.from_bytes(postfix, "big")
    incc = (c + increment) % 2**32
    res = prefix + incc.to_bytes(4, "big")
    return res

  def xor(self, a: bytes, b: bytes) -> bytes:
    """Xors two arrays.

    Args:
      a: the first array
      b: the second array

    Returns:
      the xored bytes. The length of the result is the minimum
      of the length of a and the length of b.
    """
    return bytes(x ^ y for x, y in zip(a, b))

  def gctr(self, j0: bytes, b: bytes) -> bytes:
    """Encrypts or decrypts a byte array.

    Args:
      j0: the initial counter
      b: the bytes to encrypt or decrypt.

    Returns:
      the encrypted or decrypted bytes.
    """
    res = bytearray()
    ctr = j0
    for i in range(0, len(b), 16):
      ctr = self.inc_ctr(ctr)
      res += self.xor(self.E.encrypt_block(ctr), b[i:i+16])
    return bytes(res)

  def get_tag(self, a: bytes, c: bytes, j0: bytes) -> bytes:
    """Computes the tag.

    Args:
      a: the additional data.
      c: the raw ciphertext
      j0: the initial counter value

    Returns:
      the tag
    """
    S = self.ghash(a, c)
    return self.xor(self.E.encrypt_block(j0), S)[:self.tagsize]

  def getIvForCounter(self, j0: bytes) -> bytes:
    """Returns a 16 byte iv such that get_j0(iv) == j0.

    This function is used to generate test vectors where j0 has a preferred
    value.
    E.g., this function is used to genrate test vectors where the counter values
    wraps at the 2**32 boundary.
    """
    g = bytes2gf(j0)
    iv_len = 128
    l = bytes2gf(iv_len.to_bytes(16, "big"))
    inv = self.ghash.h.inverse()
    iv = (g * inv + l) * inv
    res = gf2bytes(iv)
    # Verify the result
    assert self.get_j0(res) == j0
    return res

  def encrypt(self, iv: bytes, a: bytes, p: bytes) -> tuple[bytes, bytes]:
    """Encrypts a plaintext.

    Args:
      iv: the IV
      a: the additional data
      p: the plaintext

    Returns:
      the ciphertext and the tag.
    """
    j0 = self.get_j0(iv)
    c = self.gctr(j0, p)
    tag = self.get_tag(a, c, j0)
    return c, tag

  def decrypt(self, iv: bytes, a: bytes, c: bytes, t: bytes) -> bytes:
    """Decrypts a ciphertext.

    Args:
      iv: the IV
      a: the additional data
      c: the raw ciphertext (i.e. without tag)
      t: the tag

    Returns:
      the plaintext
    """
    j0 = self.get_j0(iv)
    tag = self.get_tag(a, c, j0)
    if t != tag:
      raise Exception("Invalid tag")
    return self.gctr(j0, c)

  def raw_decrypt(self, iv: bytes, a: bytes, c: bytes) -> tuple[bytes, bytes]:
    """Raw decryption, without tag verification.

    This function is used to generate special case test vectors.
    By choosing the ciphertext it is possible to generate edge cases for the
    computation of the Ghash.

    Args:
      iv: the IV
      a: the additional data
      c: the raw ciphertext
    Returns: a tuple (plaintext, tag) such that the encryption of the plaintext
      with additional data a and iv results in ciphertext c and tag.
    """
    j0 = self.get_j0(iv)
    tag = self.get_tag(a, c, j0)
    return self.gctr(j0, c), tag

  def get_pt_ct_for_iv_and_tag(self, iv: bytes, tag: bytes) -> bytes:
    """Returns a plaintext and corresponding ciphertext for given iv and tag.

    This function assumes that the additional data is empty.
    Args:
      iv: the IV
      tag: the targeted tag

    Returns:
      a tuple pt, ct, such that (ct, tag) == A.encrypt(iv, b"", pt)
    """
    j0 = self.get_j0(iv)
    b = bytes2gf((128).to_bytes(16, "big"))
    # solve C * H^2 + b * H + E(j0) == tag
    s = self.xor(tag, self.E.encrypt_block(j0))
    hinv = self.ghash.h.inverse()
    c = (bytes2gf(s) * hinv + b) * hinv
    ct = gf2bytes(c)
    pt = self.xor(ct, self.E.encrypt_block(self.inc_ctr(j0)))
    return pt, ct
