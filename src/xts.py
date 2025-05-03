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

import util

# Implements XTS:
# https://en.wikipedia.org/wiki/Disk_encryption_theory#XTS
# XTS is based on XEX
# Efficient Instantiations of Tweakable Blockciphers and
# Refinements to Modes OCB and PMAC
# Phillip Rogaway
# https://www.cs.ucdavis.edu/~rogaway/papers/offsets.pdf

# Variants:
# BestCrypt uses XTS with AES, Camellia, Twofish, RC6 and Serpent
# Aria and Seed can also be found in some libraries.
# Speck-XTS is used in some cases.
# I'm implementing these classes if there are OIDs or test vectors.

# Security:
# The XEX construction is CCA secure (Rogaway). I.e. a chosen
# message/ciphertext attack cannot distinguish the encryption of 16
# byte blocks from a random permutation.
# Under the assumption that IVs are not reused XTS should therefore
# be IND-CPA secure. However, this assumption is typically violated
# when XTS is used for disc encryption, where often the sector is
# used as an IV. When the same sector is encrypted multiple times
# (with the same IV) then it is possible to detect if individual
# 16-byte blocks have changed.

# type hints
uint128 = int  # 128-bit unsigned integer


def xor(a: bytes, b: bytes) -> bytes:
  """Xors two byte arrays of the same size.

  Args:
    a: the first byte array
    b: the second byte array

  Returns:
    the xored byte arrays.
  """
  if len(a) != len(b):
    raise ValueError("arguments must have the same length")
  return bytes(x ^ y for x, y in zip(a, b))


class Xts:
  """The XTS encryption mode.

  The XTS encryption mode is an encryption mode that was designed for
  encrypting data on a storage device. One of the design principles was
  that the plaintext and ciphertext are equally long. As a consequence
  this encryption modes does not include any authentication. Additionally,
  blocks are encrypted individually. The result is an encryption mode
  that is quite weak.

  References:
    IEEE P1619
    NIST SP 800-38e
  """
  block_cipher = None

  def __init__(self, key: bytes):
    """Constructs a new cipher

    Args:
      key: the key. XTS only supports 128-bit keys
    """
    if self.block_cipher is None:
      raise ValueError("block_cipher is None. Use subclass instead")
    if self.block_cipher.block_size_in_bytes != 16:
      raise ValueError("Not implemented for block sizes other than 16 bytes")
    key_size = len(key) // 2
    self.key1 = key[:key_size]
    self.key2 = key[key_size:]
    self.cipher1 = self.block_cipher(self.key1)
    self.cipher2 = self.block_cipher(self.key2)

  def mulx(self, block: bytes) -> bytes:
    """Interprets a block as an element of GF(2^128) and multiplies this by x.

    Args: A block

    Returns:
      the block multiplied by x
    """
    res = bytearray(16)
    res[0] = ((block[0] << 1) & 0xff) ^ (135 * (block[15] >> 7))
    for i in range(1, 16):
      res[i] = ((block[i] << 1) & 0xff) ^ (block[i - 1] >> 7)
    return bytes(res)

  def tweak(self, i: int, j: int) -> bytes:
    """Computes a tweak for i and j.

    Args:
      i: a positive integer
      j: a positive integer

    Returns:
      the tweak
    """
    t1 = i.to_bytes(16, "little")
    t = self.cipher2.encrypt_block(t1)
    for k in range(j):
      t = self.mulx(t)
    return t

  def block_enc(self, p: bytes, i: uint128, j: int) -> bytes:
    """Encrypts a block at position (i, j).

    Args:
      p: the block to encrypt
      i: a positive integer
      j: a positive integer

    Returns:
      the encrypted block
    """
    t = self.tweak(i, j)
    pp = xor(t, p)
    cc = self.cipher1.encrypt_block(pp)
    c = xor(t, cc)
    return c

  def block_dec(self, c: bytes, i: uint128, j: int) -> bytes:
    """Decrypts a block at position (i, j).

    Args:
      c: the block to decrypt
      i: a positive integer
      j: a positive integer

    Returns:
      the decrypted block
    """
    t = self.tweak(i, j)
    cc = xor(t, c)
    pp = self.cipher1.decrypt_block(cc)
    p = xor(t, pp)
    return p

  def encrypt(self, p: bytes, i: uint128) -> bytes:
    """Encrypts a plaintext.

    Args:
      p: the plaintext to encrypt. The size of the plaintext must be at least
        one block.
      i: the tweak

    Returns:
      the encrypted block
    """
    if len(p) < 16:
      raise ValueError("plaintext too short")
    m = len(p) // 16  # number of full blocks
    ct_blocks = [None] * (m + 1)
    for j in range(m):
      pt_block = p[16 * j:16 * (j + 1)]
      ct_blocks[j] = self.block_enc(pt_block, i, j)
    last_block_len = len(p) % 16
    if last_block_len == 0:
      ct_blocks[m] = b""
    else:
      cm1 = ct_blocks[m - 1]
      cp = cm1[last_block_len:]
      last_block = p[16 * m:] + cp
      ct_blocks[m - 1] = self.block_enc(last_block, i, m)
      ct_blocks[m] = cm1[:last_block_len]
    return b"".join(ct_blocks)

  def decrypt(self, c: bytes, i: uint128) -> bytes:
    """Decrypts a ciphertext.

    Args:
      c: the ciphertext to decrypt
      i: the tweak

    Returns:
      the plaintext
    """
    if len(c) < 16:
      raise ValueError("ciphertext too short")
    m = len(c) // 16  # number of full blocks
    pt_blocks = [None] * (m + 1)
    last_block_len = len(c) % 16
    for j in range(m):
      ct_block = c[16 * j:16 * (j + 1)]
      if j == m - 1 and last_block_len > 0:
        pt_blocks[j] = self.block_dec(ct_block, i, m)
      else:
        pt_blocks[j] = self.block_dec(ct_block, i, j)
    if last_block_len == 0:
      pt_blocks[m] = b""
    else:
      cm1 = pt_blocks[m - 1]
      cp = cm1[last_block_len:]
      last_block = c[16 * m:] + cp
      pt_blocks[m - 1] = self.block_dec(last_block, i, m - 1)
      pt_blocks[m] = cm1[:last_block_len]
    return b"".join(pt_blocks)
