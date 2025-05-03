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

# Implements SM4
# The implementation uses type hints and hence requires at least
# Python 3.5 or higher. Type hints are mainly used for documentation.
#
# Based on https://eprint.iacr.org/2008/329.pdf
# Using test vectors from
# https://tools.ietf.org/html/draft-ribose-cfrg-sm4-10

import struct
import typing
import util

# ===== The plain cipher =====

# Incomplete type declarations.
# The types are just used as annotations.
uint32 = util.Uint32

# Sbox
# A partial description of the Sbox is here:
# http://www.iaeng.org/publication/WCECS2017/WCECS2017_pp21-25.pdf
# In particular, the representation of GF(2^8) is missing.
# Though in the worst case this can be guessed and verified.
S = bytes.fromhex("d6 90 e9 fe cc e1 3d b7 16 b6 14 c2 28 fb 2c 05 "
                  "2b 67 9a 76 2a be 04 c3 aa 44 13 26 49 86 06 99 "
                  "9c 42 50 f4 91 ef 98 7a 33 54 0b 43 ed cf ac 62 "
                  "e4 b3 1c a9 c9 08 e8 95 80 df 94 fa 75 8f 3f a6 "
                  "47 07 a7 fc f3 73 17 ba 83 59 3c 19 e6 85 4f a8 "
                  "68 6b 81 b2 71 64 da 8b f8 eb 0f 4b 70 56 9d 35 "
                  "1e 24 0e 5e 63 58 d1 a2 25 22 7c 3b 01 21 78 87 "
                  "d4 00 46 57 9f d3 27 52 4c 36 02 e7 a0 c4 c8 9e "
                  "ea bf 8a d2 40 c7 38 b5 a3 f7 f2 ce f9 61 15 a1 "
                  "e0 ae 5d a4 9b 34 1a 55 ad 93 32 30 f5 8c b1 e3 "
                  "1d f6 e2 2e 82 66 ca 60 c0 29 23 ab 0d 53 4e 6f "
                  "d5 db 37 45 de fd 8e 2f 03 ff 6a 72 6d 6c 5b 51 "
                  "8d 1b af 92 bb dd bc 7f 11 d9 5c 41 1f 10 5a d8 "
                  "0a c1 31 88 a5 cd 7b bd 2d 74 d0 12 b8 e5 b4 b0 "
                  "89 69 97 4a 0c 96 77 7e 65 b9 f1 09 c5 6e c6 84 "
                  "18 f0 7d ec 3a dc 4d 20 79 ee 5f 3e d7 cb 39 48")

FK = (0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc)

CK = [None] * 32
for i in range(32):
  ba = bytes(7 * i % 256 for i in range(4 * i, 4 * (i + 1)))
  CK[i] = int.from_bytes(ba, byteorder="big", signed=False)

def rotl32(x: uint32, n: int) -> uint32:
  assert 0 <= n < 32
  return ((x << n) | (x >> (32 - n))) & 0xffffffff

def L_ref(b: uint32) -> uint32:
  c = b ^ rotl32(b, 2) ^ rotl32(b, 10) ^ rotl32(b, 18) ^ rotl32(b, 24)
  return c & 0xffffffff

def L(b: uint32) -> uint32:
  """ Computes
  (b ^ rotl32(b, 2) ^ rotl32(b, 10) ^ rotl32(b, 18) ^ rotl32(b, 24)) % 2**32
  """
  c = b ^ (b << 2) ^ (b << 10) ^ (b << 18) ^ (b << 24)
  return (c ^ (c >> 32)) & 0xffffffff

def Lp(b: uint32) -> uint32:
  c = b ^ rotl32(b, 13) ^ rotl32(b, 23)
  return c & 0xffffffff

def tau(a: uint32) -> uint32:
  # byte order is not relevant since the same operation is applied
  # to every byte
  b = struct.pack("I", a)
  c = b.translate(S)
  return struct.unpack("I", c)[0]

def T(a: uint32) -> uint32:
  return L(tau(a))

def Tp(a: uint32) -> uint32:
  return Lp(tau(a))

def F(x0: uint32, x1: uint32, x2: uint32, x3: uint32, rk: uint32) -> uint32:
  return x0 ^ T(x1 ^ x2 ^ x3 ^ rk)


def R(x0: uint32, x1: uint32, x2: uint32, x3: uint32,
      roundkeys: list[uint32]) -> tuple[uint32, uint32, uint32, uint32]:
  for rk in roundkeys:
    x0, x1, x2, x3 = x1, x2, x3, F(x0, x1, x2, x3, rk)
  return x3, x2, x1, x0


def encrypt_block(b: bytes, rk: uint32) -> bytes:
  X = [
      int.from_bytes(b[4 * i:4 * (i + 1)], byteorder="big", signed=False)
      for i in range(4)
  ]
  Y = R(*X, rk)
  return b"".join(x.to_bytes(4, byteorder="big", signed=False) for x in Y)


def decrypt_block(b: bytes, rk: uint32) -> bytes:
  X = [
      int.from_bytes(b[4 * i:4 * (i + 1)], byteorder="big", signed=False)
      for i in range(4)
  ]
  Y = R(*X, rk[::-1])
  return b"".join(x.to_bytes(4, byteorder="big", signed=False) for x in Y)

def round_keys(key: bytes):
  assert len(key) == 16
  MK = [
      int.from_bytes(key[4 * i:4 * (i + 1)], byteorder="big", signed=False)
      for i in range(4)
  ]
  a,b,c,d = [MK[i] ^ FK[i] for i in range(4)]
  rk = []
  for i in range(32):
    a,b,c,d = b,c,d, a ^ Tp(b ^ c ^ d ^ CK[i])
    rk.append(d)
  return rk

class Sm4:
  key_sizes_in_bytes = (16,)
  block_size_in_bytes = 16

  @util.type_check
  def __init__(self, key: bytes):
    if len(key) not in self.key_sizes_in_bytes:
      raise ValueError("invalid key size")
    self.key = key
    self.rk = round_keys(key)

  def encrypt_block(self, block: bytes) -> bytes:
    return encrypt_block(block, self.rk)

  def decrypt_block(self, block: bytes) -> bytes:
    return decrypt_block(block, self.rk)

# ===== Additional stuff for analysis and test vector generation =====

# Asserts that S is a permutation
assert set(S) == set(range(256))
InvS = bytearray(256)
for i,v in enumerate(S):
  InvS[v] = i

def invL(b: uint32) -> uint32:
  r"""
  The inverse of L.
  This function is not used during encryption and decryption
  hence its performance does not need to be optimized.
  L is a linear function with characteristic polynomial x ^ 16 + 1.
  Hence L ^ 16(x) = x.
  Other properties are:
    L ^ 4(x) = rotl32(x, 8)
    L ^ 14(x) = rotl32(x, 8) ^ rotl32(x, 12) ^ rotl32(x, 24)
  >>> invL(L(12345))
  12345
  """
  b = rotl32(b, 8) ^ rotl32(b, 12) ^ rotl32(b, 24)
  return L(b)

def invLp(b: uint32) -> uint32:
  """
  The inverse of Lp.
  This function is not used during encryption and decryption
  hence its performance does not need to be optimized.
  Lp is a linear function with characteristic polynomial x ^ 16 + 1.
  Hence Lp ^ 16(x) = x.
  >>> invLp(Lp(12345))
  12345
  """
  for i in range(15):
    b = Lp(b)
  return b

def invTau(a: uint32) -> uint32:
  """
  The inverse of tau.
  The function is not needed for encryption and decryption, but
  can be helpful for the analysis and test vector generation.
  >>> invTau(tau(12345))
  12345
  """
  b = a.to_bytes(4, byteorder="big")
  c = bytes(InvS[x] for x in b)
  return int.from_bytes(c, byteorder="big")

def invT(a: uint32) -> uint32:
  """
  The inverse of T.
  This function is not needed for encryption and decryption.
  >>> invT(T(1234567890))
  1234567890
  """
  return invTau(invL(a))

def invTp(a: uint32) -> uint32:
  """
  The inverse of Tp.
  This function is not needed for encryption and decryption.
  >>> invTp(Tp(1234567890))
  1234567890
  """
  return invTau(invLp(a))


def key_from_round_keys(v0: uint32, v1: uint32, v2: uint32, v3: uint32,
                        n: int) -> bytes:
  """Returns a key such that the round keys n, n+1, n+2 n+3
     have the values v0, v1, v2 and v3 respectively."""
  for ck in CK[n + 3::-1]:
    v0, v1, v2, v3 = v3 ^ Tp(v0 ^ v1 ^ v2 ^ ck), v0, v1, v2
  return b"".join(
      x.to_bytes(4, byteorder="big", signed=False)
      for x in (v0 ^ FK[0], v1 ^ FK[1], v2 ^ FK[2], v3 ^ FK[3]))


def round_key_from_x(x0: uint32, x1: uint32, x2: uint32, x3: uint32,
                     x4: uint32) -> uint32:
  """Returns a round key such that x4 = F(x0, x1, x2, x3, rk)."""
  t = x0 ^ x4
  invt = invT(t)
  return invt ^ x1 ^ x2 ^ x3


def key_and_block_from_x(X: list[int], n: int) -> bytes:
  """Returns a key k and a block b such that
     X = [x_n ... x_n+7] are 8 values computed during encryption."""
  assert len(X) == 8
  RK = [round_key_from_x(*X[i:i+5]) for i in range(4)]
  key = key_from_round_keys(*RK, n+4)
  rk = round_keys(key)
  Y = R(*X[3::-1], rk[n+3::-1])
  return key, b"".join(x.to_bytes(4, byteorder="big", signed=False) for x in Y)


def gen_test_vectors():
  for val in [0, 0x80, 0xffffff7f, 0xffffffff, 0x80000000,
              0x7fffffff, 0x71717171]:
    for pos in [0, 8, 16, 24]:
      k,b = key_and_block_from_x([val] * 8, pos)
      rk = round_keys(k)
      c = encrypt_block(b, rk)
      yield (k, b, c)

if __name__ == "__main__":
  import doctest
  doctest.testmod()
