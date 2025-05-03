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
# RFC 3713

# Type hints:
uint8 = util.Uint8
uint32 = util.Uint32
uint64 = util.Uint64
uint128 = util.Uint128

MASK8 = 0xff
MASK32 = 0xffffffff
MASK64 = 0xffffffffffffffff
MASK128 = 0xffffffffffffffffffffffffffffffff

# Key scheduling part
# Section 2.2 of RFC 3713

"""
   In the key schedule part of Camellia, the 128-bit variables of kl and
   kr are defined as follows.  For 128-bit keys, the 128-bit key K is
   used as kl and kr is 0.  For 192-bit keys, the leftmost 128-bits of
   key K are used as kl and the concatenation of the rightmost 64-bits
   of K and the complement of the rightmost 64-bits of K are used as kr.
   For 256-bit keys, the leftmost 128-bits of key K are used as kl and
   the rightmost 128-bits of K are used as kr.
"""


def rotate_left(n: int, bits: int, size: int) -> int:
  hi, lo = divmod(n << bits, 2**size)
  return hi ^ lo

SBOX1 = [
 112, 130,  44, 236, 179,  39, 192, 229, 228, 133,  87,  53, 234,  12, 174,  65,
  35, 239, 107, 147,  69,  25, 165,  33, 237,  14,  79,  78,  29, 101, 146, 189,
 134, 184, 175, 143, 124, 235,  31, 206,  62,  48, 220,  95,  94, 197,  11,  26,
 166, 225,  57, 202, 213,  71,  93,  61, 217,   1,  90, 214,  81,  86, 108,  77,
 139,  13, 154, 102, 251, 204, 176,  45, 116,  18,  43,  32, 240, 177, 132, 153,
 223,  76, 203, 194,  52, 126, 118,   5, 109, 183, 169,  49, 209,  23,   4, 215,
  20,  88,  58,  97, 222,  27,  17,  28,  50,  15, 156,  22,  83,  24, 242,  34,
 254,  68, 207, 178, 195, 181, 122, 145,  36,   8, 232, 168,  96, 252, 105,  80,
 170, 208, 160, 125, 161, 137,  98, 151,  84,  91,  30, 149, 224, 255, 100, 210,
  16, 196,   0,  72, 163, 247, 117, 219, 138,   3, 230, 218,   9,  63, 221, 148,
 135,  92, 131,   2, 205,  74, 144,  51, 115, 103, 246, 243, 157, 127, 191, 226,
  82, 155, 216,  38, 200,  55, 198,  59, 129, 150, 111,  75,  19, 190,  99,  46,
 233, 121, 167, 140, 159, 110, 188, 142,  41, 245, 249, 182,  47, 253, 180,  89,
 120, 152,   6, 106, 231,  70, 113, 186, 212,  37, 171,  66, 136, 162, 141, 250,
 114,   7, 185,  85, 248, 238, 172,  10,  54,  73,  42, 104,  60,  56, 241, 164,
  64,  40, 211, 123, 187, 201,  67, 193,  21, 227, 173, 244, 119, 199, 128, 158]

SBOX2 = [rotate_left(x, 1, 8) for x in SBOX1]
SBOX3 = [rotate_left(x, 7, 8) for x in SBOX1]
SBOX4 = [SBOX1[rotate_left(x, 1, 8)] for x in range(256)]


def f(f_in: uint64, ke: uint64) -> uint64:
  x = f_in ^ ke
  t1 =  x >> 56
  t2 = (x >> 48) & MASK8
  t3 = (x >> 40) & MASK8
  t4 = (x >> 32) & MASK8
  t5 = (x >> 24) & MASK8
  t6 = (x >> 16) & MASK8
  t7 = (x >>  8) & MASK8
  t8 =  x        & MASK8
  t1 = SBOX1[t1]
  t2 = SBOX2[t2]
  t3 = SBOX3[t3]
  t4 = SBOX4[t4]
  t5 = SBOX2[t5]
  t6 = SBOX3[t6]
  t7 = SBOX4[t7]
  t8 = SBOX1[t8]
  y1 = t1 ^ t3 ^ t4 ^ t6 ^ t7 ^ t8
  y2 = t1 ^ t2 ^ t4 ^ t5 ^ t7 ^ t8
  y3 = t1 ^ t2 ^ t3 ^ t5 ^ t6 ^ t8
  y4 = t2 ^ t3 ^ t4 ^ t5 ^ t6 ^ t7
  y5 = t1 ^ t2 ^ t6 ^ t7 ^ t8
  y6 = t2 ^ t3 ^ t5 ^ t7 ^ t8
  y7 = t3 ^ t4 ^ t5 ^ t6 ^ t8
  y8 = t1 ^ t4 ^ t5 ^ t6 ^ t7
  return ((y1 << 56) | (y2 << 48) | (y3 << 40) | (y4 << 32)
       | (y5 << 24) | (y6 << 16) | (y7 <<  8) | y8)


def fl(x: uint64, ke: uint64) -> uint64:
  x1 = x >> 32
  x2 = x & MASK32
  k1 = ke >> 32
  k2 = ke & MASK32
  x2 = x2 ^ rotate_left(x1 & k1, 1, 32)
  x1 = x1 ^ (x2 | k2)
  return (x1 << 32) | x2


def fl_inv(y: uint64, ke: uint64) -> uint64:
  y1 = y >> 32
  y2 = y & MASK32
  k1 = ke >> 32
  k2 = ke & MASK32
  y1 = y1 ^ (y2 | k2)
  y2 = y2 ^ rotate_left(y1 & k1, 1, 32)
  return (y1 << 32) | y2

class Camellia:
  key_sizes_in_bytes = (16, 24, 32)
  block_size_in_bytes = 16

  def __init__(self, key: bytes):
    self.key = key
    self.key_schedule(key)

  def key_schedule(self, key: bytes):
    k = int.from_bytes(key, "big")
    if len(key) == 16:
      kl = k
      kr = 0
    elif len(key) == 24:
      kl = k >> 64
      kr = ((k & MASK64) << 64) | (~k & MASK64)
    elif len(key) == 32:
      kl = k >> 128
      kr = k & MASK128
    else:
      raise ValueError("Invalid key size")

    sigma1 = 0xA09E667F3BCC908B
    sigma2 = 0xB67AE8584CAA73B2
    sigma3 = 0xC6EF372FE94F82BE
    sigma4 = 0x54FF53A5F1D36F1C
    sigma5 = 0x10E527FADE682D1D
    sigma6 = 0xB05688C2B3E6C1FD

    d1 = (kl ^ kr) >> 64
    d2 = (kl ^ kr) & MASK64
    d2 = d2 ^ f(d1, sigma1)
    d1 = d1 ^ f(d2, sigma2)
    d1 = d1 ^ (kl >> 64)
    d2 = d2 ^ (kl & MASK64)
    d2 = d2 ^ f(d1, sigma3)
    d1 = d1 ^ f(d2, sigma4)
    ka = (d1 << 64) | d2
    d1 = (ka ^ kr) >> 64
    d2 = (ka ^ kr) & MASK64
    d2 = d2 ^ f(d1, sigma5)
    d1 = d1 ^ f(d2, sigma6)
    kb = (d1 << 64) | d2

    def sp(k: uint128, n: int):
      tmp = rotate_left(k, n, 128)
      return tmp >> 64, tmp & MASK64

    if len(key) == 16:
      self.kw1, self.kw2 = sp(kl, 0)
      self.k1, self.k2 = sp(ka, 0)
      self.k3, self.k4 = sp(kl, 15)
      self.k5, self.k6 = sp(ka, 15)
      self.ke1, self.ke2 = sp(ka, 30)
      self.k7, self.k8 = sp(kl, 45)
      self.k9, _ = sp(ka, 45)
      _, self.k10 = sp(kl, 60)
      self.k11, self.k12 = sp(ka, 60)
      self.ke3, self.ke4 = sp(kl, 77)
      self.k13, self.k14 = sp(kl, 94)
      self.k15, self.k16 = sp(ka, 94)
      self.k17, self.k18 = sp(kl, 111)
      self.kw3, self.kw4 = sp(ka, 111)
    elif len(key) in (24, 32):
      self.kw1, self.kw2 = sp(kl, 0)
      self.k1, self.k2 = sp(kb, 0)
      self.k3, self.k4 = sp(kr, 15)
      self.k5, self.k6 = sp(ka, 15)
      self.ke1, self.ke2 = sp(kr, 30)
      self.k7, self.k8 = sp(kb, 30)
      self.k9, self.k10 = sp(kl, 45)
      self.k11, self.k12 = sp(ka, 45)
      self.ke3, self.ke4 = sp(kl, 60)
      self.k13, self.k14 = sp(kr, 60)
      self.k15, self.k16 = sp(kb, 60)
      self.k17, self.k18 = sp(kl, 77)
      self.ke5, self.ke6 = sp(ka, 77)
      self.k19, self.k20 = sp(kr, 94)
      self.k21, self.k22 = sp(ka, 94)
      self.k23, self.k24 = sp(kl, 111)
      self.kw3, self.kw4 = sp(kb, 111)

  def encrypt_block(self, block: bytes) -> bytes:
    m = int.from_bytes(block, "big")
    if len(self.key) == 16:
      d1 = m >> 64
      d2 = m & MASK64
      d1 = d1 ^ self.kw1
      d2 = d2 ^ self.kw2
      d2 = d2 ^ f(d1, self.k1)
      d1 = d1 ^ f(d2, self.k2)
      d2 = d2 ^ f(d1, self.k3)
      d1 = d1 ^ f(d2, self.k4)
      d2 = d2 ^ f(d1, self.k5)
      d1 = d1 ^ f(d2, self.k6)
      d1 = fl(d1, self.ke1)
      d2 = fl_inv(d2, self.ke2)
      d2 = d2 ^ f(d1, self.k7)
      d1 = d1 ^ f(d2, self.k8)
      d2 = d2 ^ f(d1, self.k9)
      d1 = d1 ^ f(d2, self.k10)
      d2 = d2 ^ f(d1, self.k11)
      d1 = d1 ^ f(d2, self.k12)
      d1 = fl(d1, self.ke3)
      d2 = fl_inv(d2, self.ke4)
      d2 = d2 ^ f(d1, self.k13)
      d1 = d1 ^ f(d2, self.k14)
      d2 = d2 ^ f(d1, self.k15)
      d1 = d1 ^ f(d2, self.k16)
      d2 = d2 ^ f(d1, self.k17)
      d1 = d1 ^ f(d2, self.k18)
      d2 = d2 ^ self.kw3
      d1 = d1 ^ self.kw4
      c = (d2 << 64) | d1
      return c.to_bytes(16, "big")
    elif len(self.key) in (24, 32):
      d1 = m >> 64
      d2 = m & MASK64
      d1 = d1 ^ self.kw1
      d2 = d2 ^ self.kw2
      d2 = d2 ^ f(d1, self.k1)
      d1 = d1 ^ f(d2, self.k2)
      d2 = d2 ^ f(d1, self.k3)
      d1 = d1 ^ f(d2, self.k4)
      d2 = d2 ^ f(d1, self.k5)
      d1 = d1 ^ f(d2, self.k6)
      d1 = fl(d1, self.ke1)
      d2 = fl_inv(d2, self.ke2)
      d2 = d2 ^ f(d1, self.k7)
      d1 = d1 ^ f(d2, self.k8)
      d2 = d2 ^ f(d1, self.k9)
      d1 = d1 ^ f(d2, self.k10)
      d2 = d2 ^ f(d1, self.k11)
      d1 = d1 ^ f(d2, self.k12)
      d1 = fl(d1, self.ke3)
      d2 = fl_inv(d2, self.ke4)
      d2 = d2 ^ f(d1, self.k13)
      d1 = d1 ^ f(d2, self.k14)
      d2 = d2 ^ f(d1, self.k15)
      d1 = d1 ^ f(d2, self.k16)
      d2 = d2 ^ f(d1, self.k17)
      d1 = d1 ^ f(d2, self.k18)
      d1 = fl(d1, self.ke5)
      d2 = fl_inv(d2, self.ke6)
      d2 = d2 ^ f(d1, self.k19)
      d1 = d1 ^ f(d2, self.k20)
      d2 = d2 ^ f(d1, self.k21)
      d1 = d1 ^ f(d2, self.k22)
      d2 = d2 ^ f(d1, self.k23)
      d1 = d1 ^ f(d2, self.k24)
      d2 = d2 ^ self.kw3
      d1 = d1 ^ self.kw4
      c = (d2 << 64) | d1
      return c.to_bytes(16, "big")

  def decrypt_block(self, block: bytes) -> bytes:
    c = int.from_bytes(block, "big")
    if len(self.key) == 16:
      d1 = c >> 64
      d2 = c & MASK64
      d1 = d1 ^ self.kw3
      d2 = d2 ^ self.kw4
      d2 = d2 ^ f(d1, self.k18)
      d1 = d1 ^ f(d2, self.k17)
      d2 = d2 ^ f(d1, self.k16)
      d1 = d1 ^ f(d2, self.k15)
      d2 = d2 ^ f(d1, self.k14)
      d1 = d1 ^ f(d2, self.k13)
      d1 = fl(d1, self.ke4)
      d2 = fl_inv(d2, self.ke3)
      d2 = d2 ^ f(d1, self.k12)
      d1 = d1 ^ f(d2, self.k11)
      d2 = d2 ^ f(d1, self.k10)
      d1 = d1 ^ f(d2, self.k9)
      d2 = d2 ^ f(d1, self.k8)
      d1 = d1 ^ f(d2, self.k7)
      d1 = fl(d1, self.ke2)
      d2 = fl_inv(d2, self.ke1)
      d2 = d2 ^ f(d1, self.k6)
      d1 = d1 ^ f(d2, self.k5)
      d2 = d2 ^ f(d1, self.k4)
      d1 = d1 ^ f(d2, self.k3)
      d2 = d2 ^ f(d1, self.k2)
      d1 = d1 ^ f(d2, self.k1)
      d2 = d2 ^ self.kw1
      d1 = d1 ^ self.kw2
      p = (d2 << 64) | d1
      return p.to_bytes(16, "big")
    elif len(self.key) in (24, 32):
      d1 = c >> 64
      d2 = c & MASK64
      d1 = d1 ^ self.kw3
      d2 = d2 ^ self.kw4
      d2 = d2 ^ f(d1, self.k24)
      d1 = d1 ^ f(d2, self.k23)
      d2 = d2 ^ f(d1, self.k22)
      d1 = d1 ^ f(d2, self.k21)
      d2 = d2 ^ f(d1, self.k20)
      d1 = d1 ^ f(d2, self.k19)
      d1 = fl(d1, self.ke6)
      d2 = fl_inv(d2, self.ke5)
      d2 = d2 ^ f(d1, self.k18)
      d1 = d1 ^ f(d2, self.k17)
      d2 = d2 ^ f(d1, self.k16)
      d1 = d1 ^ f(d2, self.k15)
      d2 = d2 ^ f(d1, self.k14)
      d1 = d1 ^ f(d2, self.k13)
      d1 = fl(d1, self.ke4)
      d2 = fl_inv(d2, self.ke3)
      d2 = d2 ^ f(d1, self.k12)
      d1 = d1 ^ f(d2, self.k11)
      d2 = d2 ^ f(d1, self.k10)
      d1 = d1 ^ f(d2, self.k9)
      d2 = d2 ^ f(d1, self.k8)
      d1 = d1 ^ f(d2, self.k7)
      d1 = fl(d1, self.ke2)
      d2 = fl_inv(d2, self.ke1)
      d2 = d2 ^ f(d1, self.k6)
      d1 = d1 ^ f(d2, self.k5)
      d2 = d2 ^ f(d1, self.k4)
      d1 = d1 ^ f(d2, self.k3)
      d2 = d2 ^ f(d1, self.k2)
      d1 = d1 ^ f(d2, self.k1)
      d2 = d2 ^ self.kw1
      d1 = d1 ^ self.kw2
      p = (d2 << 64) | d1
      return p.to_bytes(16, "big")
