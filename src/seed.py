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

import struct
import util

# type hints:
uint64 = util.Uint64
uint32 = util.Uint32

S0 = bytes.fromhex(
  "A9 85 D6 D3 54 1D AC 25 5D 43 18 1E 51 FC CA 63 28"
  "44 20 9D E0 E2 C8 17 A5 8F 03 7B BB 13 D2 EE 70 8C"
  "3F A8 32 DD F6 74 EC 95 0B 57 5C 5B BD 01 24 1C 73"
  "98 10 CC F2 D9 2C E7 72 83 9B D1 86 C9 60 50 A3 EB"
  "0D B6 9E 4F B7 5A C6 78 A6 12 AF D5 61 C3 B4 41 52"
  "7D 8D 08 1F 99 00 19 04 53 F7 E1 FD 76 2F 27 B0 8B"
  "0E AB A2 6E 93 4D 69 7C 09 0A BF EF F3 C5 87 14 FE"
  "64 DE 2E 4B 1A 06 21 6B 66 02 F5 92 8A 0C B3 7E D0"
  "7A 47 96 E5 26 80 AD DF A1 30 37 AE 36 15 22 38 F4"
  "A7 45 4C 81 E9 84 97 35 CB CE 3C 71 11 C7 89 75 FB"
  "DA F8 94 59 82 C4 FF 49 39 67 C0 CF D7 B8 0F 8E 42"
  "23 91 6C DB A4 34 F1 48 C2 6F 3D 2D 40 BE 3E BC C1"
  "AA BA 4E 55 3B DC 68 7F 9C D8 4A 56 77 A0 ED 46 B5"
  "2B 65 FA E3 B9 B1 9F 5E F9 E6 B2 31 EA 6D 5F E4 F0"
  "CD 88 16 3A 58 D4 62 29 07 33 E8 1B 05 79 90 6A 2A"
  "9A")
S1 = bytes.fromhex(
  "38 E8 2D A6 CF DE B3 B8 AF 60 55 C7 44 6F 6B 5B C3"
  "62 33 B5 29 A0 E2 A7 D3 91 11 06 1C BC 36 4B EF 88"
  "6C A8 17 C4 16 F4 C2 45 E1 D6 3F 3D 8E 98 28 4E F6"
  "3E A5 F9 0D DF D8 2B 66 7A 27 2F F1 72 42 D4 41 C0"
  "73 67 AC 8B F7 AD 80 1F CA 2C AA 34 D2 0B EE E9 5D"
  "94 18 F8 57 AE 08 C5 13 CD 86 B9 FF 7D C1 31 F5 8A"
  "6A B1 D1 20 D7 02 22 04 68 71 07 DB 9D 99 61 BE E6"
  "59 DD 51 90 DC 9A A3 AB D0 81 0F 47 1A E3 EC 8D BF"
  "96 7B 5C A2 A1 63 23 4D C8 9E 9C 3A 0C 2E BA 6E 9F"
  "5A F2 92 F3 49 78 CC 15 FB 70 75 7F 35 10 03 64 6D"
  "C6 74 D5 B4 EA 09 76 19 FE 40 12 E0 BD 05 FA 01 F0"
  "2A 5E A9 56 43 85 14 89 9B B0 E5 48 79 97 FC 1E 82"
  "21 8C 1B 5F 77 54 B2 1D 25 4F 00 46 ED 58 52 EB 7E"
  "DA C9 FD 30 95 65 3C B6 E4 BB 7C 0E 50 39 26 32 84"
  "69 93 37 E7 24 A4 CB 53 0A 87 D9 4C 83 8F CE 3B 4A"
  "B7")


def rotate_left(val: int, n: int, bits: int = 32) -> int:
  res = val << n
  hi, lo = divmod(res, 2**bits)
  return hi | lo


def rotate_right(val: int, n: int, bits: int = 32) -> int:
  return rotate_left(val, bits - n, bits)

MASK32 = 0xffffffff


def F(R: uint64, K: uint64) -> uint64:
  w = R ^ K
  T0, T1 = w >> 32, w & MASK32
  a = G((T0 ^ T1) & MASK32)
  b = G((a + T0) & MASK32)
  c = G((a + b) & MASK32)
  R0p = (c + b) & MASK32
  R1p = c
  return (R0p << 32) | R1p


def G(X: uint32) -> uint32:
  X3, X2, X1, X0 = X.to_bytes(4, "big")
  m0, m1, m2, m3 = 0xfc, 0xf3, 0xcf, 0x3f
  T0 = S0[X0]
  T1 = S1[X1]
  T2 = S0[X2]
  T3 = S1[X3]
  Z0 = (T0 & m0) ^ (T1 & m1) ^ (T2 & m2) ^ (T3 & m3)
  Z1 = (T0 & m1) ^ (T1 & m2) ^ (T2 & m3) ^ (T3 & m0)
  Z2 = (T0 & m2) ^ (T1 & m3) ^ (T2 & m0) ^ (T3 & m1)
  Z3 = (T0 & m3) ^ (T1 & m0) ^ (T2 & m1) ^ (T3 & m2)
  return Z0 + (Z1 << 8) + (Z2 << 16) + (Z3 << 24)

# KC1, KC2, ..., KC16
KC = [ 0x9E3779B9, 0x3C6EF373,
       0x78DDE6E6, 0xF1BBCDCC,
       0xE3779B99, 0xC6EF3733,
       0x8DDE6E67, 0x1BBCDCCF,
       0x3779B99E, 0x6EF3733C,
       0xDDE6E678, 0xBBCDCCF1,
       0x779B99E3, 0xEF3733C6,
       0xDE6E678D, 0xBCDCCF1B]

class Seed:
  key_sizes_in_bytes = (16,)
  block_size_in_bytes = 16

  def __init__(self, key: bytes):
    self.key = key
    self.key_schedule()

  def seed(self, L: uint64, R: uint64, round_keys) -> tuple[uint64, uint64]:
    for rk in round_keys:
      L, R = R, L ^ F(rk, R)
    return R, L

  def key_schedule(self):
    key0, key1, key2, key3 = struct.unpack(">4L", self.key)
    mask32 = 0xffffffff
    self.round_keys = []
    for i, kci in enumerate(KC):
      ki0 = G((key0 + key2 - kci) & mask32)
      ki1 = G((key1 - key3 + kci) & mask32)
      self.round_keys.append((ki0 << 32) | ki1)
      if i % 2 == 0:
        # Type 1 round (note i starts with 1 in the RFC)
        x = (key0 << 32) + key1
        y = rotate_right(x, 8, 64)
        key0 = y >> 32
        key1 = y & mask32
      else:
        # Type 2 round (note i starts with 1 in the RFC)
        x = (key2 << 32) + key3
        y = rotate_left(x, 8, 64)
        key2 = y >> 32
        key3 = y & mask32

  def encrypt_block(self, block: bytes) -> bytes:
    L, R = struct.unpack(">2Q", block)
    L, R = self.seed(L, R, self.round_keys)
    return struct.pack(">2Q", L, R)

  def decrypt_block(self, block: bytes) -> bytes:
    L, R = struct.unpack(">2Q", block)
    L, R = self.seed(L, R, self.round_keys[::-1])
    return struct.pack(">2Q", L, R)
