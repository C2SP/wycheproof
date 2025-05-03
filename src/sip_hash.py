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

MASK64 = 2**64 - 1


def RotateLeft(x, n):
  return ((x << n) | (x >> (64 - n))) & MASK64


def SipRounds(v0, v1, v2, v3, n):
  for j in range(n):
    v0 = (v0 + v1) & MASK64
    v2 = (v2 + v3) & MASK64
    v1 = RotateLeft(v1, 13)
    v3 = RotateLeft(v3, 16)
    v1 ^= v0
    v3 ^= v2
    v0 = RotateLeft(v0, 32)
    v2 = (v2 + v1) & MASK64
    v0 = (v0 + v3) & MASK64
    v1 = RotateLeft(v1, 17)
    v3 = RotateLeft(v3, 21)
    v1 ^= v2
    v3 ^= v0
    v2 = RotateLeft(v2, 32)
  return v0, v1, v2, v3

class SipHash:
  def __init__(self,
               key: bytes,
               out_len: int = 8,
               c: int = 2,
               d: int = 4):
    if len(key) != 16:
      raise ValueError("key must be 128 bits long")
    if out_len not in (8, 16):
      raise ValueError("out_len must be 8 or 16")
    self.k0 = int.from_bytes(key[0:8], "little")
    self.k1 = int.from_bytes(key[8:16], "little")
    self.c = 2
    self.d = 4
    self.out_len = out_len

  def prf(self, msg: bytes) -> int:
    v0 = self.k0 ^ 0x736f6d6570736575
    v1 = self.k1 ^ 0x646f72616e646f6d
    v2 = self.k0 ^ 0x6c7967656e657261
    v3 = self.k1 ^ 0x7465646279746573
    if self.out_len == 16:
      v1 ^= 0xee
    padlen = 8 - len(msg) % 8
    padded = msg + bytes([0] * (padlen - 1) + [len(msg) % 256])
    for i in range(0, len(padded), 8):
      m = int.from_bytes(padded[i:i+8], "little")
      v3 ^= m
      v0, v1, v2, v3 = SipRounds(v0, v1, v2, v3, self.c)
      v0 ^= m
    if self.out_len == 8:
      v2 ^= 0xff
      v0, v1, v2, v3 = SipRounds(v0, v1, v2, v3, self.d)
      return v0 ^ v1 ^ v2 ^ v3
    elif self.out_len == 16:
      v2 ^= 0xee
      v0, v1, v2, v3 = SipRounds(v0, v1, v2, v3, self.d)
      lo = v0 ^ v1 ^ v2 ^ v3
      v1 ^= 0xdd
      v0, v1, v2, v3 = SipRounds(v0, v1, v2, v3, self.d)
      hi = v0 ^ v1 ^ v2 ^ v3
      return lo + (hi << 64)

