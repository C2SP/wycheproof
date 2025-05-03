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

h = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
     0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]

k = [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
     0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
     0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
     0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
     0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
     0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
     0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
     0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]

def RotateRight(v: int, n: int) -> int:
   w = (v >> n) | (v << (32 - n))
   return w & 0xffffffff

def Compression(state: list[int], w: list[int]) -> list[int]:
  a, b, c, d, e, f, g, h = state
  for i in range(64):
    s1 = RotateRight(e, 6) ^ RotateRight(e, 11) ^ RotateRight(e, 25)
    ch = (e & f) ^ (~e & g)
    tmp1 = (h + s1 + ch + k[i] + w[i]) & 0xffffffff
    s0 = RotateRight(a, 2) ^ RotateRight(a, 13) ^ RotateRight(a, 22)
    maj = (a & b) ^ (a & c) ^ (b & c)
    tmp2 = (tmp1 + s0 + maj) & 0xffffffff
    tmp3 = (d + tmp1) & 0xffffffff
    a, b, c, d, e, f, g, h = tmp2, a, b, c, tmp3, e, f, g
  return (a, b, c, d, e, f, g, h)

def computeW(m: bytes) -> list[int]:
  w = list(struct.unpack(">16L", m))
  for i in range(16, 64):
    a, b = w[-15], w[-2]
    s0 = RotateRight(a, 7) ^ RotateRight(a, 18) ^ (a >> 3)
    s1 = RotateRight(b, 17) ^ RotateRight(b, 19) ^ (b >> 10)
    s = (w[-16] + w[-7] + s0 + s1) & 0xffffffff
    w.append(s)
  return w

def Padding(m: bytes):
   lm = len(m)
   lpad = struct.pack(">Q", 8 * lm)
   lenz = -(lm + 9) % 64
   return m + bytes([0x80]) + bytes(lenz) + lpad

def Sha256(m: bytes, skip_last=False)-> bytes:
   mpad = Padding(m)
   state = h
   size = len(mpad)
   if skip_last:
     size -= 64
   for i in range(0, size, 64):
     m = mpad[i: i+64]
     w = computeW(m)
     s = Compression(state, w)
     state = [(x + y) & 0xffffffff for x, y in zip(state, s)]
   return struct.pack(">8L", *state)


def test():
  tc = [
    (b"", 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'),
    (b"Test", '532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25'), 
    (b"123" * 12345,'63f75b752397905ff04c179242d8af27d680f905de886cbe63d24ea813907cc9')

    # (b"123"*2**20, 'd764dfb752d4b2f2f19d7fc646529bd1e067d68fda171e836fa5038a80eb09f2')
  ]
  for v, r in tc:
    assert Sha256(v).hex() == r
   
if __name__ == "__main__":
  test()

