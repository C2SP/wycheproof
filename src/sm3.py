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
import hmac_impl

# type hints
uint32 = int

BLOCK_SIZE = 64
DIGEST_SIZE = 32

def rotate_left32(x: uint32, n: int) -> uint32:
  return ((x << n) | (x >> (32 - n))) & 0xffffffff

def T(j):
  if 0 <= j <= 15:
    return 0x79cc4519
  elif 16 <= j <= 63:
    return 0x7a879d8a
  else:
   raise ValueError("Invalid j")

def FF(j, x, y, z):
  if 0 <= j <= 15:
    return x^y^z
  elif 16 <= j <= 63:
    return (x & y) | (x & z) | (y & z)

def GG(j, x, y, z):
  if 0 <= j <= 15:
    return x^y^z
  elif 16 <= j <= 63:
    return (x & y) | (~x & z)


def P0(x: uint32) -> uint32:
  return x ^ rotate_left32(x, 9) ^ rotate_left32(x, 17)
  
def P1(x: uint32) -> uint32:
  return x ^ rotate_left32(x, 15) ^ rotate_left32(x, 23)

def pad(m: bytes):
  size = len(m) * 8
  k = (55 - len(m)) % 64
  assert (len(m) + 1 + k) % 64 == 56
  return m + bytes([128]) + bytes(k) + size.to_bytes(8, "big")

def ME(block: bytes):
  W = list(struct.unpack(">16I", block))
  for i in range(16, 68):
    w = P1(W[-16] ^ W[-9] ^ rotate_left32(W[-3], 15) ) ^ rotate_left32(W[-13], 7) ^ W[-6]
    # print(i, hex(w))
    W.append(w)
  Wp = [W[i] ^ W[i+4] for i in range(64)]
  return W, Wp

def CF(v, w, wp):
  a,b,c,d,e,f,g,h = v
  for j in range(64):
    tmp = (rotate_left32(a, 12) + e + rotate_left32(T(j), j % 32)) & 0xffffffff
    ss1 = rotate_left32(tmp, 7)
    ss2 = ss1 ^ rotate_left32(a, 12)
    tt1 = (FF(j, a, b, c) + d + ss2 + wp[j]) &0xffffffff
    tt2 = (GG(j, e, f, g) + h + ss1 + w[j]) &0xffffffff
    d = c
    c = rotate_left32(b, 9)
    b = a
    a = tt1
    h = g
    g = rotate_left32(f, 19)
    f = e
    e = P0(tt2)
  return [x ^ y for x, y in zip([a,b,c,d,e,f,g,h], v)]

def Sm3(m: bytes):
  padded = pad(m)
  IV = bytes.fromhex("7380166f4914b2b9172442d7da8a0600"
                     "a96f30bc163138aae38dee4db0fb0e4e")
  v = struct.unpack(">8I", IV)
  for i in range(0, len(padded), 64):
    block = padded[i:i+64]
    w, wp = ME(block)
    v = CF(v, w, wp)
  return struct.pack(">8I", *v)

# https://datatracker.ietf.org/doc/html/draft-oscca-cfrg-sm3-02
HmacSm3 = hmac_impl.Hmac(Sm3,
                         block_size=BLOCK_SIZE,
                         digest_size=DIGEST_SIZE,
                         name="HMACSM3",
                         oid="1.2.156.10197.1.401.2")

def main():
  print(Sm3(b"abc").hex())
  print(Sm3(bytes(range(0x61, 0x65))*16).hex())
  
if __name__ == "__main__":
  main()

