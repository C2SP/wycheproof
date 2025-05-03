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

IP = [None] * 128
FP = [None] * 128
for i in range(31):
  for j in range(4):
    IP[4 * i + j] = i + 32 * j
    FP[i + 32 * j] = 4 * i + j

# The S-Boxes
S = [
  [3, 8, 15, 1, 10, 6, 5, 11, 14, 13, 4, 2, 7, 0, 9, 12],
  [15, 12, 2, 7, 9, 0, 5, 10, 1, 11, 14, 8, 6, 13, 3, 4],
  [8, 6, 7, 9, 3, 12, 10, 15, 13, 1, 14, 4, 0, 11, 5, 2],
  [0, 15, 11, 8, 12, 9, 6, 3, 13, 1, 2, 4, 10, 7, 5, 14],
  [1, 15, 8, 3, 12, 0, 11, 6, 2, 5, 4, 10, 9, 14, 7, 13],
  [15, 5, 2, 11, 4, 10, 9, 12, 0, 3, 14, 8, 13, 6, 7, 1],
  [7, 2, 12, 5, 8, 4, 6, 11, 14, 9, 1, 15, 13, 3, 10, 0],
  [1, 13, 15, 0, 14, 8, 2, 11, 7, 4, 12, 10, 9, 3, 5, 6]]
  
InvS = [None] * 8
for i, sbox in enumerate(S):
  inv = [None] * 16
  for j, v in enumerate(sbox):
    inv[v] = j
  InvS[i] = inv
  

def rot_left(x, bits):
  return ((x << bits) | (x >> (32 - bits))) & 0xffffffff

def ip(s):
  """Transposes 4 32-bit integers into 32 4-bit integers"""
  assert len(s) == 4
  res = bytearray(32)
  for i in range(32):
    for j in range(4):
      res[i] ^= ((s[j] >> i) & 1) << j
  return tuple(res)
      
def hat(s):
  b = ip(s)
  return ''.join('0123456789abcdef'[x] for x in b[::-1])

def fp(b):
  """Transposes 32 4-bit integers into 4 32-bit integers"""
  assert len(b) == 32
  res = [0] * 4
  for i in range(32):
    for j in range(4):
      res[j] ^= ((b[i] >> j) & 1) << i
  return tuple(res)

def mix(s, k):
  assert len(s) == 4
  assert len(k) == 4
  a, b, c, d = (x ^ y for x, y in zip(s, k))
  print('a', hex(a))
  print('b', hex(b))
  print('c', hex(c))
  print('d', hex(d))
  print('xor', hat((a, b, c, d)))
  a = rot_left(a, 13)
  c = rot_left(c, 3)
  b = a ^ b ^ c
  d = d ^ c ^ (a << 3) & 0xffffffff
  b = rot_left(b, 1)
  d = rot_left(d, 7)
  a = a ^ b ^ d
  c = c ^ d ^ (b << 7) & 0xffffffff
  a = rot_left(a, 5)
  c = rot_left(c, 22)
  return a, b, c, d

def inv_mix(s, k):
  assert len(s) == 4
  assert len(k) == 4

  a, b, c, d = s
  a = rot_left(a, 27)
  c = rot_left(c, 10)
  a = a ^ b ^ d
  c = c ^ d ^ (b << 7) & 0xffffffff
  b = rot_left(b, 31)
  d = rot_left(d, 25)
  b = a ^ b ^ c
  d = d ^ c ^ (a << 3) & 0xffffffff
  a = rot_left(a, 19)
  c = rot_left(c, 29)
  s = a, b, c, d
  return tuple(x ^ y for x, y in zip(s, k))

def sbox(i, state):
  b = ip(state)
  c = [S[i][v] for v in b]
  return fp(c)

def inv_sbox(i, state):
  b = ip(state)
  c = [InvS[i][v] for v in b]
  return fp(c)

def key_schedule(key: bytes):
  # Step 1 pad the key
  if len(key) < 32:
    key += bytes([1]) + bytes(31 - len(key))
  # Convert to w[-8] .. w[-1]
  # Serpent uses little endian encoding.
  w = list(struct.unpack("<8L", key))
  phi = 0x9e3779b9
  for i in range(132):
    w.append(rot_left(w[-8] ^ w[-5] ^ w[-3] ^ w[-1] ^ i ^ phi, 11))
  for i, wi in enumerate(w):
    print(i - 8, hex(wi))
  w = w[8:]
  k = []
  j = 3
  for i in range(0, 132, 4):
    k.append(sbox(j, w[i:i+4]))
    j = (j - 1) % 8
  print('key_schedule')
  for i, ki in enumerate(k):
    print(i, [hex(v) for v in ki])
    print(hat(ki))
  return k

class Serpent:
  def __init__(self, key: bytes):
    self.k = key_schedule(key)
  
  def encrypt_block(self, block: bytes):
    b = struct.unpack("<4L", block)
    for i in range(32):
      b = mix(b, self.k[i])
      print('bhat', hat(b))
    return struct.pack("<4L", *b)
    
  def decrypt_block(self, block: bytes):
    b = struct.unpack("<4L", block)
    for i in range(31, -1, -1):
      b = inv_mix(b, self.k[i])
    return struct.pack("<4L", *b)

def test_ip():
  k = (0x1236abde, 0x11227632, 0x12314276, 0x77ff1324)
  k2 = fp(ip(k))
  print(k)
  print(k2)
  assert k == k2

def test_mix():
  s = (0x01234567, 0x89abcdef, 0xfedcba98, 0x76543210)
  k = (0x1236abde, 0x11227632, 0x12314276, 0x77ff1324)
  a = mix(s, k)
  b = inv_mix(a, k)
  print(b)
  print(s)
  assert b == s

def test_encrypt_decrypt():
  key = bytes(range(32))
  cipher = Serpent(key)
  p = bytes(range(32, 48))
  c = cipher.encrypt_block(p)
  d = cipher.decrypt_block(c)
  assert d == p


SERPENT_KTV = [
  {"key": "0000000000000000000000000000000000000000000000000000000000000000",
   "pt":  "00000000000000000000000000000000",
   "ct":  "49672ba898d98df95019180445491089"},

  {"key": "8000000000000000000000000000000000000000000000000000000000000000",
   "pt":  "00000000000000000000000000000000",
   "ct":  "a223aa1288463c0e2be38ebd825616c0"},
   
   {"key" : "00112233445566778899aabbccddeeff",
    "pt" : "00000000000000000000000000000000",
    "ct" : "8b3e43c04d285933abde6c2e56d70126"
   },

   {"key" : "00112233445566778899aabbccddeeff",
    "pt" : "0123456789abcdef0011223344556677",
    "ct" : "7b8901685a9d2815311b673ff184501e"
   }
]

def test_ktv():
  errors = 0
  for t in SERPENT_KTV[1:]:
     print(t)
     k = bytes.fromhex(t["key"])
     p = bytes.fromhex(t["pt"])
     c = bytes.fromhex(t["ct"])
     cipher = Serpent(k[::-1])
     c2 = cipher.encrypt_block(p)
     p2 = cipher.decrypt_block(c2)
     assert p == p2
     print(c2.hex())
     if c != c2:
       errors += 1
  assert errors == 0

if __name__ == "__main__":
  # test_ip()
  # test_mix()
  # test_encrypt_decrypt()
  test_ktv()
