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

# Aria is defined in RFC 5794
# Used in RFC 6209
# New block cipher: ARIA
# ICISC 2003
# http://www.math.snu.ac.kr/~jinhong/04Aria.pdf

def xor(a: bytes, b: bytes) -> bytes:
  if len(a) != len(b):
    raise ValueError("not the same length")
  return bytes(x ^ y for x, y in zip(a, b))


def rot_left(b: bytes, n: int) -> int:
  w = int.from_bytes(b, "big")
  q,r = divmod(w << n, 1 << (8 * len(b)))
  return (q + r).to_bytes(len(b), "big")


def rot_right(b: bytes, n: int) -> int:
  return rot_left(b, -n % (8 * len(b)))

SB1 = bytes.fromhex(
       "63 7c 77 7b f2 6b 6f c5 30 01 67 2b fe d7 ab 76"
       "ca 82 c9 7d fa 59 47 f0 ad d4 a2 af 9c a4 72 c0"
       "b7 fd 93 26 36 3f f7 cc 34 a5 e5 f1 71 d8 31 15"
       "04 c7 23 c3 18 96 05 9a 07 12 80 e2 eb 27 b2 75"
       "09 83 2c 1a 1b 6e 5a a0 52 3b d6 b3 29 e3 2f 84"
       "53 d1 00 ed 20 fc b1 5b 6a cb be 39 4a 4c 58 cf"
       "d0 ef aa fb 43 4d 33 85 45 f9 02 7f 50 3c 9f a8"
       "51 a3 40 8f 92 9d 38 f5 bc b6 da 21 10 ff f3 d2"
       "cd 0c 13 ec 5f 97 44 17 c4 a7 7e 3d 64 5d 19 73"
       "60 81 4f dc 22 2a 90 88 46 ee b8 14 de 5e 0b db"
       "e0 32 3a 0a 49 06 24 5c c2 d3 ac 62 91 95 e4 79"
       "e7 c8 37 6d 8d d5 4e a9 6c 56 f4 ea 65 7a ae 08"
       "ba 78 25 2e 1c a6 b4 c6 e8 dd 74 1f 4b bd 8b 8a"
       "70 3e b5 66 48 03 f6 0e 61 35 57 b9 86 c1 1d 9e"
       "e1 f8 98 11 69 d9 8e 94 9b 1e 87 e9 ce 55 28 df"
       "8c a1 89 0d bf e6 42 68 41 99 2d 0f b0 54 bb 16")
SB2 = bytes.fromhex("e2 4e 54 fc 94 c2 4a cc 62 0d 6a 46 3c 4d 8b d1"
                    "5e fa 64 cb b4 97 be 2b bc 77 2e 03 d3 19 59 c1"
                    "1d 06 41 6b 55 f0 99 69 ea 9c 18 ae 63 df e7 bb"
                    "00 73 66 fb 96 4c 85 e4 3a 09 45 aa 0f ee 10 eb"
                    "2d 7f f4 29 ac cf ad 91 8d 78 c8 95 f9 2f ce cd"
                    "08 7a 88 38 5c 83 2a 28 47 db b8 c7 93 a4 12 53"
                    "ff 87 0e 31 36 21 58 48 01 8e 37 74 32 ca e9 b1"
                    "b7 ab 0c d7 c4 56 42 26 07 98 60 d9 b6 b9 11 40"
                    "ec 20 8c bd a0 c9 84 04 49 23 f1 4f 50 1f 13 dc"
                    "d8 c0 9e 57 e3 c3 7b 65 3b 02 8f 3e e8 25 92 e5"
                    "15 dd fd 17 a9 bf d4 9a 7e c5 39 67 fe 76 9d 43"
                    "a7 e1 d0 f5 68 f2 1b 34 70 05 a3 8a d5 79 86 a8"
                    "30 c6 51 4b 1e a6 27 f6 35 d2 6e 24 16 82 5f da"
                    "e6 75 a2 ef 2c b2 1c 9f 5d 6f 80 0a 72 44 9b 6c"
                    "90 0b 5b 33 7d 5a 52 f3 61 a1 f7 b0 d6 3f 7c 6d"
                    "ed 14 e0 a5 3d 22 b3 f8 89 de 71 1a af ba b5 81")
SB3 = bytes.maketrans(SB1, bytes(range(256)))
SB4 = bytes.maketrans(SB2, bytes(range(256)))

def SL1(x: bytes) -> bytes:
  S = [SB1, SB2, SB3, SB4] * 4
  return bytes(s[b] for b, s in zip(x, S))

def SL2(x: bytes) -> bytes:
  S = [SB3, SB4, SB1, SB2] * 4
  return bytes(s[b] for b, s in zip(x, S))

def A(x: bytes) -> bytes:
  x0, x1, x2, x3, x4, x5, x6, x7 = x[:8]
  x8, x9, x10, x11, x12, x13, x14, x15 = x[8:]
  y0  = x3 ^ x4 ^ x6 ^ x8  ^ x9  ^ x13 ^ x14
  y1  = x2 ^ x5 ^ x7 ^ x8  ^ x9  ^ x12 ^ x15
  y2  = x1 ^ x4 ^ x6 ^ x10 ^ x11 ^ x12 ^ x15
  y3  = x0 ^ x5 ^ x7 ^ x10 ^ x11 ^ x13 ^ x14
  y4  = x0 ^ x2 ^ x5 ^ x8  ^ x11 ^ x14 ^ x15
  y5  = x1 ^ x3 ^ x4 ^ x9  ^ x10 ^ x14 ^ x15
  y6  = x0 ^ x2 ^ x7 ^ x9  ^ x10 ^ x12 ^ x13
  y7  = x1 ^ x3 ^ x6 ^ x8  ^ x11 ^ x12 ^ x13
  y8  = x0 ^ x1 ^ x4 ^ x7  ^ x10 ^ x13 ^ x15
  y9  = x0 ^ x1 ^ x5 ^ x6  ^ x11 ^ x12 ^ x14
  y10 = x2 ^ x3 ^ x5 ^ x6  ^ x8  ^ x13 ^ x15
  y11 = x2 ^ x3 ^ x4 ^ x7  ^ x9  ^ x12 ^ x14
  y12 = x1 ^ x2 ^ x6 ^ x7  ^ x9  ^ x11 ^ x12
  y13 = x0 ^ x3 ^ x6 ^ x7  ^ x8  ^ x10 ^ x13
  y14 = x0 ^ x3 ^ x4 ^ x5  ^ x9  ^ x11 ^ x14
  y15 = x1 ^ x2 ^ x4 ^ x5  ^ x8  ^ x10 ^ x15
  return [y0, y1, y2, y3, y4, y5, y6, y7, y8, y9, y10, y11, y12, y13, y14, y15]


def F0(D: bytes, Rk: bytes) -> bytes:
  return A(SL1(xor(D, Rk)))


def FE(D: bytes, Rk: bytes) -> bytes:
  return A(SL2(xor(D, Rk)))

class Aria:
  key_sizes_in_bytes = (16, 24, 32)
  block_size_in_bytes = 16

  def __init__(self, key: bytes):
    if len(key) not in self.key_sizes_in_bytes:
      raise ValueError("Invalid key length")
    self.key = key
    self.key_schedule(key)

  def key_schedule(self, key: bytes) -> list[int]:
    k_padded = key + bytes(32 - len(key))
    KL = k_padded[:16]
    KR = k_padded[16:]

    C1 = bytes.fromhex("517cc1b727220a94fe13abe8fa9a6ee0")
    C2 = bytes.fromhex("6db14acc9e21c820ff28b1d5ef5de2b0")
    C3 = bytes.fromhex("db92371d2126e9700324977504e8c90e")
    if len(key) == 16:
      CK1, CK2, CK3 = C1, C2, C3
      self.rounds = 12
    elif len(key) == 24:
      CK1, CK2, CK3 = C2, C3, C1
      self.rounds = 14
    elif len(key) == 32:
      CK1, CK2, CK3 = C3, C1, C2
      self.rounds = 16

    W0 = KL
    W1 = xor(F0(W0, CK1), KR)
    W2 = xor(FE(W1, CK2), W0)
    W3 = xor(F0(W2, CK3), W1)

    ek = [None] * 18
    ek[1]  = xor(W0, rot_right(W1, 19))
    ek[2]  = xor(W1, rot_right(W2, 19))
    ek[3]  = xor(W2, rot_right(W3, 19))
    ek[4]  = xor(W3, rot_right(W0, 19))
    ek[5]  = xor(W0, rot_right(W1, 31))
    ek[6]  = xor(W1, rot_right(W2, 31))
    ek[7]  = xor(W2, rot_right(W3, 31))
    ek[8]  = xor(W3, rot_right(W0, 31))
    ek[9]  = xor(W0, rot_left(W1, 61))
    ek[10] = xor(W1, rot_left(W2, 61))
    ek[11] = xor(W2, rot_left(W3, 61))
    ek[12] = xor(W3, rot_left(W0, 61))
    ek[13] = xor(W0, rot_left(W1, 31))
    ek[14] = xor(W1, rot_left(W2, 31))
    ek[15] = xor(W2, rot_left(W3, 31))
    ek[16] = xor(W3, rot_left(W0, 31))
    ek[17] = xor(W0, rot_left(W1, 19))
    self.ek = ek

  def encrypt_block(self, P: bytes) -> bytes:
    for i in range(1, self.rounds, 2):
      P = F0(P, self.ek[i])
      P = FE(P, self.ek[i+1])
    return xor(self.ek[self.rounds + 1], A(P))

  def decrypt_block(self, C: bytes) -> bytes:
    C = A(xor(self.ek[self.rounds + 1], C))
    for i in range(self.rounds - 1, 0, -2):
      C = xor(self.ek[i+1], SL1(A(C)))
      C = xor(self.ek[i], SL2(A(C)))
    return C
