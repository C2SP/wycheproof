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

import keccak
import hashlib
from time import time

# Computing round constants a described by FIPS-202
def lfsr(bits: int = 255):
  R = 1
  res = []
  for i in range(bits):
    res.append(R & 1)
    c, R = divmod(R << 1, 256)
    R ^= c * 0b1110001
  return res
LFSR = lfsr()

def rc(t: int) -> int:
  return LFSR[t % 255]
  
def round_constant(l: int, ir: int) -> int:
  return sum(rc(j + 7 * ir) << (2 ** j - 1) for j in range(l + 1))

def round_constants(w: int) -> list[int]:
  l = w.bit_length() - 1
  rounds = 12 + 2 * l
  return [round_constant(l, ir) for ir in range(rounds)]

# Computing round constants from a reference implementation.
def round_constants_ref(w: int) -> list[int]:
  l = w.bit_length() - 1
  assert l <= 6
  rounds = 12 + 2 * l
  res = [None] * rounds
  R = 1
  for rnd in range(rounds):
    rc = 0
    for j in range(7):
      if R & 1 and j <= l:
        rc ^= (1 << ((1 << j) - 1))
      R <<= 1
      if R & 0x100:
        R ^= 0x171
    res[rnd] = rc
  return res

def sha3_224(b):
  h = hashlib.sha3_224()
  h.update(b)
  return h.digest()

def sha3_256(b):
  h = hashlib.sha3_256()
  h.update(b)
  return h.digest()

def test_round_constants():
  for w in [1, 2, 4, 8, 16, 32, 64]:
    rc0 = round_constants(w)
    rc1 = round_constants_ref(w)
    if rc0 != rc1:
      print(w, rc0 == rc1)
      for rc in (rc0, rc1):
        print(", ".join(hex(x) for x in rc))

def test0(max_size=768):
  print("test0")
  start = time()
  for sz in range(256):
    data = bytes(range(sz))
    assert sha3_224(data) == keccak.SHA3_224(data)
    assert sha3_256(data) == keccak.SHA3_256(data)
  for sz in range(256, max_size):
    data = bytes([i * 123 // 37 % 256 for i in range(sz)])
    assert sha3_224(data) == keccak.SHA3_224(data)
    assert sha3_256(data) == keccak.SHA3_256(data)
  print("time:", time()-start)

KTV = {
  "KECCAK_224" : [
    (b"", "f71837502ba8e10837bdd8d365adb85591895602fc552b48b7390abd"),
    (b"abc", "c30411768506ebe1c2871b1ee2e87d38df342317300a9b97a95ec6a8"),
  ],
  "KECCAK_256" : [
    (b"", "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"),
    (b"abc", "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45")
  ],
}

def testktv():
  print("testktv")
  for h, ktv in KTV.items():
    f = getattr(keccak, h) 
    for inp, res in ktv:
      r = f(inp).hex()
      if r != res:
        print(h, inp, res, r)
  print("done")

def test_cShake():
  N = b""
  S = b"Email Signature"
  X = bytes(range(4))
  L = 256
  res = keccak.cSHAKE128(X, L//8, N, S)
  assert res == bytes.fromhex(
      "C1C36925B6409A04F1B504FCBCA9D82B4017277CB5ED2B2065FC1D3814D5AAF5")

  X = bytes(range(200))
  res = keccak.cSHAKE128(X, L//8, N, S)
  assert res == bytes.fromhex(
      "C5221D50E4F822D96A2E8881A961420F294B7B24FE3D2094BAED2C6524CC166B")


KTV_KMAC128 = [
{ "key" : bytes(range(64, 96)),
  "data" : bytes(range(4)),
  "L" : 256,
  "S" : b"",
  "res" : "E5 78 0B 0D 3E A6 F7 D3 A4 29 C5 70 6A A4 3A 00"
          "FA DB D7 D4 96 28 83 9E 31 87 24 3F 45 6E E1 4E"},
{ "key" : bytes(range(64, 96)),
  "data" : bytes(range(4)),
  "L" : 256,
  "S": b"My Tagged Application",
  "res" : "3B 1F BA 96 3C D8 B0 B5 9E 8C 1A 6D 71 88 8B 71"
          "43 65 1A F8 BA 0A 70 70 C0 97 9E 28 11 32 4A A5"},
{  "key" : bytes(range(64, 96)),
  "data" : bytes(range(200)),
  "L": 256,
  "S": b"My Tagged Application",
  "res" : "1F 5B 4E 6C CA 02 20 9E 0D CB 5C A6 35 B8 9A 15"
          "E2 71 EC C7 60 07 1D FD 80 5F AA 38 F9 72 92 30"}]
KTV_KMAC256 = [
{ "key" : bytes(range(64, 96)),
  "data" : bytes(range(4)),
  "L": 512,
  "S": b"My Tagged Application",
  "res" : 
      "20 C5 70 C3 13 46 F7 03 C9 AC 36 C6 1C 03 CB 64"
      "C3 97 0D 0C FC 78 7E 9B 79 59 9D 27 3A 68 D2 F7"
      "F6 9D 4C C3 DE 9D 10 4A 35 16 89 F2 7C F6 F5 95"
      "1F 01 03 F3 3F 4F 24 87 10 24 D9 C2 77 73 A8 DD"},

{  "key" : bytes(range(64, 96)),
  "data" : bytes(range(200)),
  "L": 512,
  "S" : b"",
  "res" : 
      "75 35 8C F3 9E 41 49 4E 94 97 07 92 7C EE 0A F2"
      "0A 3F F5 53 90 4C 86 B0 8F 21 CC 41 4B CF D6 91"
      "58 9D 27 CF 5E 15 36 9C BB FF 8B 9A 4C 2E B1 78"
      "00 85 5D 02 35 FF 63 5D A8 25 33 EC 6B 75 9B 69"},
{ "key" : bytes(range(64, 96)),
  "data" : bytes(range(200)),
  "L": 512,
  "S" : b"My Tagged Application",
  "res":
      "B5 86 18 F7 1F 92 E1 D5 6C 1B 8C 55 DD D7 CD 18"
      "8B 97 B4 CA 4D 99 83 1E B2 69 9A 83 7D A2 E4 D9"
      "70 FB AC FD E5 00 33 AE A5 85 F1 A2 70 85 10 C3"
      "2D 07 88 08 01 BD 18 28 98 FE 47 68 76 FC 89 65"}]

def ptn(n: int):
  s = bytes(range(251))
  return s * (n // len(s)) + s[:n % len(s)] 

#
#
# 
#  { "data" : b"",
#    "customization" : b"", 10032), last 32 bytes:
#       `E8 DC 56 36 42 F7 22 8C 84 68 4C 89 84 05 D3 A8
#        34 79 91 58 C0 79 B1 28 80 27 7A 1D 28 E2 FF 6D")#  },
  
KangarooTwelveKtv = [
  { "data" : b"",
    "customization" : b"",
    "size" : 32,
    "res" : bytes.fromhex("1A C2 D4 50 FC 3B 42 05 D1 9D A7 BF CA 1B 37 51"
      "3C 08 03 57 7A C7 16 7F 06 FE 2C E1 F0 EF 39 E5")
  },
  { "data" : b"",
    "customization" : b"",
    "size" : 64,
    "res": bytes.fromhex("1A C2 D4 50 FC 3B 42 05 D1 9D A7 BF CA 1B 37 51"
      "3C 08 03 57 7A C7 16 7F 06 FE 2C E1 F0 EF 39 E5"
      "42 69 C0 56 B8 C8 2E 48 27 60 38 B6 D2 92 96 6C"
      "C0 7A 3D 46 45 27 2E 31 FF 38 50 81 39 EB 0A 71")
  },
  { "data" :ptn(1),
    "customization" : b"",
    "size" : 32,
    "res" :bytes.fromhex("2B DA 92 45 0E 8B 14 7F 8A 7C B6 29 E7 84 A0 58"
      "EF CA 7C F7 D8 21 8E 02 D3 45 DF AA 65 24 4A 1F")
  },
  { "data" :ptn(17),
    "customization" : b"",
    "size" : 32,
    "res" : bytes.fromhex("6B F7 5F A2 23 91 98 DB 47 72 E3 64 78 F8 E1 9B"
      "0F 37 12 05 F6 A9 A9 3A 27 3F 51 DF 37 12 28 88")
  },
  { "data" :ptn(17**2),
    "customization" : b"",
    "size" : 32,
    "res" : bytes.fromhex("0C 31 5E BC DE DB F6 14 26 DE 7D CF 8F B7 25 D1"
      "E7 46 75 D7 F5 32 7A 50 67 F3 67 B1 08 EC B6 7C")
  },
  { "data" :ptn(17**3),
    "customization" : b"",
    "size" : 32,
    "res" : bytes.fromhex("CB 55 2E 2E C7 7D 99 10 70 1D 57 8B 45 7D DF 77"
      "2C 12 E3 22 E4 EE 7F E4 17 F9 2C 75 8F 0D 59 D0")
  },
  { "data" :ptn(17**4),
   "customization" : b"",
    "size" : 32,
    "res" : bytes.fromhex("87 01 04 5E 22 20 53 45 FF 4D DA 05 55 5C BB 5C"
      "3A F1 A7 71 C2 B8 9B AE F3 7D B4 3D 99 98 B9 FE")
  },
  { "data" :ptn(17**5),
    "customization" : b"",
    "size" : 32,
    "res" : bytes.fromhex("84 4D 61 09 33 B1 B9 96 3C BD EB 5A E3 B6 B0 5C"
      "C7 CB D6 7C EE DF 88 3E B6 78 A0 A8 E0 37 16 82")
  },
  { "data" :ptn(17**6),
   "customization" : b"",
    "size" : 32,
    "res" : bytes.fromhex("3C 39 07 82 A8 A4 E8 9F A6 36 7F 72 FE AA F1 32"
      "55 C8 D9 58 78 48 1D 3C D8 CE 85 F5 8E 88 0A F8")
  },
  { "data" : b"",
    "customization" : ptn(1),
    "size" : 32,
    "res" : bytes.fromhex("FA B6 58 DB 63 E9 4A 24 61 88 BF 7A F6 9A 13 30"
      "45 F4 6E E9 84 C5 6E 3C 33 28 CA AF 1A A1 A5 83")
  },
  { "data" : bytes([0xff]),
    "customization" : ptn(41),
    "size" : 32,
    "res" : bytes.fromhex("D8 48 C5 06 8C ED 73 6F 44 62 15 9B 98 67 FD 4C"
      "20 B8 08 AC C3 D5 BC 48 E0 B0 6B A0 A3 76 2E C4")
  },
  { "data" :bytes([0xff]) * 3,
    "customization" : ptn(41**2),
    "size" : 32,
    "res" : bytes.fromhex("C3 89 E5 00 9A E5 71 20 85 4C 2E 8C 64 67 0A C0"
      "13 58 CF 4C 1B AF 89 44 7A 72 42 34 DC 7C ED 74")
  },
  { "data" : bytes([0xff]) * 7,
    "customization" : ptn(41**3),
    "size" : 32,
    "res" : bytes.fromhex("75 D2 F8 6A 2E 64 45 66 72 6B 4F BC FC 56 57 B9"
      "DB CF 07 0C 7B 0D CA 06 45 0A B2 91 D7 44 3B CF")}
]

TurboSHAKE128 = [
  {"M":b"",
   "D": 0x07,
   "size" :32,
   "res" :"5A 22 3A D3 0B 3B 8C 66 A2 43 04 8C FC ED 43 0F"
        "54 E7 52 92 87 D1 51 50 B9 73 13 3A DF AC 6A 2F"
  },
  {"M": b"",
   "D": 0x07,
   "size": 64,
   "res": "5A 22 3A D3 0B 3B 8C 66 A2 43 04 8C FC ED 43 0F"
        "54 E7 52 92 87 D1 51 50 B9 73 13 3A DF AC 6A 2F"
        "FE 27 08 E7 30 61 E0 9A 40 00 16 8B A9 C8 CA 18"
        "13 19 8F 7B BE D4 98 4B 41 85 F2 C2 58 0E E6 23"
  },
#  {"M": b"",
#   "D": 0x07,
#   "size": 10032), last 32 bytes:
#       "75 93 A2 80 20 A3 C4 AE 0D 60 5F D6 1F 5E B5 6E"
#        "CC D2 7C C3 D1 2F F0 9F 78 36 97 72 A4 60 C5 5D"
#  },
  {"M": ptn(1),
   "D": 0x07,
   "size": 32,
   "res": "1A C2 D4 50 FC 3B 42 05 D1 9D A7 BF CA 1B 37 51"
        "3C 08 03 57 7A C7 16 7F 06 FE 2C E1 F0 EF 39 E5"
  },
  {"M": ptn(17),
   "D": 0x07,
   "size": 32,
   "res": "AC BD 4A A5 75 07 04 3B CE E5 5A D3 F4 85 04 D8"
        "15 E7 07 FE 82 EE 3D AD 6D 58 52 C8 92 0B 90 5E"
  },
  {"M": ptn(17**2),
   "D": 0x07,
   "size": 32,
   "res": "7A 4D E8 B1 D9 27 A6 82 B9 29 61 01 03 F0 E9 64"
        "55 9B D7 45 42 CF AD 74 0E E3 D9 B0 36 46 9E 0A"
  },
  {"M": ptn(17**3),
   "D": 0x07,
   "size": 32,
   "res": "74 52 ED 0E D8 60 AA 8F E8 E7 96 99 EC E3 24 F8"
        "D9 32 71 46 36 10 DA 76 80 1E BC EE 4F CA FE 42"
  },
  {"M": ptn(17**4),
   "D": 0x07,
   "size": 32,
   "res": "CA 5F 1F 3E EA C9 92 CD C2 AB EB CA 0E 21 67 65"
        "DB F7 79 C3 C1 09 46 05 5A 94 AB 32 72 57 35 22"
  },
  {"M": ptn(17**5),
   "D": 0x07,
   "size": 32,
   "res": "E9 88 19 3F B9 11 9F 11 CD 34 46 79 14 E2 A2 6D"
        "A9 BD F9 6C 8B EF 07 6A EE AD 1A 89 7B 86 63 83"
  },
  {"M": ptn(17**6),
   "D": 0x07,
   "size": 32,
   "res": "9C 0F FB 98 7E EE ED AD FA 55 94 89 87 75 6D 09"
        "0B 67 CC B6 12 36 E3 06 AC 8A 24 DE 1D 0A F7 74"
  },
  {"M": b"",
   "D": 0x06,
   "size": 32,
   "res": "C7 90 29 30 6B FA 2F 17 83 6A 3D 65 16 D5 56 63"
        "40 FE A6 EB 1A 11 39 AD 90 0B 41 24 3C 49 4B 37"
  },
  {"M": b"",
   "D": 0x0B,
   "size": 32,
   "res": "8B 03 5A B8 F8 EA 7B 41 02 17 16 74 58 33 2E 46"
        "F5 4B E4 FF 83 54 BA F3 68 71 04 A6 D2 4B 0E AB"
  },
  # This is a duplicate
  {"M": b"",
   "D": 0x06,
   "size": 32,
   "res": "C7 90 29 30 6B FA 2F 17 83 6A 3D 65 16 D5 56 63"
        "40 FE A6 EB 1A 11 39 AD 90 0B 41 24 3C 49 4B 37"
  },
  {"M": "FF",
   "D": 0x06,
   "size": 32,
   "res": "8E C9 C6 64 65 ED 0D 4A 6C 35 D1 35 06 71 8D 68"
        "7A 25 CB 05 C7 4C CA 1E 42 50 1A BD 83 87 4A 67"
  },
  {"M": "FF FF FF",
   "D": 0x06,
   "size": 32,
   "res": "3D 03 98 8B B5 9E 68 18 51 A1 92 F4 29 AE 03 98"
        "8E 8F 44 4B C0 60 36 A3 F1 A7 D2 CC D7 58 D1 74"
  },
  {"M": "FF FF FF FF FF FF FF",
   "D": 0x06,
   "size": 32,
   "res": "05 D9 AE 67 3D 5F 0E 48 BB 2B 57 E8 80 21 A1 A8"
        "3D 70 BA 85 92 3A A0 4C 12 E8 F6 5B A1 F9 45 95"
  },
]

TurboSHAKE256 = [
 { "M": b"",
   "D": 0x07,
   "size": 64,
   "res": "4A 55 5B 06 EC F8 F1 53 8C CF 5C 95 15 D0 D0 49"
        "70 18 15 63 A6 23 81 C7 F0 C8 07 A6 D1 BD 9E 81"
        "97 80 4B FD E2 42 8B F7 29 61 EB 52 B4 18 9C 39"
        "1C EF 6F EE 66 3A 3C 1C E7 8B 88 25 5B C1 AC C3"
  },
#  {"M": b"",
#   "D": 0x07,
#   "size": 10032), last 32 bytes:
#       "40 22 1A D7 34 F3 ED C1 B1 06 BA D5 0A 72 94 93"
#        "15 B3 52 BA 39 AD 98 B5 B3 C2 30 11 63 AD AA D0"
#  },
  # draft is wrong and uses M = '00'^0
  {"M": ptn(1),
   "D": 0x07,
   "size": 64,
   "res": "B2 3D 2E 9C EA 9F 49 04 E0 2B EC 06 81 7F C1 0C"
        "E3 8C E8 E9 3E F4 C8 9E 65 37 07 6A F8 64 64 04"
        "E3 E8 B6 81 07 B8 83 3A 5D 30 49 0A A3 34 82 35"
        "3F D4 AD C7 14 8E CB 78 28 55 00 3A AE BD E4 A9"
  },
  {"M": ptn(17),
   "D": 0x07,
   "size": 64,
   "res": "66 D3 78 DF E4 E9 02 AC 4E B7 8F 7C 2E 5A 14 F0"
        "2B C1 C8 49 E6 21 BA E6 65 79 6F B3 34 6E 6C 79"
        "75 70 5B B9 3C 00 F3 CA 8F 83 BC A4 79 F0 69 77"
        "AB 3A 60 F3 97 96 B1 36 53 8A AA E8 BC AC 85 44"
  },
  {"M": ptn(17**2),
   "D": 0x07,
   "size": 64,
   "res": "C5 21 74 AB F2 82 95 E1 5D FB 37 B9 46 AC 36 BD"
        "3A 6B CC 98 C0 74 FC 25 19 9E 05 30 42 5C C5 ED"
        "D4 DF D4 3D C3 E7 E6 49 1A 13 17 98 30 C3 C7 50"
        "C9 23 7E 83 FD 9A 3F EC 46 03 FF 57 E4 22 2E F2"
  },
  {"M": ptn(17**3),
   "D": 0x07,
   "size": 64,
   "res": "62 A5 A0 BF F0 64 26 D7 1A 7A 3E 9E 3F 2F D6 E2"
        "52 FF 3F C1 88 A6 A5 36 EC A4 5A 49 A3 43 7C B3"
        "BC 3A 0F 81 49 C8 50 E6 E7 F4 74 7A 70 62 7F D2"
        "30 30 41 C6 C3 36 30 F9 43 AD 92 F8 E1 FF 43 90"
  },
  {"M": ptn(17**4),
   "D": 0x07,
   "size": 64,
   "res": "52 3C 06 47 18 2D 89 41 F0 DD 5C 5C 0A B6 2D 4F"
        "C2 95 61 61 53 96 BB 5B 9A 9D EB 02 2B 80 C5 BF"
        "2D 83 A3 BB 36 FF C0 4F AC 58 CF 11 49 C6 6D EC"
        "4A 59 52 6E 51 F2 95 96 D8 24 42 1A 4B 84 B4 4D"
  },
  {"M": ptn(17**5),
   "D": 0x07,
   "size": 64,
   "res": "D1 14 A1 C1 A2 08 FF 05 FD 49 D0 9E E0 35 46 5D"
        "86 54 7E BA D8 E9 AF 4F 8E 87 53 70 57 3D 6B 7B"
        "B2 0A B9 60 63 5A B5 74 E2 21 95 EF 9D 17 1C 9A"
        "28 01 04 4B 6E 2E DF 27 2E 23 02 55 4B 3A 77 C9"
  },
  {"M": ptn(17**6),
   "D": 0x07,
   "size": 64,
   "res": "1E 51 34 95 D6 16 98 75 B5 94 53 A5 94 E0 8A E2"
        "71 CA 20 E0 56 43 C8 8A 98 7B 5B 6A B4 23 ED E7"
        "24 0F 34 F2 B3 35 FA 94 BC 4B 0D 70 E3 1F B6 33"
        "B0 79 84 43 31 FE A4 2A 9C 4D 79 BB 8C 5F 9E 73"
  },
  # This one claims D=0x0B, but uses D=0x11
  {"M": b"",
   "D": 0x11,
   "size": 64,
   "res": "4C FB 3C A1 0E 97 D3 51 1C F6 1F C5 00 D0 BF 7D"
        "0E 0B 7E 6C 2E 6E F6 58 8F 96 24 8E 97 1C 50 26"
        "35 59 04 87 8C 01 D4 AD 64 4A 43 31 B2 BB 17 F1"
        "B9 63 C7 79 03 1A 7C B3 EE FB 02 66 9B 37 4C 2A"
  },
  {"M": b"",
   "D": 0x06,
   "size": 64,
   "res": "FF 23 DC CD 62 16 8F 5A 44 46 52 49 A8 6D C1 0E"
        "8A AB 4B D2 6A 22 DE BF 23 48 02 0A 83 1C DB E1"
        "2C DD 36 A7 DD D3 1E 71 C0 1F 7C 97 A0 D4 C3 A0"
        "CC 1B 21 21 E6 B7 CE AB 38 87 A4 C9 A5 AF 8B 03"
  },
  {"M": "FF",
   "D": 0x06,
   "size": 64,
   "res": "73 8D 7B 4E 37 D1 8B 7F 22 AD 1B 53 13 E3 57 E3"
        "DD 7D 07 05 6A 26 A3 03 C4 33 FA 35 33 45 52 80"
        "F4 F5 A7 D4 F7 00 EF B4 37 FE 6D 28 14 05 E0 7B"
        "E3 2A 0A 97 2E 22 E6 3A DC 1B 09 0D AE FE 00 4B"
  },
  {"M": "FF FF FF",
   "D": 0x06,
   "size": 64,
   "res": "E5 53 8C DD 28 30 2A 2E 81 E4 1F 65 FD 2A 40 52"
        "01 4D 0C D4 63 DF 67 1D 1E 51 0A 9D 95 C3 7D 71"
        "35 EF 27 28 43 0A 9E 31 70 04 F8 36 C9 A2 38 EF"
        "35 37 02 80 D0 3D CE 7F 06 12 F0 31 5B 3C BF 63"
  },
  {"M": "FF FF FF FF FF FF FF",
   "D": 0x06,
   "size": 64,
   "res": "B3 8B 8C 15 F4 A6 E8 0C D3 EC 64 5F 99 9F 64 98"
        "AA D7 A5 9A 48 9C 1D EE 29 70 8B 4F 8A 59 E1 24"
        "99 A9 6F 89 37 22 56 FE 52 2B 1B 97 47 2A DD 73"
        "69 15 BD 4D F9 3B 21 FF E5 97 21 7E B3 C2 C6 D9"
  }
]

def test_kmac0(kmac, ktv):
  for tv in ktv:
    key = tv["key"]
    data = tv["data"]
    L = tv["L"]
    S = tv["S"]
    expected = tv["res"]
    expected = expected.replace(" ", "").replace("\n", "").lower()
    res = kmac(key, data, L//8, S)
    assert expected == res.hex()

def test_kmac():
  print("test_kmac")
  test_kmac0(keccak.KMAC128, KTV_KMAC128)
  test_kmac0(keccak.KMAC256, KTV_KMAC256)

def test_kangaroo_twelve():
  print("test_kangaroo_twelve")
  for tv in KangarooTwelveKtv:
    data = tv["data"]
    c = tv["customization"]
    sz = tv["size"]
    expected = tv["res"]
    assert len(expected) == sz
    res = keccak.KangarooTwelve(data, c, sz)
    assert res == expected

def test_bm():
  print("test_bm")
  start = time()
  res = keccak.SHA3_256(b"a"* 10000000)
  assert res.hex() == "b8da430b2ef83f2281e94926f6e7284ac949cb7db47d4c6f7db6c59aadeeecc2"
  print(time() - start)
    
def test_turbo_shake():
  print("test_turbo_shake")
  errors = 0
  for f, tvs in [
      (keccak.TurboShake128, TurboSHAKE128),
      (keccak.TurboShake256, TurboSHAKE256)]:
    for tv in tvs:
      M = tv["M"]
      if isinstance(M, str):
        M = bytes.fromhex(M)
      D = tv["D"]
      sz = tv["size"]
      expected = bytes.fromhex(tv["res"])
      res = f(M, D, sz)
      if res != expected:
        print(tv)
        print(res.hex())
        errors += 1
  assert errors == 0
     
if __name__ == "__main__":
  start = time()
  test_round_constants()
  test0()
  testktv()
  test_cShake()
  test_kmac()
  test_turbo_shake()
  test_kangaroo_twelve()
  test_bm()
  # 89 s
  print("test total:", time() - start)
