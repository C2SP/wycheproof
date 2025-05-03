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

# Implements the paper
# Rocca: An Efficient AES-based EncryptionScheme for Beyond 5G
# by Kosei Sakamoto, Fukang Liu1, Yuto Nakano, Shinsaku Kiyomoto, and Takanori Isobe
# https://tosc.iacr.org/index.php/ToSC/article/view/8904/8480
#
# This is an experimental implementation, with the purpose to analyze the cipher and
# possibly to generate test vectors.
# Like any implementation for project Wycheproof, the implementations are not
# suitable for production. E.g., the implementation may intentionally skip certain
# verifications or add additional methods to produce edge cases.
#

import aes_util
import itertools

Block = bytes
State = list[Block]


def _xor(a: bytes, b:bytes) -> bytes:
  assert len(a) == len(b)
  return bytes(x ^ y for x, y in zip(a, b))

def _and(a: bytes, b:bytes) -> bytes:
  assert len(a) == len(b)
  return bytes(x & y for x, y in zip(a, b))

def const(c: str) -> bytes:
  """Converts a constant into bytes.

  The byte order of constants is not defined in the paper.
  Only the reference implementation indicate that the authors
  seem to use little endian order. This is actually different
  from the AEGIS paper, where constants use big endian order.
  """
  tmp = bytes.fromhex(c)
  return tmp[::-1]

class Rocca:
  z0 = const("428a2f98d728ae227137449123ef65cd")
  z1 = const("b5c0fbcfec4d3b2fe9b5dba58189dbbc")

  def __init__(self, key: bytes, tagsize :int = None):
    if len(key) != 32:
      raise ValueError("Invalid key length")
    self.key = key
    if tagsize not in [None, 16]:
      raise ValueError("Tag size not supported")
    self.tagsize = 16

  def state_update(self, S: State, x0: bytes, x1: bytes):
    aes_enc = aes_util.aes_enc
    return [
        _xor(S[7], x0),
        aes_enc(S[0], S[7]),
        _xor(S[1], S[6]),
        aes_enc(S[2], S[1]),
        _xor(S[3], x1),
        aes_enc(S[4], S[3]),
        aes_enc(S[5], S[4]),
        _xor(S[0], S[6])]

  def initialize(self, iv: Block) -> State:
    k0 = self.key[:16]
    k1 = self.key[16:]
    S = [k1, iv, self.z0, self.z1, _xor(iv, k1), bytes(16), k0, bytes(16)]
    for _ in range(20):
      S = self.state_update(S, self.z0, self.z1)
    return S

  def update_aad(self, S, aad: bytes):
    for i in range(0, len(aad), 32):
      adi = aad[i:i+32]
      if len(adi) < 32:
        adi += bytes(32 - len(adi))
      S = self.state_update(S, adi[:16], adi[16:])
    return S

  def finalize(self, S, ad_bits, msg_bits):
    t0 = ad_bits.to_bytes(16, 'little')
    t1 = msg_bits.to_bytes(16, 'little')
    for _ in range(20):
      S = self.state_update(S, t0, t1)
    tag = S[0]
    for r in S[1:8]:
      tag = _xor(tag, r)
    return tag

  def output_mask(self, S):
    m0 = aes_util.aes_enc(S[1], S[5])
    m1 = aes_util.aes_enc(_xor(S[0], S[4]), S[2])
    return m0 + m1

  def raw_encrypt(self, S, msg: bytes):
    ct_blocks = []
    for i in range(0, len(msg), 32):
      blk = msg[i:i+32]
      mask = self.output_mask(S)
      if len(blk) < 32:
        mask = mask[:len(blk)]
        p = blk + bytes(32 - len(blk))
      else:
        p = blk
      ct_blocks.append(_xor(mask, blk))
      S = self.state_update(S, p[:16], p[16:])
    return S, b''.join(ct_blocks)

  def raw_decrypt(self, S, ct: bytes):
    pt_blocks = []
    for i in range(0, len(ct), 32):
      blk = ct[i:i+32]
      mask = self.output_mask(S)
      p = _xor(mask[:len(blk)], blk)
      pt_blocks.append(p)
      if len(p) < 32:
        p += bytes(32 - len(blk))
      S = self.state_update(S, p[:16], p[16:])
    return S, b''.join(pt_blocks)

  def encrypt(self, iv: bytes, ad: bytes, msg: bytes):
    S = self.initialize(iv)
    S = self.update_aad(S, ad)
    S, ct = self.raw_encrypt(S, msg)
    tag = self.finalize(S, len(ad) * 8, len(msg) * 8)
    return ct, tag

  def decrypt(self, iv: bytes, ad: bytes, ct: bytes, tag: bytes):
    S = self.initialize(iv)
    S = self.update_aad(S, ad)
    S, pt = self.raw_decrypt(S, ct)
    tag2 = self.finalize(S, len(ad) * 8, len(ct) * 8)
    if tag2 != tag:
      raise Exception('Invalid tag')
    return pt

   # ==== stuff for analyzing the cipher ====
  def reverse_state_update(self, S: State, x0: bytes, x1: bytes) -> State:
    """Reverses the state_update method.

    I.e. if S is a state and x0 and x1 are blocks then
      S2 = state_update(S, x0, x1)
      S3 = reverse_state_update(S2, x0, x1)
    satisfies S3 == S.
    """
    aes_enc = aes_util.aes_enc
    s7 = _xor(S[0], x0)
    s0 = aes_util.inverse_aes_enc(S[1], s7)
    s6 = _xor(S[7], s0)
    s3 = _xor(S[4], x1)
    s4 = aes_util.inverse_aes_enc(S[5], s3)
    s5 = aes_util.inverse_aes_enc(S[6], s4)
    s1 = _xor(S[2], s6)
    s2 = aes_util.inverse_aes_enc(S[3], s1)
    return [s0, s1, s2, s3, s4, s5, s6, s7]

  def reverse_initialize(self, S: State) -> tuple[bytes, bytes]:
    """Recomputes the key and nonce, given the state after initialization.

    Returns:
      the key and the nonce
    Raises:
      ValueError if the S is not a state after an initialization.
    """
    for _ in range(20):
      S = self.reverse_state_update(S, self.z0, self.z1)

    if S[2] != self.z0:
      raise ValueError("S[2] invalid")
    if S[3] != self.z1:
      raise ValueError("S[3] invalid")
    if S[4] != _xor(S[0], S[1]):
      raise ValueError("S[4] invalid")
    if S[5] != bytes(16):
      raise ValueError("S[5] invalid")
    if S[7] != bytes(16):
      raise ValueError("S[7] invalid")
    return S[6] + S[0], S[1]

def min_cycles(n: int):
  S = [0] * 8
  x0 = 0
  x1 = 0
  _xor = lambda x, y: max(x, y) + 1
  aes_enc = lambda x, y: min(max(x + 4, y + 1), max(x, y) + 3)
  for i in range(n):
    S = [
        _xor(S[7], x0),
        aes_enc(S[0], S[7]),
        _xor(S[1], S[6]),
        aes_enc(S[2], S[1]),
        _xor(S[3], x1),
        aes_enc(S[4], S[3]),
        aes_enc(S[5], S[4]),
        _xor(S[0], S[6])]
  return S



KTV = [{
#===  test  vector  #1
  'key' : "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
          "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
  'nonce' : "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
  'aad' : "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
          "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
  'pt' : "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
         "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
         "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
         "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
  'ct' : "15 89 2f 85 55 ad 2d b4 74 9b 90 92 65 71 c4 b8"
         "c2 8b 43 4f 27 77 93 c5 38 33 cb 6e 41 a8 55 29"
         "17 84 a2 c7 fe 37 4b 34 d8 75 fd cb e8 4f 5b 88"
         "bf 3f 38 6f 22 18 f0 46 a8 43 18 56 50 26 d7 55",
  'tag' : "cc 72 8c 8b ae dd 36 f1 4c f8 93 8e 9e 07 19 bf"},
# ===  test  vector  #2 ===
  {'key' : "01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01"
           "01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01",
  'nonce' : "01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01",
  'aad' : "01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01"
          "01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01",
  'pt' : "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
         "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
         "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
         "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
  'ct' : "f9 31 a8 73 0b 2e 8a 3a f3 41 c8 3a 29 c3 05 25"
         "32 5c 17 03 26 c2 9d 91 b2 4d 71 4f ec f3 85 fd"
         "88 e6 50 ef 2e 2c 02 b3 7b 19 e7 0b b9 3f f8 2a"
         "a9 6d 50 c9 fd f0 53 43 f6 e3 6b 66 ee 7b da 69",
  'tag' : "ba d0 a5 36 16 59 9b fd b5 53 78 8f da ab ad 78"},
# ===  test  vector  #3===
  {'key' : "01 23 45 67 89 ab cd ef 01 23 45 67 89 ab cd ef"
           "01 23 45 67 89 ab cd ef 01 23 45 67 89 ab cd ef",
  'nonce' : "01 23 45 67 89 ab cd ef 01 23 45 67 89 ab cd ef",
  'aad' : "01 23 45 67 89 ab cd ef 01 23 45 67 89 ab cd ef"
          "01 23 45 67 89 ab cd ef 01 23 45 67 89 ab cd ef",
  'pt' : "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
         "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
         "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
         "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
  'ct' : "26 5b 7e 31 41 41 fd 14 82 35 a5 30 5b 21 7a b2"
         "91 a2 a7 ae ff 91 ef d3 ac 60 3b 28 e0 57 61 09"
         "72 34 22 ef 3f 55 3b 0b 07 ce 72 63 f6 35 02 a0"
         "05 91 de 64 8f 3e e3 b0 54 41 d8 31 3b 13 8b 5a",
  'tag' : "66 72 53 4a 8b 57 c2 87 bc f5 68 23 cd 1c db 5a"},
#===  test  vector  #4===
  {'key' : "11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11"
         "22 22 22 22 22 22 22 22 22 22 22 22 22 22 22 22",
  'nonce' : "44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44",
  'aad' : "80 81 82 83 84 85 86 87 88 89 8a 8b 8c 8d 8e 8f 90 91",
  'pt' : "00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f"
         "10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f"
         "20 21 22 23 24 25 26 27 28 29 2a 2b 2c 2d 2e 2f"
         "30 31 32 33 34 35 36 37 38 39 3a 3b 3c 3d 3e 3f",
  'ct' : "34 8b 6f 6e fa d8 07 d2 46 eb f3 45 e7 30 d8 3e"
         "59 63 bd 6d 29 ee dc 49 a1 35 40 54 5a e2 32 a7"
         "03 4e d4 ef 19 8a 1e b1 f8 b1 16 a1 76 03 54 b7"
         "72 60 d6 f2 cc a4 6e fc ad fc 47 65 ff fe 9f 09",
  'tag' : "a9 f2 06 94 56 55 9d e3 e6 9d 23 3e 15 4b a0 5e"}]

def print_tv(tv):
  for k,v in tv.items():
    print(f"{k}: {v.replace(' ','')}")

def testRocca():
  errors = 0
  for tv in KTV:
    key = bytes.fromhex(tv['key'])
    iv = bytes.fromhex(tv['nonce'])
    aad = bytes.fromhex(tv['aad'])
    pt = bytes.fromhex(tv['pt'])
    ct = bytes.fromhex(tv['ct'])
    tag = bytes.fromhex(tv['tag'])
    cipher = Rocca(key)
    c2, t2 = cipher.encrypt(iv,aad,pt)
    if ct != c2 or tag != t2:
      print("wrong encryption")
      print_tv(tv)
      print(ct.hex())
      print(c2.hex())
      print(tag.hex())
      print(t2.hex())
      print('---------')
      errors += 1
    try:
      p2 = cipher.decrypt(iv, aad, c2, t2)
      if p2 != pt:
        print("wrong decryption (1)")
        print_tv(tv)
        print(pt.hex())
        print(p2.hex())
        errors += 1
    except Exception as e:
      print("decryption failed (1)", e)
      errors += 1
    try:
      p2 = cipher.decrypt(iv,aad,ct,tag)
      if p2 != pt:
        print("wrong decryption (2)")
        print_tv(tv)
        print(pt.hex())
        print(p2.hex())
        errors += 1
    except Exception as e:
      print("decryption failed (2)", e)
      errors += 1


  print("%s errors found" % errors)
  assert errors == 0

def testInvert():
  key = bytes(range(32))
  iv = bytes(range(32, 48))
  cipher = Rocca(key)
  S = cipher.initialize(iv)
  k2, i2 = cipher.reverse_initialize(S)
  assert key == k2
  assert iv == i2
  print('key found')

if __name__ == "__main__":
  testRocca()
  testInvert()

