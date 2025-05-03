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

import aes_gcm_siv
from aes_gcm_siv import AesGcmSiv
import gf
import util
import typing

# Decorator
TESTS = []
def Test(f):
  TESTS.append(f)
  return f

def run_tests():
  for test in TESTS:
    print("== %s ==" % test.__name__)
    test()

def hex2gf(h: str) -> gf.Element:
  return aes_gcm_siv.bytes2gf(bytes.fromhex(h))

# message,
# keyMaterial,
# nonce,
# aad,
# ciphertext,
# tag
test_vectors = [
  ("48656c6c6f20776f726c64",
   "ee8e1ed9ff2540ae8f2ba9f50bc2f27c",
   "752abad3e0afb5f434dc4310",
   "6578616d706c65",
   "5d349ead175ef6b1def6fd",
   "4fbcdeb7e4793f4a1d7e4faa70100af1",
  ),
  ("0123456789abcdef" * 10,
   "000102030405060708090a0b0c0d0e0f",
   "9816741982731987391bc123",
   "01020304050607" * 128,
   "9d8b69ce0b282ac69480a8f06accd0ec77f0e04f7adccdc516f79a1df4fee689"
   "013ebf15ab764b99691d35e51fa62d70323efa213aa2da4748d6091bc33cf487"
   "bb64da4c62b44286bb2b342aa1a7ea42",
   "f01e69dd5d3a6e1e67b46ac8fc300b8d"),
]

@Test
def test_dot():
  """Examples from section 7 of RFC 8452"""
  a = hex2gf("66e94bd4ef8a2c3b884cfa59ca342b2e")
  b = hex2gf("ff000000000000000000000000000000")
  assert a * b == hex2gf("37856175e9dc9df26ebc6d6171aa0ae9")
  assert aes_gcm_siv.dot(a, b) == hex2gf("ebe563401e7e91ea3ad6426b8140c394")

@Test
def test_ktv():
  """Checks test vectors"""
  for m, k, n, a, c, t in test_vectors:
    A = AesGcmSiv(bytes.fromhex(k))
    c2,t2 = A.encrypt(bytes.fromhex(n), bytes.fromhex(a), bytes.fromhex(m))
    assert c2.hex() == c
    assert t2.hex() == t

@Test
def test_plaintext_modification():
  msg = b"918273" * 124
  key = bytes(range(16))
  A = AesGcmSiv(key)
  nonce = bytes(range(12))
  aad = bytes(range(20))
  tag = bytes(range(16))
  for i, blk in A.modified_plaintext_blocks(nonce, aad, msg, tag):
    mod = msg[:16*i] + blk + msg[16*(i+1):]
    c, t2 = A.encrypt(nonce, aad, mod)
    assert tag == t2

if __name__ == "__main__":
  run_tests()
