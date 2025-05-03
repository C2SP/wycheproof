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

import sm4
import sm4_gcm
import sm4_ccm
import sm4_ktv
import bin_matrix


def test_linear_function(f):
  rows = [f(1 << i) for i in range(32)]
  mat_b = bin_matrix.BinMatrix(rows, 32)
  inv_b = mat_b.inverse()
  print("%s^-1(1)=%s" % (f.__name__, bin(inv_b.L[0])))
  print("CharPoly:", mat_b.charPoly())
  for i in range(16):
    bp = mat_b**i
    print("%s^%s(1)=%s" % (f.__name__, i, bin(bp.L[0])))


# Test vectors from SM4 draft.
# format, (comment, plaintext, key, ct, repetitions)
TEST_VECTORS = [
    ("https://tools.ietf.org/html/draft-ribose-cfrg-sm4-10, Example 1",
     "01 23 45 67 89 AB CD EF FE DC BA 98 76 54 32 10",
     "01 23 45 67 89 AB CD EF FE DC BA 98 76 54 32 10",
     "68 1E DF 34 D2 06 96 5E 86 B3 E9 4F 53 6E 42 46", 1),
    ("https://tools.ietf.org/html/draft-ribose-cfrg-sm4-10, Example 4",
     "00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F",
     "FE DC BA 98 76 54 32 10 01 23 45 67 89 AB CD EF",
     "F7 66 67 8F 13 F0 1A DE AC 1B 3E A9 55 AD B5 94", 1),
    ("https://tools.ietf.org/html/draft-ribose-cfrg-sm4-10, Example 3",
     "01 23 45 67 89 AB CD EF FE DC BA 98 76 54 32 10",
     "01 23 45 67 89 AB CD EF FE DC BA 98 76 54 32 10",
     "59 52 98 C7 C6 FD 27 1F 04 02 F8 04 C3 3D 3F 66", 1000000),
    ("https://tools.ietf.org/html/draft-ribose-cfrg-sm4-10, Example 6",
     "00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F",
     "FE DC BA 98 76 54 32 10 01 23 45 67 89 AB CD EF",
     "37 9A 96 D0 A6 A5 A5 06 0F B4 60 C7 5D 18 79 ED", 1000000),
]


def repeat(key: bytes, block: bytes, reps: int) -> bytes:
  rk = sm4.round_keys(key)
  for i in range(reps):
    block = sm4.encrypt_block(block, rk)
  return block


# A simple profile:
#
#   ncalls  tottime  percall  cumtime  percall filename:lineno(function)
# 64000192   36.731    0.000   74.391    0.000 sms4.py:60(tau)
# 64000064   20.668    0.000   20.668    0.000 sms4.py:52(L)
# 72000200   19.416    0.000   19.416    0.000 {method "to_bytes" of "int" objects}
# 72000216   17.999    0.000   17.999    0.000 {built-in method from_bytes}
# 64000064   17.513    0.000  112.572    0.000 sms4.py:67(T)
# 64000064   16.646    0.000  129.218    0.000 sms4.py:73(F)
#  2000002   10.666    0.000  139.884    0.000 sms4.py:76(R)
# 64000192    5.576    0.000    5.576    0.000 {method "translate" of "bytes" objects}
#  2000002    3.181    0.000    5.800    0.000 sms4.py:83(<listcomp>)
# 10000010    2.682    0.000    5.395    0.000 sms4.py:86(<genexpr>)
#  2000002    2.383    0.000  154.874    0.000 sms4.py:82(encrypt_block)
#  2000002    1.413    0.000    6.808    0.000 {method "join" of "bytes" objects}
#        4    0.627    0.157  155.503   38.876 sms4.py:221(rec)
def test_repetition():
  for _, pt_hex, key_hex, ct_hex, reps in TEST_VECTORS:
    key = bytes.fromhex(key_hex)
    pt = bytes.fromhex(pt_hex)
    ct = bytes.fromhex(ct_hex)
    enc = repeat(key, pt, reps)
    if ct != enc:
      print(ct.hex())
      print(enc.hex())
    assert ct == enc


def test_aead(aead, ktv):
  for t in ktv:
    iv = bytes.fromhex(t["iv"])
    key = bytes.fromhex(t["key"])
    msg = bytes.fromhex(t["msg"])
    aad = bytes.fromhex(t["aad"])
    ct = bytes.fromhex(t["ct"])
    tag = bytes.fromhex(t["tag"])
    cipher = aead(key, len(tag))
    c2, t2 = cipher.encrypt(iv, aad, msg)
    assert c2 == ct
    assert t2 == tag
    m2 = cipher.decrypt(iv, aad, ct, tag)
    assert m2 == msg

def all_tests():
  test_linear_function(sm4.L)
  test_linear_function(sm4.Lp)
  test_repetition()
  test_aead(sm4_gcm.Sm4Gcm, sm4_ktv.SM4_GCM_KTV)
  test_aead(sm4_ccm.Sm4Ccm, sm4_ktv.SM4_CCM_KTV)

if __name__ == "__main__":
  all_tests()
