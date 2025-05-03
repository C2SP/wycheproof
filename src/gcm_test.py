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

# Test some properties of GCM.
# Note tests of GCM implementations are not tested here. These
# test are in aes_test.py, aria_test.py sm4_test.py, etc.

import aes_gcm
import gf
import gcm
from dataclasses import dataclass


@dataclass
class GhashKtv:
  h: str  # hexadecimal representation of h
  inp: str  # hexadecimal, must be a multiple of the block size
  res: str  # hexadecimal, the expected result


GHASH_KTV = [
    GhashKtv(
        h="ffffffffffffffffffffffffffffffff",
        inp="00112233445566778899aabbccddeeff",
        res="8aa0ad61e6da7fb371ad08c4437fda16"),
    GhashKtv(
        h="000102030405060708090a0b0c0d0e0f",
        inp="",
        res="00000000000000000000000000000000"),
    GhashKtv(
        h="000102030405060708090a0b0c0d0e0f",
        inp="00112233445566778899aabbccddeeff",
        res="f4d90ee8ca961e8fdb6d4f748b0a5f13"),
    GhashKtv(
        h="000102030405060708090a0b0c0d0e0f",
        inp=bytes(range(256)).hex(),
        res="2e1132bf93934d1af4a3b5edb1451d7a"),
    GhashKtv(
        h="4bb3e2c2894b90108edc3cde4116355b",
        inp="802a78855f7a8cc1fc3c440c759bff57"
        "72cc65bfef192c9c213776296da53946"
        "2a7038301603938baf0fa9764f1f0af1"
        "35fa46c8a305febf75172c3a701fe9a8"
        "71687421a6a4cc5f08a24457d40c27c1"
        "5cd3f26890db62a76555ffe02b801312"
        "14e740ffa48246c2cecb7e21a7f74241"
        "53b2c22f14ff8528d7114f598e08884b",
        res="aae329eb467a1ee715f9c927391141d9"),
]


def test_ghash():
  for t in GHASH_KTV:
    h = gcm.bytes2gf(bytes.fromhex(t.h))
    g = gcm.Ghash(h)
    res = g.hash_padded(bytes.fromhex(t.inp)).hex()
    print(res)
    print(t.res)
    assert res == t.res


def test1():
  """checks that cipher.ghash.h is the same as gcm.encrypt(b"", b"", b"")"""
  print("test1")
  key = b"0123456789abcdef"
  cipher = aes_gcm.AesGcm(key)
  c,t = cipher.encrypt(bytes(), bytes(), bytes())
  assert t.hex() == gcm.gf2bytes(cipher.ghash.h).hex()

def test2():
  """Checks that we can get H from a one block encryption when IV = """ ""
  print("test2")
  key = b"0123456789abcdef"
  cipher = aes_gcm.AesGcm(key)
  ct, tag = cipher.encrypt(bytes(), bytes(), bytes([65]*16))
  # Construct quadratic equation a*H^2 + b*H +c = 0
  a = gcm.bytes2gf(ct)
  b = gcm.bytes2gf((128).to_bytes(16, "big")) + gf.F128(1)
  c = gcm.bytes2gf(tag)
  solutions = gf.solve_quadratic(a, b, c)
  assert cipher.ghash.h in solutions

def xor(a,b):
  assert len(a) == len(b)
  return bytes(x ^ y for x, y in zip(a, b))

def test3():
  print("test3")
  key1 = b"0123456789abcdef"
  iv1 = b"0123456789ab"
  iv2 = b"123987198237"
  aad1 = bytes(range(14))
  aad2 = bytes(14)
  msg1 = bytes(range(20))
  msg2 = bytes(20)
  c1 = aes_gcm.AesGcm(key1)
  ct1 = b"".join(c1.encrypt(iv1, aad1, msg1))
  ct2 = b"".join(c1.encrypt(iv1, aad2, msg2))
  ct3 = b"".join(c1.encrypt(iv2, aad1, msg1))
  ct4 = b"".join(c1.encrypt(iv2, aad2, msg2))
  s = xor(xor(ct1, ct2), xor(ct3, ct4))
  assert s == bytes(len(msg1) + 16)


if __name__ == "__main__":
  test_ghash()
  test1()
  test2()
  test3()
