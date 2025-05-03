# Copyright 2017 Google Inc. All Rights Reserved.
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
# ==============================================================================
"""AES encryption and decryption for one data block."""

import aes_util
Aes = aes_util.Aes

TESTS = []
def Test(f):
  """Decorator for tests"""
  TESTS.append(f)
  return f

# Maybe better:
# @Invariant
# def AesEncInverse(b: block, rk: block) -> bool:
#   c = aes_util.aes_enc(b, rk)
#   d = aes_util.inverse_aes_enc(c, rk)
#   return b == d

class TestVector(object):
  def __init__(self, key: bytes, plaintext: bytes, ciphertext: bytes):
    self.key = key
    self.plaintext = plaintext
    self.ciphertext = ciphertext

  def __repr__(self):
    args = []
    for v in (self.key, self.plaintext, self.ciphertext):
      args.append("bytes.fromhex(%s)"%repr(v.hex()))
    return "TestVector(%s, %s, %s)"%tuple(args)

encrypt_tests = [
    TestVector(
        bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c"),
        bytes.fromhex("3243f6a8885a308d313198a2e0370734"),
        bytes.fromhex("3925841d02dc09fbdc118597196a0b32")),
    TestVector(
        bytes.fromhex("000102030405060708090a0b0c0d0e0f"),
        bytes.fromhex("00112233445566778899aabbccddeeff"),
        bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")),
    TestVector(
        bytes.fromhex("000102030405060708090a0b0c0d0e0f1011121314151617"),
        bytes.fromhex("00112233445566778899aabbccddeeff"),
        bytes.fromhex("dda97ca4864cdfe06eaf70a0ec0d7191")),
    TestVector(
        bytes.fromhex("000102030405060708090a0b0c0d0e0f1011121314151617"),
        bytes.fromhex("000102030405060708090a0b0c0d0e0f"),
        bytes.fromhex("0060bffe46834bb8da5cf9a61ff220ae")),
    TestVector(
        bytes.fromhex(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
        bytes.fromhex("00112233445566778899aabbccddeeff"),
        bytes.fromhex("8ea2b7ca516745bfeafc49904b496089")),
]

@Test
def testSbox():
  a = bytes(aes_util.sbox_ref(x) for x in range(256))
  assert a == aes_util.sbox0
  b = bytes(aes_util.inverse_sbox_ref(x) for x in range(256))
  assert b == aes_util.sbox1

@Test
def testMixColumns():
  for x, y in [
    ("00000000", "00000000"),
    ("00000001", "01010302"),
    ("01234567", "45ef01ab"),
    ("177af23f", "6dd1d3cf"),
    ("ffffffff", "ffffffff")]:
    assert y == aes_util.mix_columns(bytes.fromhex(x)).hex()
    assert x == aes_util.inverse_mix_columns(bytes.fromhex(y)).hex()
  
@Test
def testAesImc():
  for b in ("00000000000000000000000000000000",
            "00112233445566778899aabbccddeeff",
            "0bced12def89a4567543cba09876f321"):
    d = bytes.fromhex(b)
    a = aes_util.aes_imc_ref(d)
    c = aes_util.aes_imc(d)
    assert a == c
    e = aes_util.aes_mc(a)
    assert e == d

@Test
def testAesEnc():
  for b in ("00000000000000000000000000000000",
            "00112233445566778899aabbccddeeff",
            "0bced12def89a4567543cba09876f321"):
    a = bytes.fromhex(b)
    rk = bytes(range(16))
    c = aes_util.aes_enc(a, rk)
    d = aes_util.aes_enc_ref(a, rk)
    assert c == d
    e = aes_util.inverse_aes_enc(c, rk)
    assert e == a

@Test
def testAesDec():
  for b in ("00000000000000000000000000000000",
            "00112233445566778899aabbccddeeff",
            "0bced12def89a4567543cba09876f321"):
    a = bytes.fromhex(b)
    rk = bytes(range(16))
    c = aes_util.aes_dec(a, rk)
    d = aes_util.aes_dec_ref(a, rk)
    assert c == d
    e = aes_util.inverse_aes_dec(c, rk)
    assert e == a
  
@Test
def testEncryptBlock():
  aes = aes_util.Aes(b"0123456789abcdef")
  msg =  b"0123456789abcdef"
  ct = aes.encrypt_block(msg)
  expected = b"rr~\x88\x1e\xdc\xfd\x01\x00\xa7\x18hy\t\xb5e"
  dec = aes.decrypt_block(expected)
  assert ct == expected
  assert dec == msg

@Test
def testKeySizes():
  for key_size in [16, 24, 32]:
    key = bytes(range(key_size))
    aes = aes_util.Aes(key)
    msg = bytes(range(16, 32))
    ct = aes.encrypt_block(msg)
    dec = aes.decrypt_block(ct)
    assert msg == dec

@Test
def testExpandKeyIntel():
  key = bytes(16)
  ek, dk = aes_util.expand_key(key)
  ek2 = aes_util.expand_key_128_intel(key)
  assert ek == ek2

@Test
def testVectors():
  for test in encrypt_tests:
    cipher = aes_util.Aes(test.key)
    assert test.ciphertext == cipher.encrypt_block(test.plaintext)
    assert test.plaintext == cipher.decrypt_block(test.ciphertext)


@Test
def testTiming():
  # takes about 3.6 sec
  from time import time
  start = time()
  res = bytearray(16)
  for i in range(10000):
    msg = bytes((i >> k) & 0xff for k in range(16))
    for key_size in [16, 24, 32]:
      key = bytes(range(key_size))
      aes = aes_util.Aes(key)
      ct = aes.encrypt_block(msg)
      for i,b in enumerate(ct):
        res[i] ^= b
      dec = aes.decrypt_block(ct)
      assert dec == msg
  print(time() - start)
  print(bytes(res).hex())
  # Just some regression testing
  assert bytes(res).hex() == "ed6aedf1ffd9c74242794f98de8298b9"


if __name__ == "__main__":
  for test in TESTS:
    print(test.__name__)
    test()
  # aes_util.Aes(bytes(range(16))).print_keys()
  # aes_util.Aes(bytes(range(24))).print_keys()

