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

import binascii
import crc
import gf
import os
import struct

# Decorator
TESTS = []
def Test(f):
  TESTS.append(f)
  return f

# An invariant is a function that must pass with valid inputs
# of the given type.
INVARIANTS = []
def Invariant(f):
  INVARIANTS.append(f)
  return f

def assert_equal(a, b):
  if a != b:
    print(a)
    print(b)
  assert a == b

@Test
def test_crc32c_block():
  inp = bytes(range(8, 16))
  poly = crc.crc32c.poly
  block = struct.unpack("<Q", inp)[0]
  crc1 = crc.crc32c(inp)
  h = poly >> 1
  s = gf.bin_mult(0xffffffff, gf.bin_exp(h, 0, poly))
  s ^= gf.bin_mult(0xffffffff, gf.bin_exp(h, 64, poly))
  s ^= gf.bin_mult(block, gf.bin_exp(h, 64, poly))
  crc2 = gf.bin_mod(s, poly)
  print(hex(crc2), hex(crc1))
  assert crc2 == crc1

@Test
def test_compat(ba: list[bytes] = None) -> int:
  if ba is None:
    ba = [b"xyz",
          b"1jk24h12kj31"]
  COMPAT_LIST = [
    (crc.crc32, binascii.crc32),
   # (crc.crc16_ccitt, lambda data:binascii.crc_hqx(data, 0xffff)),
  ]
  for crc1, crc2 in COMPAT_LIST:
    print(crc1.name)
    for v in ba:
      a = crc1(v)
      b = crc2(v)
      print(v, hex(a), hex(b))
      assert a == b

@Test
def test_modify():
  ba = os.urandom(34)
  crc1 = binascii.crc32(ba)
  bb = bytearray(ba)
  for i in crc.crc32_bits:
    bb[32-i] ^= 27
  crc2 = binascii.crc32(bytes(bb))
  assert crc1 == crc2

@Test
def test_combine():
  a = b"129817234091k3j1"
  b = b"kl;35hafdpq3l12j351iph3515"
  for crc1 in crc.CRC_LIST:
    crc_a = crc1(a)
    crc_b = crc1(b)
    crc_c = crc1(a+b)
    crc_d = crc1.combine(crc_a, crc_b, len(b)*8)
    print(crc1.name, hex(crc_c), hex(crc_d))
    assert crc_c == crc_d
    crc_e = crc1.invert(crc_c, crc_b, len(b)*8)
    print(crc1.name, hex(crc_a), hex(crc_e))
    assert crc_a == crc_e

@Test
def test_repetition():
  a = b"abcdef"
  for crc1 in crc.CRC_LIST:
    for reps in [0, 1, 2, 3, 7, 15, 32, 71, 101]:
      crc_a = crc1(a*reps)
      crc_b = crc1.repetition(crc1(a), 8*len(a), reps)
      assert crc_a == crc_b

@Test
def test_substr():
  s = b"12983719847192378kjqwhekjh2131"
  a = 5
  b = 11
  for crc_alg in crc.CRC_LIST:
    crc1 = crc_alg(s[a:b])
    crc_a = crc_alg(s[:a])
    crc_b = crc_alg(s[:b])
    crc2 = crc_alg.combine(crc_a, crc_b, (b - a)*8)
    assert crc1 == crc2

def inverted(n, bits):
  res = 0
  for i in range(bits):
    res = (res << 1) + n % 2
    n //= 2
  assert n == 0
  return res

TEST_VECTORS = [
  # CRC16-CCITT uses inverted bit order (just not when this inversion takes place).
  # (crc.crc16_ccitt, b"123456789", inverted(0x29b1, 16)),
  (crc.crc32, b"123456789", 0xcbf43926),
]

@Test
def test_vectors():
  errors = 0
  for c, inp, expected in TEST_VECTORS:
    res = c(inp)
    print(c.name, hex(res), hex(expected))
    errors += res != expected
  assert errors == 0

@Test
def test_zero_bits():
  for crc_alg in crc.CRC_LIST:
    for sz in [0, 1, 2, 7, 16]:
      crc1 = crc_alg(bytes(sz))
      crc2 = crc_alg.zero_bits(8 * sz)
      assert crc1 == crc2


if __name__ == "__main__":
  for test in TESTS:
    print("== %s ==" % test.__name__)
    test()

