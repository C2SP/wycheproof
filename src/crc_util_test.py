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
import crc_util
import crc

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

xmm = 'xmm'

def assert_equal(a, b):
  if a != b:
    print(a)
    print(b)
  assert a == b

@Test
def test_pseudo_multiply():
  a = 0x12345678
  b = 0x1122334455667788
  c = crc_util.pseudo_multiply(a, b)
  print('pseudo_multiply')
  print('a', hex(a))
  print('b', hex(b))
  print('res', hex(c))
  d = gf.bin_mulmod(a, b, crc.crc32c.poly)
  d2 = gf.bin_mulmod(c, 1 << 64, crc.crc32c.poly)
  assert d == d2


@Test
def test_crc32c_rollback64():
  crc_in = 0x12345678
  blk = 0x1122334455667788
  const1 = gf.bin_mod(1 << 64, crc.crc32c.poly)
  const2 = gf.bin_mod(1 << 128, crc.crc32c.poly)
  print('const1:', hex(const1))
  print('const2:', hex(const2))
  print('crc_in:', hex(crc_in))
  print('blk:', hex(blk))
  crc_out = crc_util.pseudo_multiply(blk, const1) ^ crc_util.pseudo_multiply(crc_in, const2)
  print('crc_out:', hex(crc_out))
  assert crc_util._mm_crc32_u64(crc_out, blk) == crc_in

@Test
def test_intrinsics():
  assert 0x493c7d27 == crc_util._mm_crc32_u64(0x0, 0x1)
  assert 0x493c7d27 == crc_util._mm_crc32_u64(0x1, 0x0)
  assert 0xc44ff94d == crc_util._mm_crc32_u64(0x0, 0xffffffffffffffff)
  assert 0x0 == crc_util._mm_crc32_u64(0x12345678, 0x12345678)

@Test
def test_crc32c_clmul():
  nblocks = 8
  nbytes = nblocks * 8
  nbits = 8 * nbytes
  poly = crc.crc32c.poly
  inp = bytes(range(nbytes))
  inp = bytes(nbytes)
  # little endian order
  blocks = struct.unpack("<%dQ" % nblocks,inp)
  h = poly >> 1
  s = gf.bin_mult(0xffffffff, gf.bin_exp(h, nbits, poly))
  for j,b in enumerate(blocks):
    m = nblocks - 1 - j
    s ^= gf.bin_mult(b, gf.bin_exp(h, m * 64, poly))
  s ^= 0xffffffff
  crc_clmul = gf.bin_mod(s, poly)
  crc2 = crc.crc32c(inp)
  print(hex(crc2), hex(crc_clmul))
  assert crc2 == crc_clmul

@Test
def test_crc32c_clmul2():
  nblocks = 12
  nbytes = nblocks * 8
  nbits = 8 * nbytes
  poly = crc.crc32c.poly
  inp = bytes(range(1,1+nbytes))
  inp = bytes(nbytes)
  # little endian order
  blocks = struct.unpack("<%dQ" % nblocks,inp)
  h = poly >> 1
  s = gf.bin_mult(0xffffffff, gf.bin_exp(h, nbits - 128, poly))
  for j,b in enumerate(blocks[:-2]):
    m = nblocks - 3 - j
    s ^= gf.bin_mult(b, gf.bin_exp(h, m * 64, poly))
  s ^= blocks[-2]
  s ^= blocks[-1] << 64
  crc_clmul = crc_util.crc_m128i(s) ^ 0xffffffff
  crc2 = crc.crc32c(inp)
  print(hex(crc2), hex(crc_clmul), hex(crc2 ^ crc_clmul))
  assert crc2 == crc_clmul

@Test
def test_crc32_montgomery_mult(x: int = None, m: int = None):
  print("== test_crc32_montgomery_mult ==")

  if x is None:
    x = 0x12345678
  if m is None:
    m = 0x72746123

  poly = crc.crc32c.poly
  assert x.bit_length() <= 32
  assert m.bit_length() <= 32
  expected_result = gf.bin_mulmod(x, m, poly)
  m_montg = gf.bin_mod(m << 32, poly)
  invpoly = gf.bin_inverse(poly, 32)
  lb = gf.bin_mult(m_montg, invpoly) % 2**32
  const1 = (m_montg << 32) ^ lb
  print('const1:', hex(const1))

  # Normal way:
  tmp = gf.bin_mult(x, m_montg)
  a = gf.bin_mult(tmp, invpoly) % 2**32
  b = tmp ^ gf.bin_mult(a, poly)
  print(hex(b))
  result1 = b >> 32
  print(hex(expected_result), hex(result1))

  # Multiplication folding.
  tmp1 = gf.bin_mult(x, const1)
  tmp2 = gf.bin_mult(tmp1 % 2**32, poly)
  result2 = (tmp1 >> 64) ^ (tmp2 >> 32)
  print(hex(expected_result), hex(result2))
  assert expected_result == result1
  assert expected_result == result2

@Test
def test_uint64_reduce():
  poly = crc.crc32c.poly
  for a in [0, 1241241231, 0xfedcba9876543210,
            0x0123456789abcdef]:
    assert gf.bin_mod(a, poly) == crc_util.uint64_reduce(a)

@Test
def test_crc32_update_shortcuts():
  crc_in = 0xfedcba91
  block = 0xfe322d357212345f
  for bits in range(65):
    a = crc_util.crc32c_update(crc_in, block % 2**bits, bits)
    b = crc_util.crc32c_update_shortcuts(crc_in, block % 2**bits, bits)
    if a!=b:
      print(bits, hex(a), hex(b))
      assert False

@Invariant
def invariant_crc_m128i(a: xmm):
  c = crc_util.crc_m128i(a)
  poly = crc.crc32c.poly
  h = poly >> 1
  m = gf.bin_exp(h, 128, poly)
  r = gf.bin_mulmod(a, m, poly)
  assert_equal(hex(c), hex(r))

@Test
def test_crc_m128i():
  a = 0x00112233445566778899aabbccddeeff
  invariant_crc_m128i(a)

@Invariant
def invariant_crc_xmm_product(a: xmm, b: xmm):
  poly = crc.crc32c.poly
  p = gf.bin_mult(a, b)
  ca = crc_util.crc_m128i(a)
  cb = crc_util.crc_m128i(b)
  cp = crc_util.crc_m256i(p)
  c2 = gf.bin_mulmod(ca, cb, poly)
  assert_equal(hex(cp), hex(c2))

@Test
def test_crc_xmm_prod():
  a = 0x00112233445566778899aabbccddeeff
  b = 0xf0123456789abcdef012345789abcdef
  invariant_crc_xmm_product(a, b)


@Test
def test_montgomery_reduce():
  a = 0x00112233445566778899aabbccddeeff
  b = 0xf0123456789abcdef012345789abcdef
  p = 0x1c2000000000000000000000000000001
  res1 = crc_util.montgomery_reduce_ref(a,b,p)
  res2 = crc_util.montgomery_reduce(a,b,p)
  assert_equal(hex(res1),hex(res2))

@Invariant
def invariant_montgomery_reduce_crc(a: xmm, b: xmm, poly:int):
  p = (a << 128) ^ b
  crc_in = crc_util.crc_m256i(p)
  res, crc_diff = crc_util.montgomery_reduce_crc(a, b, poly)
  crc_out = crc_util.crc_m128i(res)
  assert_equal(hex(crc_in ^ crc_out), hex(crc_diff))  

@Test
def test_crc_montgomery_reduce_crc():
  a = 0x00112233445566778899aabbccddeeff
  b = 0xf0123456789abcdef012345789abcdef
  p = 0x1c2000000000000000000000000000001
  invariant_montgomery_reduce_crc(a, b, p)

@Invariant
def invariant_montgomery_reduce_crc_diff(a: xmm, b: xmm, poly:int, diff:xmm):
  crc_poly = crc.crc32c.poly
  p = (a << 128) ^ b
  crc_in = crc_util.crc_m256i(p)
  # Computes montgomery_reduce_crc with an error diff in the computation
  # of m.
  res, crc_diff = crc_util.montgomery_reduce_crc_diff(a, b, poly, diff)
  crc_out = crc_util.crc_m128i(res)
  # Without an error in the compution of m, the value error should be 0.
  error = crc_out ^ crc_in ^ crc_diff
  # dm is the value that is truncated in the computation of res, but that
  # is included in the computation of crc_diff.
  dm = gf.bin_mult(diff, poly) % 2**128
  expected_error = crc_util.crc_m256i(dm)
  assert_equal(hex(error), hex(expected_error))

@Test
def test_crc_montgomery_reduce_crc_diff():
  a = 0x00112233445566778899aabbccddeeff
  b = 0xf0123456789abcdef012345789abcdef
  p = 0x1c2000000000000000000000000000001
  for diff in (0, 1, 2, 3,  crc.crc32c.poly):
  #  diff = 0xffeeddccbbaa01234567890123456789
    invariant_montgomery_reduce_crc_diff(a, b, p, diff)

@Test
def test_crc32c_extend_128x():
  L = [
      0x00000000000000000000000000000000,
      0x00112233445566778899aabbccddeeff,
      0xffeeddccbbaa99887766554433221100,
      0xf0123456789abcdef012345789abcdef,
      0x7816487126bcd133876487162387f163,
      0x17164887126478123618738172378772,
      0x00000000000000000000000000000000,
      0xffffffffffffffffffffffffffffffff,
      0x55555555555555555555555555555555]
  prefix = b'123'
  crc_prefix = crc.crc32c(prefix)
  for i in range(len(L)+1):
    L0 = L[:i]
    b = b''.join(x.to_bytes(16, 'little') for x in L0)
    crc1 = crc.crc32c(prefix + b)
    crc2 = crc_util.crc32c_extend_128x(crc_prefix, L0)
    assert crc1 == crc2

GCM_STREAM_TESTS = [
    ('00000000000000000000000000000001', 0, 0x0),
    ('18723648761231872361241200000001', 0, 0x0),
    ('12873684761237816487123761287320', 0, 0x0),
    ('18276381726418726387126300000001', 1, 0x7bb7810f),
    ('98126784617836123123123200000001', 2, 0x38da72b5),
    ('19823612486123871263123100000001', 3, 0x228ad19b),
    ('00000000000000000000000000000001', 4, 0x28ec8f72),
    ('0001020304050607090a0b0c00000001', 4, 0x1659511b),
    ('ffffffffffffffffffffffff00000001', 5, 0x81ebe8f0),
    ('19823612486123871263123100000001', 3, 0x228ad19b),
    ('817248986718264b212386f200000001', 15, 0x9a7e8c29),
    ('891261daa12301741237721100000001', 253, 0xa84216ff),
    ('891261daa12301741237721100000001', 254, 0x1a9d13ee),
    ('891261daa12301741237721100000001', 255, 0x47f6e921),
    ('000102030405060708090a0b00000001', 256, 0x8729ec09),
    ('000102030405060708090a0b00000001', 257, 0x7886ecbd),
    ('891261daa12301741237721100000001', 509, 0x75def39c),
    ('891261daa12301741237721100000001', 510, 0xb703bba1),
    ('891261daa12301741237721100000001', 511, 0x5606b9b1),
    ('000102030405060708090a0b00000001', 512, 0x3f6b937a),
    ('000102030405060708090a0b00000001', 513, 0x7dad8c59),
    ('891261daa12301741237721100000001', 1021, 0xed286ee6),
    ('891261daa12301741237721100000001', 1022, 0x5ebe26d5),
    ('000102030405060708090a0b00000001', 1023, 0x19739867),
    ('000102030405060708090a0b00000001', 1024, 0x6b21e955),
    ('000102030405060708090a0b00000001', 1025, 0x21b5d560),
    ('000102030405060708090a0b00000001', 65533, 0x89b386dd),
    ('000102030405060708090a0b00000001', 65534, 0xf464ac25),
    ('000102030405060708090a0b00000001', 65535, 0x644c1266),
    ('000102030405060708090a0b00000001', 65536, 0x285a9a5c),
    ('000102030405060708090a0b00000001', 65537, 0x928fda8a),
    ('000000000000000000000000ffffffff', 15, 0x686b94b3),
    ('ffffffffffffffffffffffffffffffff', 15, 0x62a37a4e),
    ('fffffffffffffffffffffffffffffffe', 1, 0xef2f4c10),
    ('fffffffffffffffffffffffffffffffe', 15, 0xb82a5cc3),
    ('fffffffffffffffffffffffffffffffd', 15, 0x5b39a8dc),
    ('fffffffffffffffffffffffffffffff0', 255, 0x4d9e723b),
    ('ffffffffffffffffffffffffffffff00', 255, 0x4d6da634),
    ('ffffffffffffffffffffffffffffff00', 255, 0x4d6da634),
    ('fffffffffffffffffffffffffffffe10', 1023, 0x537a60ae),
    ('817239a16018236871d36876487678ff', 65535, 0xf4a54743),
    ('9817aa4e9874981b62387612d78dc110', 0x1ffff, 0x181aa008),
    ('18923764123198748731983718923121', 1193046, 0x4fc2c52a),
    ('9817aa4e9874981b6238761200000001', 131071, 0x8fe9e12d),
    ('0123456789abcdef0123456700000001', 349525, 0x33878b35),
    ('18923764123198748731983700000001', 1193046, 0xb9a4dacc),
    ('fedcba9876543210fedcba9800000001', 3355443, 0x5096a173),
    ('18236874618736187361876300000001', 19088743, 0x8fc53df),
    ('ffffffffffffffffffffffff00000001', 591751049, 0xaab49d16),
    ('10000000000000000000000000000001', 2147483648, 0x531374a7),
    ('fffffffffffffffffffffffe00000001', 2147483647, 0xe3b3faef),
    ('19823618746172318313112300000001', 1234567890, 0x5c30ad06),
    ('81831746187368716317831300000001', 4042322160, 0x22f4a79),
    ('81237984adf131314aa0132200000001', 4278190335, 0xb5b7fe96),
    ('12896417687618723618731300000001', 4294967293, 0x21b7be29),
    ('13764871683671827361873600000001', 4294967294, 0x1df94521),
    ('ffffffffffffffffffffffff00000001', 4294967294, 0x1df94521),
    ('10000000000000000000000000000001', 4294967294, 0x1df94521),
]

@Test
def test_gcm_stream(skip=50000):
  for j0, blocks, expected in GCM_STREAM_TESTS:
    if expected is not None and blocks > skip:
      continue
    if blocks > 10000000:
      continue
    crc = crc_util.crc32c_gcm_stream_ref(bytes.fromhex(j0), blocks)
    if expected is None:
      print(f"    ({repr(j0)}, {blocks}, {hex(crc)}),")
    else:
      assert crc == expected

@Test
def test_gcm_12byte_nonce_small():
  errors = 0
  nonce = bytes(range(12))
  for blocks in range(300):
    res1 = crc_util.crc32c_12byte_nonce_ref(nonce, blocks)
    res2 = crc_util.crc32c_12byte_nonce(nonce, blocks)
    if res1 != res2:
      print(blocks, hex(res1), hex(res2))
      errors += 1
  assert errors == 0

@Test
def test_gcm_12byte_nonce():
  errors = 0
  for (j0, blocks, expected) in GCM_STREAM_TESTS:
    ctr = bytes.fromhex(j0)
    if ctr[12:] == bytes.fromhex('00000001'):
      nonce = ctr[:12]
      crc_computed = crc_util.crc32c_12byte_nonce(nonce, blocks)
      if expected is None:
        print(f"    ({repr(j0)}, {blocks}, {hex(crc)}),")
      elif crc_computed !=expected:
        print(crc_computed, expected)
        errors += 1
  assert errors == 0

@Test
def test_gcm_12byte_nonce_incremental():
  nonce = bytes(range(12))
  ranges = [(2**i - 5, 2**i + 4) for i in range(3, 32)]
  ranges += [(m - 5, m + 4) for m in 
              [0xffff0000, 0xff00ff00, 0xf0f0f0f0, 0x55555555,
               0xbbbbbbbb, 0x99999999, 0x33333333]]
  ranges += [(2**32 - 5, 2**32 - 1)]
  for start, stop in ranges:
    crc0 = crc_util.crc32c_12byte_nonce(nonce, start)
    for i in range(start + 1, stop):
      crc1 = crc_util.crc32c_12byte_nonce(nonce, i)
      crc_last = crc.crc32c(nonce + (i + 1).to_bytes(4, 'big'))
      expected = crc.crc32c.combine(crc0, crc_last, 128)
      assert crc1 == expected
      crc0 = crc1

@Test
def test_string_splitter():
  css = crc_util.CrcStringSplitter(bytes(range(253)))
  while css:
    block, crc = css.split_off_prefix(16)

  css = crc_util.CrcStringSplitter(bytes(range(253)))
  while css:
    block, crc = css.split_off_8byte_prefix()

if __name__ == "__main__":
  from time import time
  for test in TESTS:
    print('== %s ==' % test.__name__)
    start = time()
    test()
    print(time() - start)

