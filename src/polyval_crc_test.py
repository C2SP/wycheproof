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

import crc
import crc_util
import gf
import typing
from dataclasses import dataclass


# Decorator
TESTS = []
def Test(f):
  TESTS.append(f)
  return f

# An element of gf.F128siv
# Currently, I can't specify that this an element of gf.F128siv
FsivElem = gf.Element
FgcmElem = gf.Element


# ======= GHASH =======
def bytes_to_fgcm(ba: bytes) -> FgcmElem:
  """Returns a element of GF(2)[x]/(x^128+x^7+x^4+x^2+x+1) where bytes

     are the coefficient of the element in little endian order.
     The most significant bit of the first byte is the coefficient of x^0.
  """
  n = 0
  for b in ba[::-1]:
    n = n * 256 + inv_byte(b)
  return gf.F128(n)


def inv_byte(b) -> int:
  res = 0
  for i in range(8):
    res = 2 * res + b % 2
    b //= 2
  return res


def fgcm_to_bytes(p: FgcmElem) -> bytes:
  """Converts an element of GF(2^128) into bytes using little endian order

     both for the bits and the bytes.
  """
  poly = p.poly
  res = bytearray(16)
  for i in range(16):
    res[i] = inv_byte(poly % 256)
    poly //= 256
  return bytes(res)


def ghash(h: FgcmElem, b: bytes) -> gf.F128:
  assert len(b) % 16 == 0
  res = gf.F128(0)
  for i in range(0, len(b), 16):
    el = bytes_to_fgcm(b[i:i + 16])
    res = (res + el) * h
  return res


# ====== POLYVAL ======
def bytes_to_fsiv(ba: bytes) -> FsivElem:
  """Returns a element of GF(2)[x]/(x^127 + x^124 + x^121 + x^114 + 1),

     where bytes are the coefficient of the element in little endian order.
     The least significant bit of the first byte is the coefficient of x^0.
  """
  n = 0
  for b in ba[::-1]:
    n = n * 256 + b
  return gf.F128siv(n)


def fsiv_to_bytes(p: FsivElem) -> bytes:
  """Converts an element of GF(2^128) into bytes using little endian order

     both for the bits and the bytes.
  """
  poly = p.poly
  res = bytearray(16)
  for i in range(16):
    res[i] = poly % 256
    poly //= 256
  return bytes(res)


invX128 = gf.F128siv(2).inverse()**128


def dot(a, b):
  return a * b * invX128


def polyval(h: FsivElem, ba: bytes) -> FsivElem:
  """The function POLYVAL described in Section 3 of RFC 8452.

  Args:
    h: the generator
    ba: the bytes to hash
  """
  assert len(ba) % 16 == 0
  s = gf.F128siv(0)
  for i in range(0, len(ba), 16):
    x = bytes_to_fsiv(ba[i:i + 16])
    s = dot(s + x, h)
  return s


def fsiv_to_fgcm(h: FsivElem) -> FgcmElem:
  hbytes = fsiv_to_bytes(h)
  return bytes_to_fgcm(hbytes[::-1])


def fgcm_to_fsiv(h: FgcmElem) -> FgcmElem:
  hbytes = fgcm_to_bytes(h)
  return bytes_to_fsiv(hbytes[::-1])


@Test
def fsiv_to_fgcm_test():
  a = bytes_to_fsiv(b"fedcba0123456789")
  b = bytes_to_fsiv(b"f4d235701dbca798")
  x = gf.F128(2)
  c = fsiv_to_fgcm(dot(a, b))
  c2 = fsiv_to_fgcm(a) * fsiv_to_fgcm(b) * x
  print(fgcm_to_bytes(c).hex())
  print(fgcm_to_bytes(c2).hex())
  assert c == c2


@Test
def test_convert_h():
  hhex = "4bb3e2c2894b90108edc3cde4116355b"
  hsiv = bytes_to_fsiv(bytes.fromhex(hhex))
  hgcm = fsiv_to_fgcm(hsiv) * gf.F128(2)
  hsiv2 = fgcm_to_fsiv(hgcm) * gf.F128siv(2)
  print(hsiv)
  print(hsiv2)
  assert hsiv == hsiv2


def polyval_with_ghash(h: FsivElem, ba: bytes):
  """Computes POLYVAL with GHASH.

  The method is described in Section 3 of RFC 8452.
  """
  assert len(ba) % 16 == 0
  blocks = [ba[j:j+16] for j in range(0, len(ba), 16)]
  inverted = bytes().join(block[::-1] for block in blocks)
  hgcm = fsiv_to_fgcm(h) * gf.F128(2)
  res = ghash(hgcm, inverted)
  return fgcm_to_fsiv(res)

def ghash_with_polyval(h: FgcmElem, ba: bytes):
  """Computes GHASH with POLYVAL.

  The method is the inversion of the method described in Section 3 of RFC 8452.
  """
  assert len(ba) % 16 == 0
  blocks = [ba[j:j+16] for j in range(0, len(ba), 16)]
  inverted = bytes().join(block[::-1] for block in blocks)
  hgcm = fgcm_to_fsiv(h) * gf.F128siv(2)
  res = polyval(hgcm, inverted)
  return fsiv_to_fgcm(res)

@Test
def test_polyval():
  hhex = "4bb3e2c2894b90108edc3cde4116355b"
  m = ("802a78855f7a8cc1fc3c440c759bff57"
       "72cc65bfef192c9c213776296da53946"
       "2a7038301603938baf0fa9764f1f0af1"
       "35fa46c8a305febf75172c3a701fe9a8"
       "71687421a6a4cc5f08a24457d40c27c1"
       "5cd3f26890db62a76555ffe02b801312"
       "14e740ffa48246c2cecb7e21a7f74241"
       "53b2c22f14ff8528d7114f598e08884b")
  expected = "8df9b0d689992b341a45297c384d72cc"
  h = bytes_to_fsiv(bytes.fromhex(hhex))
  res = polyval(h, bytes.fromhex(m))
  reshex = fsiv_to_bytes(res).hex()
  print(expected)
  print(reshex)
  assert reshex == expected


@Test
def test_polyval_with_ghash():
  hhex = "4bb3e2c2894b90108edc3cde4116355b"
  m = ("802a78855f7a8cc1fc3c440c759bff57"
       "72cc65bfef192c9c213776296da53946"
       "2a7038301603938baf0fa9764f1f0af1"
       "35fa46c8a305febf75172c3a701fe9a8"
       "71687421a6a4cc5f08a24457d40c27c1"
       "5cd3f26890db62a76555ffe02b801312"
       "14e740ffa48246c2cecb7e21a7f74241"
       "53b2c22f14ff8528d7114f598e08884b")
  expected = "8df9b0d689992b341a45297c384d72cc"
  h = bytes_to_fsiv(bytes.fromhex(hhex))
  res = polyval_with_ghash(h, bytes.fromhex(m))
  reshex = fsiv_to_bytes(res).hex()
  print(expected)
  print(reshex)
  assert reshex == expected


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


@Test
def test_ghash_with_polyval():
  for t in GHASH_KTV:
    h = bytes_to_fgcm(bytes.fromhex(t.h))
    m = bytes.fromhex(t.inp)
    expected = bytes_to_fgcm(bytes.fromhex(t.res))
    res1 = ghash(h, m)
    res2 = ghash_with_polyval(h, m)
    print("expt", expected)
    print("res1", res1)
    print("res2", res2)
    assert expected == res1
    assert expected == res2

# ========= INTEL intrinsics ========

# Tests implementations of AES-GCM-SIV.
def _pclmulqdq(src1: int, src2: int, imm: int) -> int:
  assert 0 <= src1 < 2**128
  assert 0 <= src2 < 2**128
  assert imm in (0x00, 0x01, 0x10, 0x11)
  if imm & 1:
    inp1 = src1 >> 64
  else:
    inp1 = src1 % 2**64
  if imm & 0x10:
    inp2 = src2 >> 64
  else:
    inp2 = src2 % 2**64
  return gf.bin_mult(inp1, inp2)

@Test
def siv_gcm_reduction(poly:int = None):
  if poly is None:
    poly = 0x11223344556677889900aabbccddeeffff0102030405060708091a1b1c1d1e1f
  assert poly.bit_length() <= 256
  p =  2**128 + 2**127 + 2**126 + 2**121 + 1
  expected = gf.bin_mod(poly, p)
  hi = poly >> 128
  lo = poly % 2**128

  a = 0xb4563df92ea7081b4563df92ea7081b5

  m1 = _pclmulqdq(a, hi, 0x11)
  m2 = _pclmulqdq(a, hi, 0x01)
  m3 = _pclmulqdq(a, hi, 0x10)

  m = m1 ^ hi ^ ((m2 ^ m3) >> 64)
  m_ref = (gf.bin_mult(2**128 + a, hi) >> 128)
  print(hex(m))
  print(hex(m_ref))
  q = p - 2**128
  w_ref = gf.bin_mult(m, p)
  w_ref2 = gf.bin_mult(m, q)
  q1, q0 = divmod(q, 2**64)
  print(hex(q1), hex(q0))
  w_low = m ^ (_pclmulqdq(m, q, 0x10) << 64)
  print('---')
  print(hex(w_low % 2**128))
  print(hex(w_ref % 2**128))
  print(hex(w_ref2 % 2**128))
  print(hex(poly))
  res = w_ref ^ poly
  print(hex(res))
  print(hex(expected))
  assert res == expected

@Test
def siv_gcm_reduction2(poly:int = None):
  if poly is None:
    poly = 0x11223344556677889900aabbccddeeffff0102030405060708091a1b1c1d1e1f
  assert poly.bit_length() <= 256
  p =  2**128 + 2**127 + 2**126 + 2**121 + 1
  expected = gf.bin_mod(poly, p)
  hi = poly >> 128
  lo = poly % 2**128

  a = 0xb4563df92ea7081b4563df92ea7081b5

  m1 = _pclmulqdq(a, hi, 0x11)
  m2 = _pclmulqdq(a, hi, 0x01)
  m3 = _pclmulqdq(a, hi, 0x10)

  m = m1 ^ hi ^ ((m2 ^ m3) >> 64)
  m_ref = (gf.bin_mult(2**128 + a, hi) >> 128)
  print(hex(m))
  print(hex(m_ref))
  q = p - 2**128
  w_ref = gf.bin_mult(m, p)
  w_ref2 = gf.bin_mult(m, q)
  q1, q0 = divmod(q, 2**64)
  print(hex(q1), hex(q0))
  w_low = m ^ (_pclmulqdq(m, q, 0x10) << 64)
  print('---')
  print(hex(w_low % 2**128))
  print(hex(w_ref % 2**128))
  print(hex(w_ref2 % 2**128))
  print(hex(poly))
  res = w_ref ^ poly
  print(hex(res))
  print(hex(expected))
  assert res == expected

@Test
def test_crc32_dot(a:int=None, b:int=None):
  def crc_mm128i(m):
    assert m < 2**128
    hi, lo = divmod(m, 2**64)
    crc = 0xffffffff
    crc = crc_util._mm_crc32_u64(crc, lo)
    crc = crc_util._mm_crc32_u64(crc, hi)
    return crc ^ 0xffffffff

  def crc_mm128i_unconditioned(m):
    assert m < 2**128
    hi, lo = divmod(m, 2**64)
    crc = crc_util._mm_crc32_u64(0, lo)
    return crc_util._mm_crc32_u64(crc, hi)

  def crc_dot(c_a, c_b, m):
    """Computes (a * b) ^ (poly * m) * x^{-128} % crc_poly.

    Args:
      c_a: a % crc_poly
      c_b: b % crc_poly
      m: multiplier in Montgomery reduction
    """
    # 2 times _pclmulqdq
    # 3 times _crc32_u64

    # could be precomputed
    c_b_red = crc_util._mm_crc32_u64(0, c_b)

    # real comp
    c_prod = _pclmulqdq(c_a, c_b_red, 0x00)

    c_poly = 0xe5143e68  # gf.bin_mod(poly_dot, poly_crc)
    m_hi, m_lo = divmod(m, 2**64)
    c_m = crc_util._mm_crc32_u64(0, m_lo) ^ m_hi
    mp = _pclmulqdq(c_m, c_poly, 0x00)  # 96-bits
    mp_hi, mp_lo = divmod(mp, 2**64)

    c_dot = crc_util._mm_crc32_u64(0, c_prod ^ mp_lo) ^ mp_hi
    return c_dot

  poly_dot = 2**128 + 2**127 + 2**126 + 2**121 + 1
  poly_crc = crc.crc32c.poly
  if a is None:
    a = 0xfedcba98765432100123456789abcdef
  if b is None:
    b = 0xf98173ad316bcc121ed3214128273255
  c_a = gf.bin_mod(a, poly_crc)
  c_b = gf.bin_mod(b, poly_crc)

  F = gf.F128siv
  # h = 0x92040000000000000000000000000001  # x^-128

  prod = gf.bin_mult(a, b)
  lo = prod % 2**128
  lo ^= (lo << 127) ^ (lo << 126) ^ (lo << 121)
  lo %= 2**128
  reduced = prod ^ gf.bin_mult(lo, poly_dot)
  dot = reduced >> 128
  c_dot = crc_dot(c_a, c_b, lo)
  print(hex(reduced))
  print(hex(dot))
  print(hex(F(b).dot(F(a)).poly))
  assert c_dot == gf.bin_mod(dot, poly_crc)

if __name__ == "__main__":
  for test in TESTS:
    print('== %s ==' % test.__name__)
    test()
