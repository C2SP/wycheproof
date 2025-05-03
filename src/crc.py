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

import gf
import struct

# Sources:
# https://en.wikipedia.org/wiki/Cyclic_redundancy_check
# https://users.ece.cmu.edu/~koopman/crc/crc32.html
# good for: large collection, some analysis
# http://reveng.sourceforge.net/crc-catalogue/17plus.htm
# good for: IVs, references, contains code-words (i.e. inputs with 0 crc)
#
#
#

class Crc:
  def __init__(self, name: str, poly: int, init: int, xorout: int):
    """Defines a CRC algorithm.

    Args:
      name: the name of the algorithm
      poly: the reciprocal polynomial defining the CRC.
      init: the initialization of the CRC
      xorout: added to the state before returning the CRC.
   """
    # Assertions made: (i.e. poly does not need to be irreducible)
    assert poly > 1 and poly % 2 == 1
    assert init >= 0 and init.bit_length() < poly.bit_length()
    assert xorout >= 0 and xorout.bit_length() < poly.bit_length()

    self.name = name
    self.init = init
    self.xorout = xorout
    self.poly = poly

  def __call__(self, ba: bytes) -> int:
    """Computes a CRC.

    Args:
      ba: the bytes form which the CRC is computed
    Returns:
      the CRC as integer."""
    res = self.init
    poly = self.poly
    for by in ba:
      for i in range(8):
        b = (by >> i) & 1
        res ^= b
        if res & 1:
          res ^= poly
        res >>= 1
    res ^= self.xorout
    return res

  def xTo(self, n: int):
    if n < 0:
      h = (self.poly ^ 1) >> 1
      n = -n
    else:
      h = 2
    return gf.bin_exp(h, n, self.poly)

  def logX(self, t):
    poly = self.poly
    if poly.bit_length() > 36:
      raise ValueError("Not implemented")
    tab = {}
    m = 1 << (poly.bit_length() // 2)
    r = 1
    for i in range(m):
      if r == t:
        return i
      tab[r] = i
      r <<= 1
      r = min(r, r ^ poly)
    xm = self.xTo(-m)
    for j in range(1 << ((poly.bit_length() + 1) // 2)):
      if t in tab:
        return tab[t] + j * m
      t = gf.bin_mulmod(t, xm, poly) 

  def _extend(self, crc: int, n: int):
    """Returns crc * x^(-n) % self.poly.

    This is the same as extending an unconditioned CRC by n 0-bits.

    Args:
      crc: a CRC
      n: the number of bits (may be negative)
    Returns:
      the extended CRC."""
    return gf.bin_mulmod(crc, self.xTo(-n), self.poly)

  def zero_bits(self, n: int) -> int:
    """Returns the crc of n zero bits.
    
    Args:
      n : the number of 0 bits
    Returns:
      the CRC
    """
    return gf.bin_mulmod(self.init, self.xTo(-n), self.poly) ^ self.xorout

  def unconditioned(self, ba: bytes):
    return self(ba) ^ self.zero_bits(8 * len(ba))

  def combine(self, crc1: int, crc2: int, bit_len2: int) -> int:
    """Combines to CRCs.

    Args:
      crc1: the crc of a first message m1
      crc2: the crc of a second message m2
      bit_len2: the length of m2 in bits
    Returns:
      The CRC of m1 + m2
    """
    return crc2 ^ self._extend(crc1 ^ self.init ^ self.xorout, bit_len2)

  def repetition(self, crc:int, bit_len: int, n: int) -> int:
    """Computes the CRC of a repeated block.

    Args:
      crc: the CRC of the repeated block
      bit_len: the length of the repeated block in bits.
      n: the number of repetitions
    Returns:
      The CRC of the block repeated n times.
    """
    if n < 0:
      raise ValueError("Negative number of repetitions")
    zero = self(b'')
    res = zero
    mul = self.xTo(-bit_len)
    while True:
      n, rem = divmod(n, 2)
      if rem:
        res = gf.bin_mulmod(res ^ zero, mul, self.poly) ^ crc
      if n == 0:
        return res
      crc = gf.bin_mulmod(crc ^ zero, mul, self.poly) ^ crc
      mul = gf.bin_mulmod(mul, mul, self.poly)
        

  def invert(self, crc_out: int, crc2: int, bit_len2: int) -> int:
    """Finds crc1 such that combine(crc1, crc2, bit_len2) == crc_out.

    Args:
      crc_out: the CRC of part1 || part2
      crc2: the CRC of part2
      bit_len2: the length of part2 in bits.
    """
    return self._extend(crc_out ^ crc2, -bit_len2) ^ self.init ^ self.xorout

  def print_polys(self, exp):
    for e in exp:
      print("x^(%d) = %s" % (e, hex(self.xTo(e))))

  def properties(self) -> str:
    res = []
    res.append("name:%s" % self.name)
    res.append("poly:%s" % hex(self.poly))
    inv_poly = gf.bin_inverse(self.poly, self.poly.bit_length())
    res.append("inv poly:%s" % hex(inv_poly))
    res.append("degree:%d" % (self.poly.bit_length() - 1))
    try:
      field = gf.GF(self.poly)
      res.append("generator:%s" % field.get_generator())
    except ValueError as e:
      # Not all CRC polynomials are irreducible, hence
      # the code above can fail.
      res.append("%s" % e)
    for exp in [32, 64, 128]:
      res.append("x^(-%d) = %s" % (exp, self.xTo(-exp)))
    return "\n".join(res)

# TODO: This is supposed to be the same as crc_hqx
crc16_ccitt_bits = (16, 12, 5, 0)
crc16_ccitt_poly = sum(2**(16-i) for i in crc16_ccitt_bits)
crc16_ccitt = Crc("CRC-CCITT", crc16_ccitt_poly, 0, 0)

crc32_bits = (32, 26, 23, 22, 16, 12, 11, 10, 8, 7, 5, 4, 2, 1, 0)
crc32_poly = sum(2**(32-i) for i in crc32_bits)
crc32 = Crc("CRC-32", crc32_poly, 0xffffffff, 0xffffffff)

# (x + 1) (x^31 + x^30 + x^29 + x^28 + x^26 + x^24 + x^23 + x^21 + x^20 + x^18
#          + x^13 + x^10 + x^8 + x^5 + x^4 + x^3 + x^2 + x + 1) (mod 2)
crc32c_bits = (32, 28, 27, 26, 25, 23, 22, 20, 19, 18, 14, 13, 11, 10, 9, 8, 6, 0)
crc32c_poly = sum(2**(32-i) for i in crc32c_bits)
crc32c = Crc("CRC-32C", crc32c_poly, 0xffffffff, 0xffffffff)

crc64ecma = Crc("CRC-64-ECMA", 0x192D8AF2BAF0E1E85, 0, 0)
crc64iso = Crc("CRC-64-ISO", 0x1B000000000000001, 2**64-1, 2**64-1)

# Just for testing: not irreducible, init and xorout are different
crc_test = Crc("TEST", 0xc241abc31231, 0x1231123412, 0xffff1231)

CRC_LIST = [x for x in globals().values() if isinstance(x, Crc)]

def print_list():
  for crc in CRC_LIST:
    print()
    print(crc.properties())


if __name__ == "__main__":
  print_list()
