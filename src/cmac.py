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

from typing import Optional, Union, List
import util

# Known implementations that are currently supported:
# AES-CMAC
# CAMELLIA-CMAC   RFC ????
# ARIA-CMAC       RFC 5794

# Implementations that are not supported (yet),
# mostly because of the lack of a standard or RFC.
# SM4-CMAC   implemented in BouncyCastle
# SEEDMAC    defined in Section 2.4 of RFC 4269
#            (not sure if this is actually CMAC)
# SEED-CMAC  implemented in BouncyCastle.
#            Is this the same as SEEDMAC?
#
# Generalizing CMAC and OMAC to block ciphers with blocks of sizes
# other than 128 bit requires a field of the same size.
# There are a few proposals but so far nothing that can be called
# standardized:
# The paper OMAC: One key-CBC MAC by Iwata and Kurosawa
# proposes to use the lexicographically first irreducible polynomial
# with a minimum number of coefficients. In particular it proposes:
# x^64 + x^4  + x^3 + x + 1 and x^256 + x^10 + x^5 + x^2 + 1
# bouncycastle/crypto/mac/CMac.java defines the polynomials
# for additional sizes.
#
# More stuff is here:
# https://op.dr.eck.cologne/en/theme/crypto_karisik/eax_cmac_problem.shtml

class Poly:

  def __init__(self, coeffs: List[int]):
    assert 0 in coeffs
    self.polynomial = sum(1 << i for i in coeffs)
    self.degree = max(coeffs)
    self.size_in_bytes = (self.degree + 7) // 8

  @util.type_check
  def double(self, b: bytes) -> bytes:
    m = int.from_bytes(b, 'big')
    m <<= 1
    if m.bit_length() > self.degree:
      m ^= self.polynomial
      assert m.bit_length() <= self.degree
    return m.to_bytes(self.size_in_bytes, 'big')

  @util.type_check
  def halve(self, b: bytes) -> bytes:
    m = int.from_bytes(b, 'big')
    if m & 1:
      m ^= self.polynomial
    m >>= 1
    assert m.bit_length() <= self.degree
    return m.to_bytes(self.size_in_bytes, 'big')


POLY_64 = Poly((64, 4, 3, 1, 0))
POLY_128 = Poly((128, 7, 2, 1, 0))
POLY_256 = Poly((256, 10, 5, 2, 0))


# Obsolete: just used for the doc tests
def dbl(block: bytes) -> bytes:
  """Doubles a block.

  Args:
    block: an element of GF(128) represented in big endian order

  Returns:
    The block doubled.

  >>> b = bytearray(range(16))
  >>> dbl(b).hex()
  '00020406080a0c0e10121416181a1c1e'
  >>> b = bytearray([255]*16)
  >>> dbl(b).hex()
  'ffffffffffffffffffffffffffffff79'
  """
  return POLY_128.double(block)


def divide_by_x(block: bytes) -> bytes:
  '''Inverse of dbl
  >>> b = bytearray(range(16))
  >>> divide_by_x(dbl(b)) == b
  True
  >>> b = bytearray([255]*16)
  >>> divide_by_x(dbl(b)) == b
  True
  '''
  return POLY_128.halve(block)


@util.type_check
def _xor(a: bytes, b: bytes) -> bytes:
  assert len(a) == len(b)
  return bytes(x^y for x,y in zip(a,b))

class Cmac:

  def __init__(self,
               cipher,
               macsize: Optional[int] = None,
               poly: Optional[Poly] = None):
    """Constructs a CMAC instance.

    Args:
      cipher: an instance of a block cipher. This must be a cipher with 128-bit
        blocks.
      macsize: the tag size in bytes (default is the size of the block cipher)
      poly: the polynomial for doubling (Default are the polynomials from the
        paper OMAC: One key-CBC MAC by Iwata and Kurosawa
    """
    if macsize is None:
      macsize = cipher.block_size_in_bytes
    if poly is None:
      if cipher.block_size_in_bytes == 8:
        poly = POLY_64
      elif cipher.block_size_in_bytes == 16:
        poly = POLY_128
      elif cipher.block_size_in_bytes == 32:
        poly = POLY_256
      else:
        raise ValueError('Unknown polynomial')
    if poly.degree != 8 * cipher.block_size_in_bytes:
      raise ValueError('Degree of polynomial and block cipher do not match')
    if macsize > cipher.block_size_in_bytes:
      raise ValueError('macsize too large')
    self.poly = poly
    self.cipher = cipher
    self.block_size = cipher.block_size_in_bytes
    self.macsize = macsize
    self.l = self.cipher.encrypt_block(bytes(self.block_size))
    self.k1 = poly.double(self.l)
    self.k2 = poly.double(self.k1)

  @util.type_check
  def mac(self, data: bytes) -> bytes:
    block_size = self.block_size
    blocks = max(1, (len(data) + block_size - 1) // block_size)
    lastblock = len(data) - block_size * (blocks - 1)
    b = bytes(block_size)
    for i in range(blocks - 1):
      b = _xor(b, data[i * block_size:(i + 1) * block_size])
      b = self.cipher.encrypt_block(b)
    ba = bytearray(b)
    for j in range(lastblock):
      ba[j] ^= data[(blocks - 1) * block_size + j]
    if lastblock == block_size:
      b = _xor(bytes(ba), self.k1)
    else:
      ba[lastblock] ^= 0x80
      b = _xor(bytes(ba), self.k2)
    b = self.cipher.encrypt_block(b)
    return b[:self.macsize]

  @util.type_check
  def inverse_mac(self,
                  tag: bytes,
                  head: bytes = b'',
                  tail: bytes = b'') -> bytes:
    '''Finds a block b such that self.mac(head + b + tail) == tag'''
    block_size = self.block_size
    tag = tag + bytes(block_size - len(tag))
    assert len(head) % block_size == 0
    b = bytes(block_size)
    for i in range(len(head) // block_size):
      b = _xor(b, head[i * block_size:(i + 1) * block_size])
      b = self.cipher.encrypt_block(b)
    r = self.cipher.decrypt_block(tag)
    # removed padding:
    tailblocks, rem = divmod(len(tail), block_size)
    if rem == 0:
      r = _xor(r, self.k1)
    else:
      r = bytearray(_xor(r, self.k2))
      r[rem] ^= 0x80
      for i in range(rem):
        r[i] ^= tail[tailblocks * block_size + i]
      r = self.cipher.decrypt_block(bytes(r))
    for i in range(tailblocks -1, -1 ,-1):
      r = _xor(r, tail[i * block_size:(i + 1) * block_size])
      r = self.cipher.decrypt_block(r)
    return _xor(r, b)

class Omac:

  def __init__(self,
               cipher,
               macsize: Optional[int] = None,
               poly: Optional[Poly] = None):
    self.cmac = Cmac(cipher, macsize, poly)
    self.block_size = cipher.block_size_in_bytes

  def mac(self, t: int, ba: bytes) -> bytes:
    b = bytes([0] * (self.block_size - 1) + [t])
    return self.cmac.mac(b + ba)

  def inverse_mac(self,
                  t: int,
                  tag: bytes,
                  head: bytes = b'',
                  tail: bytes = b'') -> bytes:
    b = bytes(self.block_size - 1) + bytes([t])
    return self.cmac.inverse_mac(tag, b + head, tail)

if __name__ == "__main__":
  import doctest
  doctest.testmod()
