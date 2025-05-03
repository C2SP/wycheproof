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

import aes
import struct
import typing
from util import type_check

'''Implements UMAC.

   UMAC is a MAC that requires a nonce for each MAC. It was designed to
   be fast 32-bit CPUs (though it assumes a fast integer multiplication).
   This implementation uses RFC 4418.

   Other variants are not implemented:
   UMAC16, UMAC_STD_30, UMAC_STD_60, UMAC_MMX_15, UMAC_MMX_30, UMAC_MMX_60.
   
   The Ecrypt "D5.4 Algorithms, Key size and protocol report (2018)"
   Section 5.3 recommends to use 64-bit tags.
'''

def _xor(a: bytes, b: bytes) -> bytes:
  '''Returns a bytes string that is the
     bitwise exclusive xor or a and b.'''
  assert len(a) == len(b)
  return bytes(x ^ y for x, y in zip(a, b))

def _and(a: bytes, b: bytes) -> bytes:
  '''Returns a byte string made of the bitwise
     conjunction of a and b'''
  assert len(a) == len(b)
  return bytes(x & y for x, y in zip(a, b))
 
def _zeropad(S: bytes, n) -> bytes:
  '''Pads a byte string with zeros (possibly none) to the
     next multiple of n bytes.'''
  if len(S) == 0:
    return bytes(n)
  else:
    padsize = -len(S) % n
    return S + bytes(padsize)

def _bytes2uint(s: bytes) -> int:
  '''Implements the function str2uint from RFC 4418
  >>> _bytes2uint(bytes([1, 2]))
  258
  '''
  return int.from_bytes(s, byteorder='big')

def _uint2bytes(m: int, n: int) -> bytes:
  '''Implements the function uint2string from RFC 4418.
  >>> _uint2bytes(258, 2).hex()
  '0102'
  >>> x = 1234567
  >>> _bytes2uint(_uint2bytes(x, 8)) == x
  True
  '''
  return m.to_bytes(n, byteorder='big')

class Umac:
  block_cipher = aes.AES
  def __init__(self, key: bytes, tag_size: int, debug: bool = False):
    assert tag_size in (32, 64, 96, 128)
    self.key = key
    self.tagsize = tag_size // 8
    self.BLOCKLEN = self.block_cipher.block_size_in_bytes
    assert self.BLOCKLEN == 16
    self.debug = debug
    # precomputation
    self.pdf_key = self.kdf(0, len(key))
    self.iters = self.tagsize // 4
    self.l1key = self.kdf(1, 1024 + (self.iters-1) * 16)
    self.l2key = self.kdf(2, self.iters * 24)
    self.l3key1 = self.kdf(3, self.iters * 64)
    self.l3key2 = self.kdf(4, self.iters * 4)

  def encipher(self, key:bytes, t: bytes) -> bytes:
    """Encrypts a block of plaintext.

    Args:
      key: the key used for the encryption
      t: the plaintext block to encrypt
    Returns:
      a ciphertext block
    """
    return self.block_cipher(key).encrypt_block(t)

  def prime(self, n:int) -> int:
    '''Returns the largest prime number smaller than 2^n.
       Only values used in Umac are implemented.
       See section 2.2
    '''
    if n == 36:
      return 2 ** 36 - 5
    elif n == 64:
      return 2 ** 64  - 59
    elif n == 128:
      return 2 ** 128 - 159
    else:
      raise ValueError('not implemented')


  def kdf(self, index:int, size:int) -> bytes:
    """The key derivation function.

    Defined in section 3.2.1

    Args:
      key: the key
      index: a non-negative integer less than 2^64
      size: the length of the result in bytes
    """
    n = (size + self.BLOCKLEN - 1) // self.BLOCKLEN
    y = []
    for i in range(1, n + 1):
      t = _uint2bytes(index, self.BLOCKLEN - 8) + _uint2bytes(i, 8)
      t = self.encipher(self.key, t)
      y.append(t)
    return b''.join(y)[:size]

  def pdf(self, nonce: bytes) -> bytes:
    """The PDF algorithm

    Args:
      key: the key
      nonce: the nonce
      taglen: the length of the tag in bytes
    """
    key = self.key
    taglen = self.tagsize
    if taglen in (4, 8):
      index = _bytes2uint(nonce) % (self.BLOCKLEN // taglen)
      nonce = _xor(nonce, _uint2bytes(index, len(nonce)))
    nonce += bytes(self.BLOCKLEN - len(nonce))
    t = self.encipher(self.pdf_key, nonce)
    if taglen in (4, 8):
      offset = index * taglen
      return t[offset: offset + taglen]
    else:
      return t[:taglen]

  def umac(self, m: bytes, nonce: bytes) -> bytes:
    """The UMAC algorithm.

    Defined in Section 4.2.
    Args:
      key: the key
      m: the message
      nonce: the nonce
    """

    key = self.key
    assert 1 <= len(nonce) <= self.BLOCKLEN

    hashed_message = self.uhash(m)
    pad = self.pdf(nonce)
    return _xor(hashed_message, pad)


  def uhash(self, m: bytes) -> bytes:
    taglen = self.tagsize
    iters = self.iters
    y = b''
    for i in range(iters):
      l1key_i = self.l1key[i*16 : i*16 + 1024]
      l2key_i = self.l2key[i*24 : (i+1)*24]
      l3key1_i = self.l3key1[i*64 : (i+1)*64]
      l3key2_i = self.l3key2[i*4 : (i+1)*4]
      a = self.l1hash(l1key_i, m)
      if len(m) <= len(l1key_i):
        b = bytes(8) + a
      else:
        b = self.l2hash(l2key_i, a)
      c = self.l3hash(l3key1_i, l3key2_i, b)
      if self.debug:
        print('l1-hash', a.hex())
        print('l2-hash', b.hex())
        print('l3-hash', c.hex())
      y+= c
    return y

  def l1hash(self, l1key: bytes, m: bytes) -> bytes:
    t = max(1, (len(m) + 1023) // 1024)
    y = b''
    for i in range(t-1):
      m_i = m[i*1024: (i+1)*1024]
      # Does not swap m_i here, since nh expects little endian order.
      val = self.nh(l1key, m_i)
      val = (val + len(m_i) * 8) & 0xffffffffffffffff
      y += _uint2bytes(val, 8)
    m_t = m[(t-1)*1024:]
    len_rem = len(m_t)
    m_t = _zeropad(m_t, 32)
    # Does not swap m_t here, nh expects little endian order.
    val = self.nh(l1key, m_t)
    val = (val + len_rem * 8) & 0xffffffffffffffff
    y += _uint2bytes(val, 8)
    return y

  def nh(self, key: bytes, m: bytes) -> int:
    '''Same as nh in the RFC, but m has not been swapped'''
    y = 0
    assert len(m) % 32 == 0
    assert len(key) == 1024
    t = len(m) // 4
    for i in range(0, t, 8):
      # Converts a message block into integers using little endian
      # order. This is a result of not swapping bytes before calling nh.
      ma = struct.unpack("<IIIIIIII", m[4 * i: 4 * i + 32])
      # Convert the key bytes into integers using big endian order.
      # This is according to the standard.
      ka = struct.unpack(">IIIIIIII", key[4 *i: 4 * i + 32])
      for j in range(4):
        a = (ma[j] + ka[j]) & 0xffffffff
        b = (ma[j+4] + ka[j+4]) & 0xffffffff
        y += a * b
    return y & 0xffffffffffffffff

  def l2hash(self, key: bytes, m: bytes) -> bytes:
    assert len(key) == 24
    mask64  = 0x01ffffff01ffffff
    mask128 = 0x01ffffff01ffffff01ffffff01ffffff
    k64    = _bytes2uint(key[0:8]) & mask64
    k128   = _bytes2uint(key[8:24]) & mask128
    if len(m) <= 2**17:
      y = self.poly(64, 2**64-2**32, k64, m)
    else:
      m1 = m[:2**17]
      m2 = m[2**17:]
      m2 = _zeropad(m2 + bytes([0x80]), 16)
      y = self.poly(64, 2**64 - 2**32, k64, m1)
      y = self.poly(128, 2**128 - 2**96, k128, _uint2bytes(y, 16) + m2)
    return _uint2bytes(y, 16)

  def poly(self,
           wordbits: int,
           maxwordrange: int,
           k: int,
           m: bytes) -> int:
    assert wordbits in (64, 128)
    wordbytes = wordbits // 8
    p = self.prime(wordbits)
    offset = 2**wordbits - p
    marker = p - 1
    n = len(m) // wordbytes
    y = 1
    for i in range(n):
      mi = _bytes2uint(m[i*wordbytes:(i+1)*wordbytes])
      if mi >= maxwordrange:
        y = (k * y + marker) % p
        y = (k * y + (mi - offset)) % p
      else:
        y = (k * y + mi) % p
    return y

  def l3hash(self,
             k1: bytes,
             k2: bytes,
             m: bytes) -> bytes:
    assert len(k1) == 64
    assert len(k2) == 4
    assert len(m) == 16
    y = 0
    p = self.prime(36)
    for i in range(8):
      mi = _bytes2uint(m[2*i: 2*(i+1)])
      ki = _bytes2uint(k1[8*i: 8*(i+1)]) % p
      if self.debug:
        print('l3', i, hex(ki))
      y += mi * ki
    y %= p
    y %= 2**32
    y = _uint2bytes(y, 4)
    y = _xor(y, k2)
    return y

  def tag(self, message: bytes, nonce: bytes) -> bytes:
    return self.umac(message, nonce)

  def tag_hex(self, message:bytes, nonce: bytes) -> str:
    return self.tag(message, nonce).hex().upper()

def testdebug():
  print('debug')
  key = b'abcdefghijklmnop'
  nonce = b'bcdefghi'
  umac64 = Umac(key, 64, debug=True)
  a = umac64.tag_hex(b'abc'*500, nonce)
  print('debug result:', a)

# One test vector in the RFC is wrong. The correct test vector is in the
# errata.
# TODO: There are some missing test cases:
#   - 128-bit tag
#   - message length slightly smaller than a multiple of 1024
#   - message length slightly larger than a multiple of 1024
#   - message length == 2**17
#   - mi == maxwordrange in poly
#   - overflow situations like the one in vmac.
# Other sources that were not used:
# https://www.cosic.esat.kuleuven.be/nessie/testvectors/
def test1():
  r'''
  >>> test1()
  b'a'    *          0 113145FB  6E155FAD26900BE1  32FEDB100C79AD58F07FF764
  b'a'    *          3 3B91D102  44B5CB542F220104  185E4FE905CBA7BD85E4C2DC
  b'a'    *       1024 599B350B  26BF2F5D60118BD9  7A54ABE04AF82D60FB298C3C
  b'a'    *      32768 58DCF532  27F8EF643B0D118D  7B136BD911E4B734286EF2BE
  b'a'    *    1048576 DB6364D1  A4477E87E9F55853  F8ACFA3AC31CFEEA047F7B11
  b'a'    *   33554432 85EE5CAE  FACA46F856E9B45F  A621C2457C0012E64F3FDAE9
  b'abc'  *          1 ABF3A3A0  D4D7B9F6BD4FBFCF  883C3D4B97A61976FFCF2323
  b'abc'  *        500 ABEB3C8B  D4CF26DDEFD5C01A  8824A260C53C66A36C9260A6
  b'a'    *     131071 EEC970DF  91ED6A895DAE75E7  CD06EE347747D35E803C2CB3
  b'abcd' *      32768 C7EECA2C  B8CAD07AB23FF1F1  E42154C798D65748713AB35D
  b'abc'  *      43691 DE426658  A1667C0E84DD5C62  FD8DF8B3AE34FADB5453648A


  '''
  key = b'abcdefghijklmnop'
  umac32 = Umac(key, 32)
  umac64 = Umac(key, 64)
  umac96 = Umac(key, 96)
  nonce = b'bcdefghi'
  for i, s in [(0, b'a'), (3, b'a'), (2**10, b'a'),
               (2**15, b'a'), (2**20, b'a'), (2**25, b'a'),
               (1, b'abc'), (500, b'abc'),
               # additional test cases
               (2**17-1, b'a'),
               (2**15, b'abcd'), # size = 2**17
               (43691, b'abc'), # size = 2**17 + 1
              ]:
    inp = i * s
    a = umac32.tag_hex(inp, nonce)
    b = umac64.tag_hex(inp, nonce)
    c = umac96.tag_hex(inp, nonce)
    print("%-7s * %10d %s  %s  %s" % (s, i, a, b, c))

# Current profile: 12 seconds
#   Ordered by: internal time
#  ncalls  tottime  percall  cumtime  percall filename:lineno(function)
#    205290    8.819    0.000   11.026    0.000 umac.py:189(nh)
#  13136868    2.128    0.000    2.128    0.000 {built-in method _struct.unpack}
#        66    0.618    0.009   11.910    0.180 umac.py:174(l1hash)
#    205290    0.126    0.000    0.266    0.000 umac.py:52(_add)
#    567868    0.073    0.000    0.122    0.000 umac.py:35(_bytes2uint)
#    416048    0.056    0.000    0.097    0.000 umac.py:42(_uint2bytes)
#        48    0.052    0.001    0.080    0.002 umac.py:227(poly)
def profile():
  from time import time
  from cProfile import run
  start = time()
  run('test1()', sort=1)
  print(time() - start)

if __name__ == "__main__":
  import doctest
  testdebug()
  profile()
  doctest.testmod()
  print('-done-')

