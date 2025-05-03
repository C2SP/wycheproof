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
import util
import typing

# Reference: draft-krovetz-vmac-01.txt
# Implements a slow version of VMAC.
# Used for test vector generation only.
# Should not be used for production, since some of the methods
# may intentionally implement weak behaviour or skip essential
# checks. Often skipping parameter verification leads to problems.
# This only implements VMAC with AES as cipher and 64 or 128 bit tags.

BLOCKSIZE = 16  # block size of AES in bytes
L1KEYSIZE = 128  # size of the L1 key in bytes

MASK_POLY = 0x1FFFFFFF1FFFFFFF1FFFFFFF1FFFFFFF
P127 = 2 ** 127 - 1
P64  = 2 ** 64 - 257
PP = 2 ** 64 - 2 ** 32

def nh(k, m):
  r'''
  >>> nh([1,2,3,4], [5,6,7,8])
  168
  >>> nh([0,0], [2**64-3, 2**64-1])
  85070591730234615792056675563103846403
  >>> nh([12345, 23456, 2**64-1, 2**63-1], [76543, 65432, 2**64-3, 2**64-5])
  85070591730234615718269699276166716504
  '''
  mask64 = 0xffffffffffffffff
  res = 0
  for i in range(0, len(m), 2):
    res += ((m[i] + k[i]) & mask64) * ((m[i+1] + k[i+1]) & mask64)
  return res & ((1 << 126) - 1)

def as_uint64(ba: bytes) -> typing.List[int]:
  r'''
  >>> as_uint64(bytes(range(32)))
  (283686952306183, 579005069656919567, 1157726452361532951, 1736447835066146335)
  '''
  cnt = len(ba) // 8
  return struct.unpack('>%dQ' % cnt, ba)

class Vmac:
  def __init__(self,
               key: bytes,
               taglength: int,
               accept_faulty_nonces: bool = False):
    """Constructs a VMAC for a given key and tag length.

    Args:
       key: the VMAC key. Since AES is uses as underlying cipher this must be
            either 16, 24 or 32 bytes long.
       taglength: the size of the tag in bits (must be either 64 or 128)
       accept_faulty_nonces: Nonces must be at most 127-bit long. The
            restriction is because the AES block cipher is used for two
            purposes. The first purpose is to derive sub keys. For this purpose
            the msb of the first bytes is always 1. The second purpose is
            the function pdf with the nonce as input. Here the msb of the
            first bytes must be 0."""
    assert taglength in (64, 128)
    self.cipher = aes.AES(key)
    self.taglen = taglength
    self.accept_faulty_nonces = accept_faulty_nonces
    self.offsets = taglength // 64
    self.l1_keys = [None] * self.offsets
    self.l2_keys = [None] * self.offsets
    self.l3_keys = [None] * self.offsets
    for i in range(self.offsets):
      self.l1_keys[i] = self.kdf_int(128, 2 * i, 2 * i + L1KEYSIZE // 8)
      self.l2_keys[i] = self.kdf_int(192, 2 * i, 2 * (i + 1))
    idx = 1
    found = 0
    while found < self.offsets:
      k0, k1 = self.kdf_int(224, 2 * (idx - 1), 2 * idx)
      idx += 1
      if (k0 < P64) and (k1 < P64):
        self.l3_keys[found] = k0, k1
        found += 1
    # keep the index so that we can generate test vectors for different cases
    self.last_idx = idx

  def encrypt_block(self, ba) -> bytes:
    return self.cipher.encrypt_block(ba)

  # TODO: only used by kdf_int
  def kdf(self, index: int, size: int) -> bytes:
    r'''
    >>> vmac = Vmac(b'0123456789abcdef', 128)
    >>> vmac.kdf(1, 32)
    b'\x17\xffF\x1e\x0co8\xc7}\xca\xc5\x8aTJ\xd5\xe9\xa6>\x84\xa99\xc9\x96|B\x0c\xb1\xc0\x15Y?\xf7'
    '''
    if size % BLOCKSIZE > 0:
      return self.kdf(index, size + (-size % BLOCKSIZE))[:size]
    res = bytearray(size)
    inp = bytearray(BLOCKSIZE)
    inp[0] = index
    for i in range(size // BLOCKSIZE):
      inp[-1] = i
      res[BLOCKSIZE * i : BLOCKSIZE * (i+1)] = self.encrypt_block(bytes(inp))
    return bytes(res)

  def kdf_int(self, index: int, start: int, stop: int) -> typing.Sequence[int]:
    '''Computes the key derivation function in the range (8 * start, 8 * stop) and
       converts the result into unsigned 64-bit integers using bigendian ordering'''
    ba = self.kdf(index, 8 * stop)
    return struct.unpack('>%dQ' % (stop - start), ba[8 * start: 8 * stop])

  def pdf(self, nonce: bytes, tagsize: int) -> bytes:
    r'''
    >>> vmac = Vmac(b'0123456789abcdef', 128)
    >>> vmac.pdf(b'12345', 8)
    b'\xf3%\xea"\xfa\xe2\x99\xd1'
    '''
    assert BLOCKSIZE % tagsize == 0
    assert isinstance(nonce, bytes)
    tagsperblock = BLOCKSIZE // tagsize
    index = nonce[-1] % tagsperblock
    block = bytearray(BLOCKSIZE - len(nonce)) + nonce
    block[-1] -= index
    enc = self.encrypt_block(bytes(block))
    return enc[index * tagsize : (index + 1) * tagsize]

  def l1_hash(self, m: bytes, offset: int) -> typing.List[int]:
    r'''
    >>> vmac = Vmac(b'0123456789abcdef', 128)
    >>> vmac.l1_hash(b'x'*200, 0) 
    [39250594795058690859694288774263872712, 13045367440783573705522954400766214409]
    >>> vmac.l1_hash(b'x'*200, 1)  
    [38130957308925659091226731199188593985, 12333347372922997709693305871414499944]
    '''
    assert isinstance(m, bytes)
    # k = self.kdf_int(128, 2 * offset, 2 * offset + L1KEYSIZE // 8)
    k = self.l1_keys[offset]
    blocks = (len(m) + L1KEYSIZE - 1) // L1KEYSIZE
    fullblocks = len(m) // L1KEYSIZE
    y = [None] * blocks
    cnt = L1KEYSIZE // 8
    fmt = '<%dQ' % cnt
    for i in range(fullblocks):
      curpos = i * L1KEYSIZE
      hstr = struct.unpack_from(fmt, m, curpos)
      y[i] = nh(k, hstr)
    if blocks > fullblocks:
      curpos = fullblocks * L1KEYSIZE
      ba = m[curpos : curpos + L1KEYSIZE]
      ba += bytes(-len(ba) % 16)
      cnt = len(ba) // 8
      hstr = struct.unpack('<%dQ' % cnt, ba)
      y[fullblocks] = nh(k, hstr)
    return y

  def l2_hash(self, m: bytes, bitlen: int, offset: int) -> int:
    r'''
    >>> vmac = Vmac(b'0123456789abcdef', 128)
    >>> vmac.l2_hash([1,2,3,4], 1600, 0)
    167367894800334945645447479717713582928
    >>> vmac.l2_hash([1,2,3,4], 1600, 1)
    41204176406347227408381541859716831329
    '''
    t0, t1 = self.l2_keys[offset]
    k = ((t0 & MASK_POLY) << 64) | (t1 & MASK_POLY)
    if len(m) == 0:
      y = k
    else:
      y = 1
      for x in m:
        y = (y * k + x) % P127
    return (y + ((bitlen % (L1KEYSIZE * 8)) << 64)) % P127

  def l3_hash(self, m: int, offset: int) -> int:
    k0, k1 = self.l3_keys[offset]
    m0, m1 = divmod(m, PP)
    # TODO: Generate vectors with 64-bit integer overflow at this point.
    return ((k0 + m0) * (k1 + m1)) % P64

  def vhash(self, m: bytes) -> typing.List[int]:
    y = []
    for offset in range(self.offsets):
      a = self.l1_hash(m, offset)
      b = self.l2_hash(a, 8 * len(m), offset)
      y.append(self.l3_hash(b, offset))
    return y

  @util.type_check
  def tag(self, m: bytes, nonce: bytes) -> typing.List[int]:
    hashedmessage = self.vhash(m)
    pad = self.pdf(nonce, self.taglen // 8)
    padnum = as_uint64(pad)
    return [(x + y) % 2 ** 64 for x,y in zip(padnum, hashedmessage)]

  def mac(self, m: bytes, nonce: bytes) -> bytes:
    if len(nonce) > 16:
      raise ValueError("Nonce too long")
    elif len(nonce) == 16 and nonce[0] >= 128:
      if not self.accept_faulty_nonces:
        raise ValueError("Nonce must be smaller than 128-bits")
    t = self.tag(m, nonce)
    return struct.pack('>%dQ' % len(t), *t)

  def tag_hex(self, m: bytes, nonce: bytes) -> str:
    return self.mac(m, nonce).hex().upper()


def test1():
  # Test vectors from https://tools.ietf.org/html/draft-krovetz-vmac-01
  r'''
  >>> test1()
  'abc' *        0  2576BE1C56D8B81B  472766C70F74ED23481D6D7DE4E80DAC
  'abc' *        1  2D376CF5B1813CE5  4EE815A06A1D71EDD36FC75D51188A42
  'abc' *        2  5828920F0E389036  79D93AB9C6D4C53E6DBAB3B5E343D12E
  'abc' *       16  E8421F61D573D298  09F2C80C8E1007A0C12FAE19FE4504AE
  'abc' *      100  4492DF6C5CAC1BBE  66438817154850C61D8A412164803BCB
  'abc' *      512  D6EEBB132ED66322  F89F63BDE772982AF54D94437780F009
  'abc' *  1000000  09BA597DD7601113  2B6B02288FFC461B75485DE893C629DC
  'abc' * 10000000  5628C32289B680D0  77D96BCD4252B5D86D4E2298ED47EECE
  '''
  key = b'abcdefghijklmnop'
  vmac64 = Vmac(key, 64)
  vmac128 = Vmac(key, 128)
  nonce = b'bcdefghi'
  for i in [0, 1, 2, 16, 100, 512, 1000000, 10000000]:
    inp = b'abc' * i
    a = vmac64.tag_hex(inp, nonce)
    b = vmac128.tag_hex(inp, nonce)
    print("'abc' * %8d  %s  %s" % (i, a, b))

#   ncalls  tottime  percall  cumtime  percall filename:lineno(function)
#   773493    1.583    0.000    1.609    0.000 vmac.py:56(nh)
#       24    0.247    0.010    2.070    0.086 vmac.py:84(l1_hash)
#   773478    0.200    0.000    0.200    0.000 {built-in method _struct.unpack_from}
#       24    0.175    0.007    0.177    0.007 vmac.py:108(l2_hash)
#   775673    0.026    0.000    0.026    0.000 {built-in method builtins.len}
#        1    0.007    0.007    2.267    2.267 vmac.py:174(test1)
#       16    0.005    0.000    2.260    0.141 vmac.py:153(tag)
#      288    0.003    0.000    0.010    0.000 ciphers.py:21(__init__)
#       16    0.003    0.000    2.253    0.141 vmac.py:144(vhash)
def profile():
  from cProfile import run
  run('vmac.test1()', sort=1)

if __name__ == "__main__":
  import doctest
  from time import time
  start = time()
  doctest.testmod()
  print(time() - start)
