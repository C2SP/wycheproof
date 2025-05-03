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

# This is an implemention of GMAC for test vector generation.
# The implementation is slow, it doesn't check for invalid inputs and hence
# must not be used for production.
#
# GMAC is an AES-GCM encryption without plaintext and where the AAD is the
# data to MAC. [NIST SP 800-38d, page 2]
# 
# GMAC is implemented by BouncyCastle and keymaster.
#
# The Ecrypt recommendation "D5.4 Algorithms, Key size and protocol report
# (2018) puts GMAC into the legacy category, citing weaknesses.

import aes
import gf
import util

def int2bytes(n:int, cnt:int) -> bytes:
  '''Converts an integer into an array of bytes
     of size cnt using big-endian order.'''
  res = bytearray(cnt)
  for i in range(cnt):
    res[cnt - 1 - i] = n % 256
    n //= 256
  return bytes(res)

def bytes2int(ba:bytes) -> int:
  '''Converts an array of bytes into an integer
     using bigendian order'''
  res = 0
  for b in ba:
    res = 256 * res + b
  return res


def invByte(b):
  res = 0
  for i in range(8):
    res = 2 * res + b % 2
    b //= 2
  return res


def bytes2gf(ba:bytes) -> gf.F128:
  '''Returns a element of GF(2)[x]/(x^128+x^7+x^4+x^2+x+1) where bytes
     are the coefficient of the element in little endian order.
     The most significant bit of the first byte is the coefficient of x^0.'''
  n = 0
  for b in ba[::-1]:
    n = n * 256 + invByte(b)
  return gf.F128(n)

def gf2bytes(p:gf.F128) -> bytes:
  '''Converts an element of GF(2^128) into bytes using little endian order
     both for the bits and the bytes.'''
  poly = p.poly
  res = bytearray(16)
  for i in range(16):
    res[i] = invByte(poly % 256)
    poly //= 256
  return bytes(res)

class Gmac:
  name = "GMAC"
  def __init__(self, block_cipher: type, key:bytes, tagsize:int = 16):
    """Constructs a key GMAC instance

    Args:
      key: the key used for GMAC. It must be 16, 24 or 32 bytes long.
      tagsize: the size of the tag in bytes
    """
    self.key = key
    # a block cipher for the key
    self.E = block_cipher(key)
    zero = bytes(16)
    self.H = bytes2gf(self.E.encrypt_block(zero))
    assert 1 <= tagsize <= 16
    self.tagsize = tagsize

  def get_j0(self, iv: bytes) -> bytes:
    if len(iv) == 12:
      return iv + bytes([0, 0, 0, 1])
    t = iv + bytes(-len(iv) % 16) + int2bytes(len(iv) * 8, 16)
    res = gf2bytes(self.ghash(t))
    return res

  def ghash(self, b: bytes) -> gf.F128:
    assert len(b) % 16 == 0
    res = gf.F128(0)
    for i in range(0, len(b), 16):
      el = bytes2gf(b[i:i+16])
      res = (res + el) * self.H
    return res

  def xor(self, A: bytes, B: bytes) -> bytes:
    return bytes(x^y for x,y in zip(A, B))

  def getIvForCounter(self, j0: bytes) -> bytes:
    '''Returns a 16 byte nonce such that get_j0(IV) == j0'''
    g = bytes2gf(J0)
    iv_len = 128
    l = bytes2gf(int2bytes(iv_len, 16))
    inv = self.H.inverse()
    iv = (g*inv + l)*inv
    res = gf2bytes(iv)
    assert self.get_j0(res) == j0
    return res

  @util.type_check
  def mac(self, nonce: bytes, msg: bytes) -> bytes:
    j0 = self.get_j0(nonce)

    L = int2bytes(len(msg) * 8, 8) + bytes(8)
    pad = bytes(-len(msg) % 16)
    gh = self.ghash(msg + pad + L)
    s = gf2bytes(gh)
    return self.xor(self.E.encrypt_block(j0), s)[:self.tagsize]

  def inverse_mac(self, nonce: bytes, tag: bytes) -> bytes:
    """Returns a message m such that
       self.mac(nonce, msg) == tag"""
    j0 = self.get_j0(nonce)
    # the expected result of ghash
    g = self.xor(tag, self.E.encrypt_block(j0))
    msg_len = 16
    L = int2bytes(msg_len * 8, 8) + bytes(8)
    inv = self.H.inverse()
    m = (bytes2gf(L) * self.H + bytes2gf(g)) * inv * inv
    msg = gf2bytes(m)
    assert self.mac(nonce, msg) == tag
    return msg

class AesGmac(Gmac):
  name = "AES-GMAC"
  block_cipher = aes.AES

  def __init__(self, key:bytes, tagsize:int = 16):
    super().__init__(aes.AES, key, tagsize)

# keyMaterial,
# nonce,
# bytes,
# tag
test_vectors = [
    ( "29d3a44f8723dc640239100c365423a312934ac80239212ac3df3421a2098123",
      "00112233445566778899aabb",
      "aabbccddeeff",
      "2a7d77fa526b8250cb296078926b5020"),
]

def test1():
  '''check test vectors'''
  print('test1')
  for k,n,a,t in test_vectors:
    tag = bytes.fromhex(t)
    mc = Gmac(bytes.fromhex(k), tagsize = len(tag))
    t2 = mc.mac(bytes.fromhex(n), bytes.fromhex(a))
    assert t2 == tag

def test2():
  '''checks that A.H is the same as Gmac.mac(b'', b'')'''
  print('test2')
  key = b'0123456789abcdef'
  A = AesGmac(key)
  t = A.mac(bytes(), bytes())
  assert t.hex() == gf2bytes(A.H).hex()


if __name__ == "__main__":
  test1()
  test2()
