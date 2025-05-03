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

from cryptography.hazmat.primitives.ciphers.modes import ECB
from cryptography.hazmat.primitives.ciphers.algorithms import TripleDES
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.backends import default_backend

import typing
import util

# Implements TKW for experiments.
#
# The main intent is to show that TKW is too weak to be used.
#
# Reference:
# NIST SP 800-38F
# https://nvlpubs.nist.gov/nistpubs/specialpublications/nist.sp.800-38f.pdf
#
class TKW:
  default_iv = bytes([0xa6])*4

  def __init__(self, key:bytes, rounds=6):
    '''We allow to initilize TKW with less than 6 rounds,
       so that we can do experiments with reduced round TKW.
       For experiments this allows single key DES.'''
    assert len(key) in (8, 16, 24)
    alg = TripleDES(key)
    self.cipher = Cipher(alg, mode=ECB(), backend=default_backend())
    self.rounds = rounds

  def round(self, a:bytes, r:bytes, t:int) -> bytes:
      enc = self.cipher.encryptor()
      c = enc.update(bytes(a + r)) + enc.finalize()
      c = bytearray(c)
      k = 3
      while t and k >= 0:
        c[k] ^= t  & 0xff
        t >>= 8
        k -= 1
      return bytes(c[:4]), bytes(c[4:])

  def inv_round(self, a:bytes, r:bytes, t) -> bytes:
      c = bytearray(a + r)
      k = 3
      while t and k >= 0:
        c[k] ^= t  & 0xff
        t >>= 8
        k -= 1
      dec = self.cipher.decryptor()
      p = dec.update(bytes(c)) + dec.finalize()
      return p[:4], p[4:]

  @util.type_check
  def wrap(self, pt:bytes, iv=None) -> bytes:
    assert isinstance(pt, bytes)
    assert len(pt) % 4 == 0
    if iv is None:
      iv = self.default_iv
    assert isinstance(iv, bytes)
    n = len(pt) // 4
    A = iv
    R = [pt[4*i: 4*(i+1)] for i in range(n)]
    for i in range(self.rounds):
      for t in range(n):
        A, R[t] = self.round(A, R[t], i*n+t+1)
    return A + bytes(x for r in R for x in r)

  @util.type_check
  def unwrap_raw(self, ct:bytes) -> typing.Tuple[bytes, bytes]:
    assert isinstance(ct, bytes)
    assert len(ct) % 4 == 0 and len(ct) >= 4
    n = len(ct) // 4 - 1
    A = ct[:4]
    R = [ct[4*i:4*(i+1)] for i in range(1, n+1)]
    for i in range(self.rounds - 1, -1, -1):
      for t in range(n - 1, -1, -1):
        A, R[t] = self.inv_round(A, R[t], i*n+t+1)
    return A, bytes(x for r in R for x in r)

  @util.type_check
  def unwrap(self, ct:bytes, iv=None) -> bytes:
    tag, R = self.unwrap_raw(ct)
    if iv is None:
      iv = self.default_iv
    assert iv == tag
    return R

test_vectors_tkw = [
  ["0001020304050607080a0a0b0c0d0e0f0011223344556677",
   "00112233445566778899AABBCCDDEEFF",
   'ae420d99ea10b0474677681e45c8c2c60a5a268b'],
  ["000102030405060708090A0B0C0D0E0F1011121314151617",
   "0011223344556677",
   '16277d1db80d82a76de53a76'],
]

def bin(n,m):
  res = 1
  for i in range(m):
    res *= n-i
    res //= i+1
  return res

def getm(rounds, blocks):
  pairs = 2**(32*(rounds-1)) / bin(blocks, rounds - 1)
  return int((2*pairs) ** 0.5)

def exp(rounds=2, n=10, blocks=2**17, keysize=24):
  from time import time
  start = time()
  tab = {}
  key = bytes(range(keysize))
  tkw = TKW(key, rounds=rounds)
  input = byts(4 * blocks)
  for i in range(n):
    t = i
    for k in range(4):
      input[12+k] = t%256
      t >>= 8
    res = tkw.wrap(input)
    idx = str(res[4:12])
    bytes = res[:20].hex()
    if idx in tab:
      print("collision", (i, bytes), tab[idx])
    else:
      tab[idx] = (i, bytes)
  print(time()-start)

def test(debug=False):
  for k,d,res in test_vectors_tkw:
    w = TKW(bytes.fromhex(k))
    wrapped = w.wrap(bytes.fromhex(d))
    if bytes.fromhex(res) != wrapped:
      print(k,d,res, wrapped.hex())
    else:
      unwrapped = w.unwrap(wrapped)
      assert bytes.fromhex(d) == unwrapped

if __name__ == "__main__":
  test()

