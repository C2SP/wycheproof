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
import aes_cmac
import cmac
from typing import Optional
import util

# AesSiv implements
# https://tools.ietf.org/html/rfc5297
#
# The implementation is meant for testing and generating test vectors and
# must not be used otherwise.
# Some of the methods implemented in this class are only used to find
# edge cases, but are not used for production systems. Indeed, some
# of the additional functionality may break the implemented primitive.

dbl = cmac.dbl

def xor(a, b) -> bytes:
  """Allows bytes or generators."""
  return bytes(x ^ y for x, y in zip(a, b))

class AesSiv:
  def __init__(self, key:bytes, tagsize: Optional[int]=None):
    assert len(key) in (32, 48, 64)
    if tagsize:
      assert tagsize == 16
    keylen = len(key) // 2
    self.k1 = key[:keylen]
    self.k2 = key[keylen:]
    self.cmac = aes_cmac.AesCmac(self.k1).mac
    self.aesk2 = aes.AES(self.k2)
    self.tagsize = 16

  # TODO: @util.type_check does not work here,
  #   since there is a mismatch between the number of arguments
  #   and the number of types.
  def s2v(self, plaintext: bytes, *aad) -> bytes:
    d = self.cmac(bytes(16))
    for a in aad:
      d = xor(dbl(d), self.cmac(a))
    if len(plaintext) >= 16:
      plaintext = bytearray(plaintext)
      for i in range(16):
        plaintext[i-16] ^= d[i]
      return self.cmac(bytes(plaintext))
    else:
      d = bytearray(dbl(d))
      for i in range(len(plaintext)):
        d[i] ^= plaintext[i]
      d[len(plaintext)] ^= 0x80
      return self.cmac(bytes(d))

  def s2v_find_plaintext(self, siv, *aad):
    """Returns a plaintext block b such that 
       self.s2v(b, *aad) == siv"""
    r = aes_cmac.AesCmac(self.k1).inverse_mac(siv)
    d = self.cmac(bytes(16))
    for a in aad:
      d = xor(dbl(d), self.cmac(a))
    return xor(d, r)

  def keystream(self, v: bytes):
    q = bytearray(v)
    q[8] &= 0x7f
    q[12] &= 0x7f
    while True:
      for x in self.aesk2.encrypt_block(bytes(q)): yield x
      for i in range(15,-1,-1):
        if q[i] < 255:
          q[i] += 1
          break
        else:
          q[i] = 0

  def ctr_crypt(self, siv: bytes, msg: bytes) -> bytes:
    return xor(msg, self.keystream(siv))

  def encrypt_raw(self, plaintext: bytes, *aad) -> tuple[bytes, bytes]:
    siv = self.s2v(plaintext, *aad)
    return self.ctr_crypt(siv, plaintext), siv

  def decrypt_raw(self, ciphertext: bytes, siv: bytes, *aad) -> bytes:
    assert len(siv) == 16
    p = self.ctr_crypt(siv, ciphertext)
    v = self.s2v(p, *aad)
    if v != siv:
      raise ValueError("Invalid tag")
    return p

  # AEAD interface
  def encrypt(self, nonce:bytes, aad:bytes, msg:bytes) -> tuple[bytes, bytes]:
    return self.encrypt_raw(msg, aad, nonce)

  def decrypt(self, nonce:bytes, aad:bytes, ct:bytes, tag:bytes)-> bytes:
    return self.decrypt_raw(ct, tag, aad, nonce)

  # DAEAD interface
  def encrypt_deterministically(self, aad: bytes, plaintext: bytes) -> bytes:
    ct, siv = self.encrypt_raw(plaintext, aad)
    return siv + ct

  def decrypt_deterministically(self, aad: bytes, ct: bytes) -> bytes:
    assert len(ct) >= 16
    tag, ct = ct[:16], ct[16:]
    return self.decrypt_raw(ct, tag, aad)

