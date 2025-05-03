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

import cmac
from typing import Optional, Tuple
import util

def _xor(a: bytes, b: bytes) -> bytes:
  assert len(a) == len(b)
  return bytes(x ^ y for x, y in zip(a, b))

class Eax:
  @util.type_check
  def __init__(self, block_cipher, key: bytes, tagsize: int = 16):
    if block_cipher.block_size_in_bytes != 16:
      raise ValueError("Not implemented for block sizes != 16")
    if tagsize > 16:
      raise ValueError("Invalid tag size: %d" % tagsize)
    self.E = block_cipher(key)
    # self.omac = Omac(self.E).mac
    self.omac = cmac.Omac(cipher=self.E).mac
    self.tagsize = tagsize

  def _ctr(self, iv: bytes, ba: bytes) -> bytes:
    # make copies of iv and ba
    iv = bytearray(iv)
    res = bytearray(ba)
    for i in range(len(ba)):
      if i % 16 == 0:
        stream = self.E.encrypt_block(bytes(iv))
        for k in range(15, -1 ,-1):
          iv[k] = (iv[k] + 1) & 0xff
          if iv[k]: break
      res[i] ^= stream[i % 16]
    return bytes(res)

  @util.type_check
  def encrypt(self, nonce: bytes, aad: bytes, msg: bytes
             ) -> Tuple[bytes, bytes]:
    N = self.omac(0, nonce)
    H = self.omac(1, aad)
    C = self._ctr(N, msg)
    T = self.omac(2, C)
    tag = _xor(N, _xor(T, H))[:self.tagsize]
    return C, tag

  @util.type_check
  def decrypt(self, nonce: bytes, aad: bytes, ct: bytes, tag: bytes) -> bytes:
    if len(tag) != self.tagsize: return False
    N = self.omac(0, nonce)
    H = self.omac(1, aad)
    T = self.omac(2, ct)
    t2 = _xor(N, _xor(T, H))[:self.tagsize]
    if t2 != tag: return False
    return self._ctr(N, ct)
