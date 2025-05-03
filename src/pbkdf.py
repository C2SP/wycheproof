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

import hashlib
import hmac
import hmac_algorithms
import util
import typing
import test_vector


PBKDF1_SUPPORTED_HASHES = ["MD2", "MD5", "SHA-1"]
PBKDF2_SUPPORTED_HASHES = ["SHA-1", "SHA-256", "SHA-512"]
SUPPORTED_HASHES = sorted(
    set(PBKDF1_SUPPORTED_HASHES + PBKDF2_SUPPORTED_HASHES))

# Implements RFC 2898 for test vector generation.
class PBKDF1:
  def __init__(self, md: str):
    self.md = md
    if md in ("MD2", "MD5"):
      self.digest_size = 16
    elif md == "SHA-1":
      self.digest_size = 20
    else:
      raise ValueError("md not implemented:" + md)

  def __call__(self, p: bytes, s: bytes, c: int, dk_len:int) -> bytes:
    if dk_len > self.digest_size:
      raise ValueError("dk_len larger than the digest size")
    if len(s) != 8:
      raise ValueError("salt size is wrong")
    t = p + s
    for _ in range(c):
      t = util.hash(self.md, t)
    return t[:dk_len]

def _xor(A: bytes, B: bytes) -> bytes:
  if len(A) != len(B):
    raise ValueError('size not equal')
  return bytes(x ^ y for x,y in zip(A, B))

  
class PBKDF2:
  '''Implements PBKDF2 using HMAC'''
  def __init__(self, md: str):
    self.hmac = hmac_algorithms.HmacAlgorithm(md)
  
  def f(self, p: bytes, s: bytes, c: int, i: int) -> bytes:
    def prf(s: bytes) -> bytes:
      h2 = h.copy()
      h2.update(s)
      return h2.digest()
    h = self.hmac.new(p)
    u = prf(s + i.to_bytes(4, 'big'))
    res = u
    for j in range(c - 1):
      u = prf(u)
      res = _xor(res, u)
    return res

  def __call__(self, p: bytes, s: bytes, c: int, dk_len: int) -> bytes:
    digest_size = self.hmac.digest_size
    if dk_len > (2**32 - 1) * digest_size:
      raise ValueError("dk_len too large")
    l = (dk_len + digest_size - 1) // digest_size
    T = b''.join(self.f(p, s, c, j) for j in range(1, l + 1))
    return T[:dk_len]


