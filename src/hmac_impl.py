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

from typing import Optional
import test_vector

def xor(a: bytes, b: bytes):
  assert len(a) == len(b)
  return bytes(x ^ y for x, y in zip(a ,b))


class Hmac(test_vector.Algorithm):
  def __init__(self, md, *,
               name: str,
               block_size: int,
               digest_size: int,
               oid: str):
    self.md = md
    self.block_size = block_size
    self.digest_size = digest_size
    self.opad = bytes([0x5c]) * block_size
    self.ipad = bytes([0x36]) * block_size
    self.name = name
    self.oid = oid
  
  def mac(self, key: bytes, msg: bytes, mac_size: Optional[int]=None):
    if len(key) > self.block_size:
      key = self.md(key)
    k = key + bytes(self.block_size - len(key))
    tmp = self.md(xor(k, self.ipad) + msg)
    digest = self.md(xor(k, self.opad) + tmp)
    if mac_size is None:
      return digest
    if len(digest) < mac_size:
      raise ValueError("mac_size too large")
    return digest[:mac_size]

