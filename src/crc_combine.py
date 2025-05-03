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

from binascii import crc32
import collections
import os

def combine(a: int, b:int) -> int:
  return crc32(a.to_bytes(4, "little") + b.to_bytes(4, "little"))

def test(u:bytes, v: bytes):
  # Compute two hashes by rearranging the inputs
  c1 = combine(crc32(u), crc32(v+bytes(4)))
  c2 = combine(crc32(v), crc32(u+bytes(4)))
  # Because of properties of CRC32 this always collides.
  assert(c1 == c2)
  
k = 8
u = os.urandom(k)
v = os.urandom(k)
test(u, v)
  
