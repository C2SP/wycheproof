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

import poly1305
import os

def collisions(otkey: bytes, block: bytes, n:int, cnt:int):
  a = poly1305.le_bytes_to_int(block)
  p = poly1305.poly1305(otkey, block)
  b = a
  last = a
  while cnt:
    b += 1
    p2 = poly1305.poly1305(otkey, poly1305.int_to_bytes(b))
    if p[:n] == p2[:n]:
      yield b, b - last
      last = b
      cnt -= 1

# performs some test with poly1305
# [522, 131081, 522, 130559, 522, 131081, 522, 130559, 522, 131081, 522, 130559, 522, 131081, 522, 130559]
# [114373, 14208, 114373, 14208, 114373, 14208, 114373, 14208, 114373, 14208, 114373, 14208, 114373, 14208, 114373, 14208]
# [28954, 28954, 177741, 28954, 28954, 28954, 177741, 28954, 28954, 28954, 148787, 28954, 28954, 28954, 177741, 28954]
def test1(otkey=None, block=None):
  if otkey is None:
    otkey = os.urandom(32)
  if block is None:
    block = os.urandom(16)
  L = list(collisions(otkey, block, 2, 16))
  print(poly1305.get_rs(otkey))
  print([diff for b,diff in L])
  otkey2 = otkey[:16] + os.urandom(16)
  L = list(collisions(otkey, block, 2, 16))
  print(poly1305.get_rs(otkey))
  print([diff for b,diff in L])

def test2(otkey=None, block=None, n:int=2):
  if otkey is None:
    otkey = os.urandom(32)
  if block is None:
    block = os.urandom(16)
  a = poly1305.le_bytes_to_int(block)
  p = poly1305.poly1305(otkey, block)[:n]
  for b, diff in collisions(otkey, block, n, 3):
    print()
    for i in range(5):
      p3 = poly1305.poly1305(otkey, poly1305.int_to_bytes(b + i * diff))
      print(i, p3[:n], int.from_bytes(p3[:n], 'little'))
  

if __name__ == "__main__":
  test1()
  test2()


