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

def modify_tag(tag: bytes) -> bytes:
  '''For a given tag this function yields pairs (modified_tag, explanation)'''
  bits = 8 * len(tag)
  # Some of the bit positions in the list below have been chosen because these
  # bits are treated specially in some algorithms:
  #   AES-SIV computes the IV from SIV by modifying bits 71 and 103.
  bitset = sorted(set(x % bits for x in
      [0, 1, 7, 8, 31, 32, 33, 63, 64, 71, 77, 80, 96, 97, 103, -8, -7, -2, -1]))

  for i in bitset:
    mod = bytearray(tag)
    mod[i//8] ^= 1 << (i % 8)
    yield bytes(mod), "Flipped bit %s in tag" % i
  for p in [(0, 64), (31, 63), (63, 127)]:
    if max(p) >= bits: continue
    mod = bytearray(tag)
    for i in p:
      mod[i//8] ^= 1 << (i % 8)
    yield bytes(mod), "Flipped bits %s and %s in tag" % p
  # Some modifications that test for sloppy comparison of tests:
  # bugs such as:
  #   using _mm_testz_si128(tag, computed_tag)
  #   xoring differences instead of or-ing them in time-invariant comparison.
  yield bytes(0xff ^ x for x in tag), "all bits of tag flipped"
  yield bytes(0 for x in tag), "Tag changed to all zero"
  yield bytes(0xff for x in tag), "tag changed to all 1"
  yield bytes(x ^ 0x80 for x in tag), "msbs changed in tag"
  yield bytes(x ^ 1 for x in tag), "lsbs changed in tag"


