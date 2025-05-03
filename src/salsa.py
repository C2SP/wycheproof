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

import struct
import util

# type hints: This is mostly just documentation
uint32 = int
State = tuple[int, ...]

def rotleft32(a: uint32, n: int) -> uint32:
  a &= 0xffffffff
  return ((a << n) | (a >> (32 - n))) & 0xffffffff


def quarter_round(a: uint32, b: uint32, c: uint32,
                  d: uint32) -> tuple[int, int, int, int]:
  b ^= rotleft32(a + d, 7)
  c ^= rotleft32(b + a, 9)
  d ^= rotleft32(c + b, 13)
  a ^= rotleft32(d + c, 18)
  return a, b, c, d


def inner_block(S: State) -> None:
  for (x, y, z, w) in [
      (0, 4, 8, 12),
      (5, 9, 13, 1),
      (10, 14, 2, 6),
      (15, 3, 7, 11),
      (0, 1, 2, 3),
      (5, 6, 7, 4),
      (10, 11, 8, 9),
      (15, 12, 13, 14),
  ]:
    S[x], S[y], S[z], S[w] = quarter_round(S[x], S[y], S[z], S[w])

def make_state(key: bytes, nonce: bytes) -> bytes:
  if len(key) == 16:
    key = key * 2
  elif len(key) != 32:
    raise ValueError("Invalid key size")
  if len(nonce) != 16:
    raise ValueError("Invalid nonce length")
  state = [None] * 16
  key_words = struct.unpack("<8L", key)
  state[0:16:5] = (0x61707865, 0x3320646e, 0x79622d32, 0x6b206574)
  state[1:5] = key_words[0:4]
  state[6:10] = struct.unpack("<4L", nonce)
  state[11:15] = key_words[4:8]
  return state

@util.type_check
def salsa20_block(key: bytes, nonce: bytes)-> bytes:
  state = make_state(key, nonce)
  working_state = state[:]
  for i in range(10):
    inner_block(working_state)
  L = [(x + y) % 2**32 for x, y in zip(working_state, state)]
  return struct.pack("<16L", *L)

@util.type_check
def salsa20_encrypt(key: bytes,
                     counter: int,
                     nonce: bytes,
                     plaintext: bytes)-> bytes:
  s = bytearray()
  for b in range(0, len(plaintext), 64):
    s += salsa20_block(key, nonce + (b//64).to_bytes(8,"little"))
  return bytes(x ^ y for x, y in zip(plaintext, s))

salsa20_decrypt = salsa20_encrypt

