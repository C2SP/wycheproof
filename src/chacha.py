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
  return ((a << n) | (a >> (32 - n))) & 0xffffffff


def quarter_round(a: uint32, b: uint32, c: uint32,
                  d: uint32) -> tuple[int, int, int, int]:
  a = (a + b) & 0xffffffff
  d = rotleft32(d ^ a, 16)
  c = (c + d) & 0xffffffff
  b = rotleft32(b ^ c, 12)
  a = (a + b) & 0xffffffff
  d = rotleft32(d ^ a, 8)
  c = (c + d) & 0xffffffff
  b = rotleft32(b ^ c, 7)
  return a, b, c, d


def inner_block(S: State) -> None:
  for (x, y, z, w) in [
      (0, 4, 8, 12),
      (1, 5, 9, 13),
      (2, 6, 10, 14),
      (3, 7, 11, 15),
      (0, 5, 10, 15),
      (1, 6, 11, 12),
      (2, 7, 8, 13),
      (3, 4, 9, 14),
  ]:
    S[x], S[y], S[z], S[w] = quarter_round(S[x], S[y], S[z], S[w])


def bytes2int32(ba: bytes) -> list[uint32]:
  assert len(ba) % 4 == 0
  k = len(ba) // 4
  return [int.from_bytes(ba[4 * i:4 * (i + 1)], "little") for i in range(k)]


@util.type_check
def chacha20_block(key: bytes, nonce: bytes, cnt: int)-> bytes:
  assert len(key) == 32
  assert len(nonce) == 12
  state = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]
  state += bytes2int32(key)
  state += [cnt]
  state += bytes2int32(nonce)
  working_state = state[:]
  for i in range(10):
    inner_block(working_state)
  L = [(x + y) % 2**32 for x, y in zip(working_state, state)]
  return struct.pack("<16L", *L)

@util.type_check
def chacha20_encrypt(key: bytes,
                     counter: int,
                     nonce: bytes,
                     plaintext: bytes)-> bytes:
  return b"".join(
      bytes(x ^ y
            for x, y in zip(
                chacha20_block(key, nonce, (b // 64 + counter) %
                               2**32), plaintext[b:b + 64]))
      for b in range(0, len(plaintext), 64))

chacha20_decrypt = chacha20_encrypt

