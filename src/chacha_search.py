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

import util
from chacha import *
import xchacha_poly1305

# Stuff that is used to search for edge case inputs.
def inverse_quarter_round(a,b,c,d):
  '''ChaCha quarter round
  >>> inp = (0xea2a92f4, 0xcb1cf8ce, 0x4581472e, 0x5881c4bb)
  >>> [hex(x) for x in inverse_quarter_round(*inp)]
  ['0x11111111', '0x1020304', '0x9b8d6f43', '0x1234567']
  '''
  b = rotleft32(b, 25) ^ c
  c = (c - d) & 0xffffffff
  d = rotleft32(d, 24) ^ a
  a = (a - b) & 0xffffffff
  b = rotleft32(b, 20) ^ c
  c = (c - d) & 0xffffffff
  d = rotleft32(d, 16) ^ a
  a = (a - b) % 0xffffffff
  return a,b,c,d

def iqr(S, x, y, z, w):
  S[x], S[y], S[z], S[w] = inverse_quarter_round(S[x], S[y], S[z], S[w])

def inverse_inner_block(state):
  iqr(state, 0, 5,10, 15)
  iqr(state, 1, 6,11, 12)
  iqr(state, 2, 7, 8, 13)
  iqr(state, 3, 4, 9, 14)
  iqr(state, 0, 4, 8, 12)
  iqr(state, 1, 5, 9, 13)
  iqr(state, 2, 6,10, 14)
  iqr(state, 3, 7,11, 15)

def search_fix_points(L=None):
  if L is None:
    S = {0, 1, 2,
         2**7,
         2**8 - 1, 2**8, 2**8 + 1,
         2**15,
         2**16 - 1, 2**16, 2**16 + 1,
         2**24 - 1, 2**24, 2**24 + 1,
         2**31}
    S = S | {-x % 2**32 for x in S}
    L = sorted(S)
  for a in L:
    for b in L:
      for c in L:
        for d in L:
          S = (a,b,c,d)
          T = S
          for i in range(1,11):
            T = quarter_round(*T)
            if T == S:
              print('fixpoint:', S, 'rounds:', i)
              break
  print('fixpoint search done')

def find_large_r(key: bytes, nonce_prefix: bytes = bytes(range(8))):

  def le_bytes_to_int(s: bytes) -> int:
    return sum(c * 256**i for i,c in enumerate(s))

  def int32_to_bytes(c: int)-> bytes:
    res = bytearray(4)
    for i in range(4):
      res[3-i] = c % 256
      c //= 256
    return bytes(res)

  print('key:' + key.hex())
  best = [2**28 - 2**8]*4 + [2**30 - 2**24] + [256] * 4 + [2**24]
  bestidx = [0]*10
  c = 0
  while c < 0xffffffff:
    nonce = nonce_prefix + int32_to_bytes(c)
    r = chacha20_block(key, nonce, 0)[:16]
    r = le_bytes_to_int(r) & 0x0ffffffc0ffffffc0ffffffc0fffffff
    s = 0
    found = False
    for i in range(4):
      r,l = divmod(r, 2**32)
      s += l
      if l > best[i]:
        best[i] = l
        bestidx[i] = c
        found = True
      if l < best[5 + i]:
        best[5 + i] = l
        bestidx[5 + i] = c
        found = True
    if s > best[4]:
      best[4] = s
      bestidx[4] = c
      found = True
    if s < best[9]:
      best[9] = s
      bestidx[9] = c
      found = True
    if found:
      print(c, hex(c))
      print([hex(x) for x in best])
      print([int32_to_bytes(x).hex() for x in bestidx])
    c += 1

def find_large_r_xchacha(key: bytes, nonce_prefix: bytes):
  assert len(key) == 32
  assert len(nonce_prefix) == 20
  print('Xchacha key:', key.hex())
  print('Nonce prefix:', nonce_prefix.hex())
  dkey = xchacha_poly1305.h_chacha20(key, nonce_prefix[:16])
  find_large_r(dkey, bytes(4) + nonce_prefix[16:])

if __name__ == "__main__":
  # search_fix_points()
  find_large_r_xchacha(
      bytes(range(96, 96 + 32)),
      bytes(range(20)))


