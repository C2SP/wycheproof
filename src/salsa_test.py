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

import salsa
import struct

def test():
  inp = [0x00000001, 0x00000000, 0x00000000, 0x00000000,
         0x00000000, 0x00000000, 0x00000000, 0x00000000,
         0x00000000, 0x00000000, 0x00000000, 0x00000000,
         0x00000000, 0x00000000, 0x00000000, 0x00000000]
  out = [0x8186a22d, 0x0040a284, 0x82479210, 0x06929051,
         0x08000090, 0x02402200, 0x00004000, 0x00800000,
         0x00010200, 0x20400000, 0x08008104, 0x00000000,
         0x20500000, 0xa0000040, 0x0008180a, 0x612a8020]
  res = inp[:]
  salsa.inner_block(res)
  assert res == out

  inp = [0xde501066, 0x6f9eb8f7, 0xe4fbbd9b, 0x454e3f57,
     0xb75540d3, 0x43e93a4c, 0x3a6f2aa0, 0x726d6b36,
     0x9243f484, 0x9145d1e8, 0x4fa9d247, 0xdc8dee11,
     0x054bf545, 0x254dd653, 0xd9421b6d, 0x67b276c1]
  out = [0xccaaf672, 0x23d960f7, 0x9153e63a, 0xcd9a60d0,
     0x50440492, 0xf07cad19, 0xae344aa0, 0xdf4cfdfc,
     0xca531c29, 0x8e7943db, 0xac1680cd, 0xd503ca00,
     0xa74b2ad6, 0xbc331c5c, 0x1dda24c7, 0xee928277]
  res = inp[:]
  salsa.inner_block(res)
  assert res == out

  key = bytes(range(1,17)) + bytes(range(201, 217))
  n = bytes(range(101, 117))
  res = salsa.salsa20_block(key, n)
  expected = bytes([
      69, 37, 68, 39, 41, 15,107,193,255,139,122, 6,170,233,217, 98,
      89,144,182,106, 21, 51,200, 65,239, 49,222, 34,215,114, 40,126,
     104,197, 7,225,197,153, 31, 2,102, 78, 76,176, 84,245,246,184,
     177,160,133,130, 6, 72,149,119,192,195,132,236,234,103,246, 74])
  assert res == expected

if __name__ == "__main__":
  test()
