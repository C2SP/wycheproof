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

order = 2**252 + 27742317777372353535851937790883648493
S = set()
# Reduce reduces the output of SHA-512. Hence the largest value that
# might be reduced is 2**512-1
maxval = 2**512-1
for residue in [0, 1, 2, 2**252-1, 2**21, 2**(11*21), 2**252, order-1]:
  for approx in [
    0,
    order,
    2*order,
    2**253,
    2**256,
    order * order - order,
    order * order,
    2**504,
    2**503,
    2**(23*21),
    2**(22*21),
    order * (2**252),
    order * (2**252-1),
    order * (2**252 + 1),
    2**511,
    2**512 - 2**256,
    2**512 - order,
    2**512,
    (-2**256) % order,
    (-2**252) % order,
    (-2**(21*13)) % order, 
    (-2**252) % order * 2**21,
    (-2**252) % order * 2**231,
    (-2**252) % order * 2**252,
    ]:
    r = (approx - approx % order) + residue
    for w in [approx, r - order, r, r + order]:
      if 0 <= w <= maxval:
         S.add(w)

def generate():
  for s in sorted(S):
    sz = (s.bit_length() + 7) // 8
    res = s.to_bytes(sz, 'big').hex()
    L = ['"%s"' % res[i:i+64] for i in range(0,len(res),64)]
    L[-1] += ","
    for i in range(1,len(L)):
      L[i] = "      + " + L[i]
    L[0] = "    " + L[0]
    for x in L:
      print(x)

if __name__ == "__main__":
  generate()

