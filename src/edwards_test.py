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

import edwards

# Note(bleichen): Isomorphisms are tested in xdh_test.py
#   Maybe these tests could be moved here.

def edwards25519Test():
  curve = edwards.edwards25519
  order = 2**252 + 27742317777372353535851937790883648493
  mod = curve.mod
  y = 4 * pow(5, -1, mod) % mod
  B = curve.point_from_y(y)
  Inf = B * order
  assert bool(Inf) == False

def edwards448Test():
  p = 2**448 - 2**224 - 1
  order = (2**446 -
      int("1381806680989511535200738674851542688033669247488217860989454750"
          "3885"))
  # From RFC 7748
  x = int("224580040295924300187604334099896036246789641632564134246125461"
          "686950415467406032909029192869357953282578032075146446173674602635"
          "247710")
  y = int("298819210078481492676017930443930673437544040154080242095928241"
          "372331506189835876003536878655418784733982303233503462500531545062"
          '832660')
  B = edwards.edwards448.point(x,y)
  Inf = B * order
  assert bool(Inf) == False

if __name__ == "__main__":
  VERIFY_POINTS = True
  edwards25519Test()
  edwards448Test()
  VERIFY_POINTS = False
