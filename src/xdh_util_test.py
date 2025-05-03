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
from typing import List
import time
import xdh_util
import xdh

TESTS = []


def Test(f):
  TESTS.append(f)
  return f


def run_tests():
  for test in TESTS:
    print('----- %s -----' % test.__name__)
    test()


def is_collinear(x1, x2, x3, z3):
  a = 486662
  p = 2**255 - 19
  lhs = 4 * ((x1 + x2 + a) * z3 + x3) * (x1 * x2 * x3)
  rhs = ((x1 * x2 - 1) * z3 + x3 * (x1 + x2))**2
  print(hex(lhs % p))
  print(hex(rhs % p))
  return (lhs - rhs) % p == 0


@Test
def test_multiply_step():
  p = 2**255 - 19
  a24 = 121665
  u = 9
  x2 = 123123
  z2 = 13117823613
  x3 = 11111111
  z3 = 123456789
  T0 = x2, z2, x3, z3
  T = xdh_util.multiply_step(p, a24, u, *T0)
  S = list(xdh_util.inverse_multiply_step(p, a24, u, *T))
  assert T0 in S
  for i, s in enumerate(S):
    print(i, s)


@Test
def test_multiply():
  p = 2**255 - 19
  a24 = 121665
  for k in (13245, 1238164213, 2131313, 12893189241, 1371638713, 16, 17, 127,
            255):
    u = xdh.x25519.point_mult(9, k)
    u2, res = xdh_util.point_mult(p, a24, 9, k)
    assert u == u2
  print('test multiply done')


@Test
def test_inverse_multiply():
  p = 2**255 - 19
  a24 = 121665
  for k in (5, 11, 1234567):
    k -= k % 2
    u2, res = xdh_util.point_mult(p, a24, 9, k)
    state0 = res[0]
    for b, states in xdh_util.inverse_multiply(p, a24, k, 9, *res[0]):
      print('step', b, len(states), res[b] in states)
      assert res[b] in states


# 20 steps: 365 sec   65 sec
# 40 steps:          238 sec
# 50 steps:          338 sec
def benchmark(steps):
  p = 2**255 - 19
  a24 = 121665
  u = 9
  x2 = 123123
  z2 = 13117823613
  x3 = 11111111
  z3 = 123456789
  T0 = (x2, z2, x3, z3)
  T = T0
  for i in range(steps):
    T = xdh_util.multiply_step(p, a24, u, *T)
  S = [T]
  start = time.time()
  for i in range(steps):
    U = []
    for V in S:
      for w in xdh_util.inverse_multiply_step(p, a24, u, *V):
        U.append(w)
    print('step', i, len(U), len(set(U)), time.time() - start)
    S = U
  print('done', T0 in S)


if __name__ == '__main__':
  run_tests()
  # benchmark(10)
