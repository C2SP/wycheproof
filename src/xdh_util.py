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
import mod_arith
import util
from typing import List
import poly


def moddiv(a, b, p):
  return a * pow(b, -1, p) % p


def multiply_step(p, a24, x_1, x_2, z_2, x_3, z_3):
  """Performs a step of XDH.

  Assumes that x2/z2, x3/x3 are the x-coordinates of
  two points r = k*u and s =(k+1) * u
  Returns 2*r and r+s
  """
  A = (x_2 + z_2) % p
  AA = A**2 % p
  B = (x_2 - z_2) % p
  BB = B**2 % p
  E = (AA - BB) % p
  C = (x_3 + z_3) % p
  D = (x_3 - z_3) % p
  DA = D * A % p
  CB = C * B % p
  x_3 = (DA + CB)**2 % p
  z_3 = x_1 * (DA - CB)**2 % p
  x_2 = AA * BB % p
  z_2 = E * (AA + a24 * E) % p
  return x_2, z_2, x_3, z_3


def point_mult(p, a24, u, k):
  return multiply(p, a24, k, u, 1, 0, u, 1)


def multiply(p, a24, k, x_1, x_2, z_2, x_3, z_3):
  # Keeps the intermediate results
  res = {}
  bits = k.bit_length()
  swaps = k ^ (k << 1)
  res[bits] = (x_2, z_2, x_3, z_3)
  for b in range(bits - 1, -1, -1):
    swap = swaps >> (b + 1) & 1
    if swap:
      x_2, x_3 = x_3, x_2
      z_2, z_3 = z_3, z_2
    x_2, z_2, x_3, z_3 = multiply_step(p, a24, x_1, x_2, z_2, x_3, z_3)
    res[b] = (x_2, z_2, x_3, z_3)
  if swaps & 1:
    x_2, x_3 = x_3, x_2
    z_2, z_3 = z_3, z_2

  u_2 = moddiv(x_2, z_2, p)
  return u_2, res


def reduce_private(self, k: int) -> int:
  k = k % 2**254
  k -= k % 8
  k |= 2**254
  return k


#--------


def mod_square_roots(a, p):
  assert 0 <= a < p
  if a == 0:
    return [0]
  s = mod_arith.modsqrt(a, p)
  if s is None:
    return []
  return [s, p - s]


def inverse_multiply_step(p, a24, x_1, x_2, z_2, x_3, z_3, debug=False):

  def P(coeffs):
    return poly.Polynomial(coeffs, p)

  # x_2 = AA * BB
  # z_2 = E * (AA + a24 * E)
  # E = AA - BB
  # -> BB = x_2/AA
  # -> z_2 = (AA - x2/AA) * (AA + a24 * (AA-x2/AA)
  # -> z_2*A4 = (A4 - x2) * (A4 + a24 * (A4 - x2))
  div_2 = pow(2, -1, p)
  sum_da_cb = mod_square_roots(x_3, p)
  if debug:
    print('sum_da_cb', sum_da_cb)
  if not sum_da_cb:
    return
  diff_da_cb = mod_square_roots(moddiv(z_3, x_1, p), p)
  if debug:
    print('diff_da_cb', diff_da_cb)
  if not diff_da_cb:
    return
  AB = mod_square_roots(x_2, p)
  if debug:
    print('AB', AB)

  if not AB:
    return
  f = P([-x_2, 1]) * P([-x_2 * a24, 1 + a24]) - P([0, z_2])
  A = []
  for a4 in f.roots():
    if debug:
      print('a4', a4)
    for aa in mod_square_roots(a4, p):
      if debug:
        print('aa', aa)
      r = mod_square_roots(aa, p)
      if debug:
        print('a', r)
      A += r
  for a in A:
    for ab in AB:
      b = moddiv(ab, a, p)
      for s in sum_da_cb:
        for d in diff_da_cb:
          da = (s + d) * div_2 % p
          cb = (s - da) % p
          d = moddiv(da, a, p)
          c = moddiv(cb, b, p)
          x_2 = (a + b) * div_2 % p
          z_2 = (a - x_2) % p
          x_3 = (c + d) * div_2 % p
          z_3 = (c - x_3) % p
          yield (x_2, z_2, x_3, z_3)


def inverse_multiply(p, a24, k, x_1, x_2, z_2, x_3, z_3):
  # Keeps the intermediate results
  res = []
  bits = k.bit_length()
  swaps = k ^ (k << 1)
  if swaps & 1:
    x_2, x_3 = x_3, x_2
    z_2, z_3 = z_3, z_2
  S = [(x_2, z_2, x_3, z_3)]
  for b in range(bits):
    swap = swaps >> (b + 1) & 1
    R = []
    for s in S:
      for t in inverse_multiply_step(p, a24, x_1, *s):
        if swap:
          R.append(t[2:] + t[:2])
        else:
          R.append(t)
    S = R
    yield b + 1, S
