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

# This is experimental code, that is not necessary for Wycheproof.
import gf


def divisors_from_factors(f):
  S = {1}
  for p in f:
    S = S.union(set(x * p for x in S))
  L = list(S)
  L.sort()
  return L


def divisors(r):
  return divisors_from_factors(gf.factor(r))


def binary(x):
  if x == 0:
    return '0'
  res = ''
  while x:
    res = '01'[x & 1] + res
    x = x >> 1
  return res


# number of irreducible polynomials of degree n
# OEIS A001037
Irred = [
    1, 2, 1, 2, 3, 6, 9, 18, 30, 56, 99, 186, 335, 630, 1161, 2182, 4080, 7710,
    14532, 27594, 52377, 99858, 190557, 364722, 698870, 1342176, 2580795,
    4971008, 9586395, 18512790, 35790267, 69273666, 134215680, 260300986,
    505286415, 981706806, 1908866960, 3714566310, 7233615333, 14096302710,
    27487764474
]

mnod_tab = {}


def maxNumberOfDivisors(degree, maxd):
  """maximal number of divisors of a binary polynomial of degree degree,

     where maxd is the maximal degree of a factor
  """
  if degree < 0:
    return 0
  if degree == 0:
    return 1
  if maxd < 1:
    return 0
  if maxd == 1:
    c0 = degree // 2
    c1 = degree - c0
    # poly = x^c0 * (x+1)^c1
    return (1 + c0) * (1 + c1)
  if (degree, maxd) in mnod_tab:
    return mnod_tab[degree, maxd]
  res = 0
  irred = Irred[maxd]
  for j in range(degree // maxd + 1):
    q = j // irred
    r = j % irred
    cnt = (2 + q)**r * (1 + q)**(irred - r) * maxNumberOfDivisors(
        degree - j * maxd, maxd - 1)
    res = max(res, cnt)
  mnof_tab[degree, maxd] = res
  return res


def primitive_trinomials(degree):
  return [i for i in range(1, degree) if gf.is_primitive((0, i, degree))]


def trace_constants():
  for n, f in gf.defined_fields():
    bits = []
    for i in range(f.degree()):
      t = f(2**i).trace(1)
      assert t.poly in (0, 1)
      if t:
        bits.append(i)
    trace_const = sum(2**i for i in bits)
    print(f.name, bits, hex(trace_const))
    if f.trace_constant is not None:
      assert trace_const == f.trace_constant


def primitive_quintonomials(degree, eqn=None):
  for c in range(degree):
    for b in range(c):
      for a in range(1, b):
        if eqn and not eqn(a, b, c):
          continue
        if gf.is_primitive((0, a, b, c, degree)):
          yield (0, a, b, c, degree)


def find_quintonomials(degree, eqn=(lambda a, b, c: a + b == c)):
  for p in primitive_quintonomials(degree, eqn):
    print(p)


def maybe_irreducible(degree):
  for i in range(1, degree):
    P = gf.poly2int((0, i, degree))
    if gf.bin_exp(2, 2**degree - 1, P) == 1:
      yield i


if __name__ == '__main__':
  trace_constants()
