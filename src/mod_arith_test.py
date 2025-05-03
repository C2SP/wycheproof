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

import math
import mod_arith

def test_is_square():
  assert mod_arith.is_square(0)
  assert mod_arith.is_square(1)
  assert mod_arith.is_square(4)
  assert mod_arith.is_square(12345**2)
  assert mod_arith.is_square(1182371387198237123817983189237 ** 2)
  assert not mod_arith.is_square(-1)
  assert not mod_arith.is_square(2)
  assert not mod_arith.is_square(1182371387198237123817983189237 ** 2 + 1)


def test_extended_gcd():
  for a, b in [
    (0, 11),
    (3, 13),
    (5, 128),
    (123, 129),
    (64, 128),
    (25, 625)]:
    g, x, y = mod_arith.extended_gcd(a, b)
    assert g == math.gcd(a, b)
    assert a * x + b * y == g


def test_legendre():
  for a, p, expected in [
    (1, 11, 1),
    (2, 11, -1),
    (4, 11, 1),
    (22, 11, 0),
    (9, 13, 1),
    (5, 13, -1),]:    
    assert mod_arith.legendre(a, p) == expected


def test_jacobi():
  for a, n, expected in [
    (1, 11, 1),
    (2, 11, -1),
    (4, 11, 1),
    (22, 11, 0),
    (9, 13, 1),
    (5, 13, -1),
    (64, 91, 1),
    (73, 121, 1),
    (772, 1331, -1),]:
    assert mod_arith.jacobi(a, n) == expected


def test_modsqrt():
  for y, p in [
    (13, 71),
    (17, 73),
    (23, 79)]:
    assert mod_arith.modsqrt(y * y % p, p) == y


def test_bininv():
  for a, k in [
    (1, 1),
    (3, 3),
    (7, 3),
    (12345, 16),
    (12345123213, 32),]:
    inv = mod_arith.bininv(a, k)
    assert 0 < inv < 2**k
    assert inv * a % 2**k == 1


def test_bininvsqrt():
  for a, k in [
    (1, 1),
    (1, 3),
    (17, 5),
    (12345, 16),
    (12345121233, 32),]:
    inv_sqrt = mod_arith.bininvsqrt(a, k)
    assert 0 < inv_sqrt < 2**k
    assert inv_sqrt ** 2 * a % 2**k == 1


def test_chrem():
  for x1, m1, x2, m2 in [
    (0, 5, 3, 12),
    (1, 8, 6, 7),
    (0, 12, 0, 17),
    (12, 13, 13, 14),
    (12, 13, 0, 12),
    (123, 1234, 187, 1235)]:
    x = mod_arith.chrem(x1, m1, x2, m2)
    assert 0 <= x < m1 * m2
    assert x % m1 == x1
    assert x % m2 == x2


if __name__ == "__main__":
  test_is_square()
  test_extended_gcd()
  test_legendre()
  test_jacobi()
  test_modsqrt()
  test_bininv()
  test_bininvsqrt()
  test_chrem()

