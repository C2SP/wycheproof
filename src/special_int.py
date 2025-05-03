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

import mod_arith
import math
from typing import Optional


def generate_inverse(n: int, a0: int, b0: int) -> Optional[int]:
  """Tries to generate a test case with a mod b.

  Tries to generate an integer x, such that the computation of the modular
  inverse of x modulo n using the Euclidean GCD contains the step
  a mod b.

  Args:
    n: modulus
    a: must be coprime to mod
    b: must be coprime to mod and a

  Returns:
    x, if there is an x such that modular inverse of x modulo n uses
    a % b or None if no such x was found.
  """

  def check(n: int, x: int, a: int, b: int) -> bool:
    a, b = sorted([a, b])
    while x:
      if (x, n) == (a, b):
        return True
      n, x = x, n % x
    return False

  if math.gcd(n, a0) != 1 or math.gcd(n, b0) != 1 or math.gcd(a0, b0) != 1:
    return None
  # Find r,s with a*r + b*s == n
  for a, b in [(a0, b0), (b0, a0)]:
    r = pow(a, -1, b) * n % b
    s = (n - r * a) // b
    if s <= 0:
      continue
    g, u, v = mod_arith.extended_gcd(r, s)
    if g != 1:
      continue
    # 1 = u * r + v * s.
    x = abs(u) * b + abs(v) * a
    if check(n, x, a, b):
      return x


def edge_case_inverse(mod: int):
  """Yields special cases for modular inverses modulo mod.

  References:

  CVE-2019-0865: don't know the problem
  CVE-2013-4207: overflow if inverse does not exist.
  CVE-2022-0778:
  https://bugzilla.mozilla.org/show_bug.cgi?id=1554336

  Args:
    mod: the modulus

  Yields:
    integers that may lead to difficulties when computing modular inverses.
  """

  bits = mod.bit_length() // 2 - 32
  res = set()
  if bits > 8:
    for a, b in [(2**bits, 2**(bits // 2) - 1), (2**bits, 2**(bits // 2) + 1),
                 (2**bits - 2**(bits // 2 + 1), 2**(bits // 2) - 1),
                 (2**bits, 2**bits - 3), (2**bits - 1, 2**52 - 1),
                 (2**bits - 1, 2**64 - 1), (2**bits - 1, 2**(bits // 2) + 3),
                 (2**bits - 1, 2**(bits // 2) - 3),
                 (2**bits - 1, 2**(bits // 4)),
                 (2**bits - 1, 2**(bits // 4 + 1) + 1),
                 (2**bits - 1, 2**(bits // 4 - 1) - 1), (2**112 - 1, 2**52 - 1),
                 (2**112 - 1, 2**52 - 3), (2**bits - 1, 2**64 - 2**32),
                 (2**bits - 1, 2**128 - 2**64)]:
      while math.gcd(a, b) != 1:
        a -= 1
      x = generate_inverse(mod, a, b)
      if x and x not in res:
        res.add(x)
        yield x
