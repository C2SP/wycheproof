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
from typing import Optional

def is_square(n: int) -> bool:
  """Determines whether n is a square.

  Args:
    n: the integer to test

  Returns:
    True if n is a square. False otherwise.
  """
  if n < 0:
    return False
  return math.isqrt(n) ** 2 == n


def extended_gcd(a: int, b: int) -> tuple[int, int, int]:
  """Implementation of the extended GCD.
  
  Returns: a tuple (g, x, y) such that
     g = gcd(a,b) and g = x*a + y*b.
  """
  if b == 0:
    return a, 1, 0
  r, s = a, b
  u, v = 1, 0
  while r:
    q = s // r
    r, s = s - q * r, r
    u, v = v - q * u, u
  if s < 0:
    s, v = -s, -v
  # Just a sanity test
  assert (s - a * v) % b == 0
  return s, v, (s - a * v) // b


def legendre(x: int, p: int) -> int:
  """Computes the Legendre symbol.

  Args:
    x: an integer
    p: a prime
  Returns:
    1 if x is a quadratic residue, -1 if x is a non-residue
    and 0 if x is a multiple of p.
  """
  x = pow(x, (p-1)//2, p)
  if x == p-1:
    return -1
  if x not in (0, 1):
    raise ValueError("p is not prime")
  return x


def jacobi(a: int, n: int) -> int:
  """Computes the Jacobi symbol.
  
  Args:
    a: an integer
    n: positive, odd integer
  Returns:
    the Jacobi symbol
  """
  if n < 0 or n % 2 == 0:
    raise ValueError("p must be positive and odd")
  a %= n
  res = 1
  while a != 0:
    while a % 2 == 0:
      a //= 2
      if n % 8 in [3, 5]:
        res = -res
    if 3 == a % 4 == n % 4:
      res = -res
    a, n = n % a, a
  if n != 1:
    return 0
  return res


def modsqrt(x: int, p: int) -> Optional[int]:
  """Computes a modular square root of x.

  The result is undefined if p is not a prime.

  Args:
    x: an integer
    p: an odd prime
  Returns:
    an integer y, such that y**2 % p == x % p or
    None if no such integer exists.
  """
  if p < 2 or p % 2 == 0:
    raise ValueError("p must be an odd prime")
  if x == 0: return 0
  if p % 4 == 3:
    sqr = pow(x, (p+1)//4, p)
  else:
    a = 1
    # Find a quadratic nonresidue.
    while True:
      d = (a * a - x) % p
      if legendre(d, p) == -1:
        break
      a += 1
      if a > 128:
        return None
    q = (p+1)//2
    u = a
    v = 1
    for b in range(q.bit_length() - 2, -1, -1):
      u, v = (u * u + v * v % p * d) %p, 2 * u * v % p
      if (q >> b) & 1:
        u, v = (a * u + v * d) % p, (a * v + u) % p
    sqr = u
  if 2 * sqr > p: sqr = p - sqr
  if (sqr * sqr - x) % p == 0:
    return sqr
  else:
    return None


def bininv(a: int, k: int) -> int:
  """Computes a^-1 mod 2**k

  Args:
    a: an odd integer
    k: a positive integer

  Returns:
    the modular invers of a modulo 2**k or None if
    no inverse exist.
  """
  if a % 2 == 0:
    return None
  x = a % 4
  n = 2
  while n < k:
    # The loop invariant is: 1 == a*x % 2**n
    # lifting:
    # a*x - 1 == 0 (mod 2^n) implies
    # (a*x - 1)^2 == 0 (mod 2^(2n)),
    # a * x * (2 - a * x) == 1 (mod 2^(2n))
    n = min(k, 2 * n)
    x = x * (2 - a * x) % 2**n
  return x


def bininvsqrt(a: int, k: int) -> Optional[int]:
  """Computes a solution x to a * x^2 == 1 (mod 2^k).

  If x is a solution then there are 3 more solutions:
     (2^(k+1) - x) % 2**k,
     (2^(k+1) + x) % 2**k,
     -x % 2**k,

  Args:
    a: an integer
    k: a positive integer

  Returns:
    a solution to a * x^2 == 1 (mod 2^k) is such a solution
    exists or None otherwise.
  """
  if a % 8 != 1:
    return None
  x = 1
  n = 3
  while n < k:
    # The loop invariant is 1 == a * x * x % 2**n
    n = min(k, 2 * n - 2)
    x = x * (3 - a * x * x) // 2 % 2**n
  return x


def chrem(x1: int, m1: int, x2: int, m2: int) -> int:
  """Chinese remaindering.

  Args:
    x1: an integer 0 <= x1 < m1
    m1: a positive integer
    x2: an integer 0 <= x2 < m2
    m2: a positive integer with gcd(m1, m2) == 1

  Returns:
    x, such that
    x % m1 = x1
    x % m2 = x2
  """
  inv = pow(m1, -1, m2)
  k = (x2 - x1) * inv % m2
  return x1 + k * m1
