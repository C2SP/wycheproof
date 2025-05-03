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

# Implements polynomials in a ring Z/(mZ)
import typing

class Polynomial:
  # Defines sum(x^n*coeffs[n] % mod)
  def __init__(self, coeffs, mod, reduced = False):
    if not reduced:
      coeffs = [c % mod for c in coeffs]
    self.coeffs = coeffs
    self.mod = mod
    self.degree = len(coeffs)-1
    while self.degree >= 0 and self[self.degree] == 0:
      self.degree -= 1

  def newPoly(self, coeffs: typing.List[int], reduced:bool = False):
     return Polynomial(coeffs, self.mod, reduced)

  def __getitem__(self, i):
    if 0 <= i <= self.degree:
      return self.coeffs[i]
    else:
      return 0

  def coerce(self, other):
    if isinstance(other, int):
      return Polynomial([other], self.mod)
    elif isinstance(other, Polynomial) and other.mod == self.mod:
      return other
    else:
      return None

  def __add__(self, other):
    other = self.coerce(other)
    if other == None: return NotImplemented
    c = min(self.degree, other.degree) + 1
    A = self.coeffs
    B = other.coeffs
    L = ([(A[i]+B[i]) % self.mod for i in range(c)] 
        + self.coeffs[c:self.degree+1]
        + other.coeffs[c:other.degree+1])
    return self.newPoly(L, reduced=True)
  __radd__ = __add__
  def __neg__(self):
    return self.newPoly([-x for x in self.coeffs])
  def __sub__(self, other):
    return self.__add__(-other)
  def __rsub__(self, other):
    return (-self)+other
  def __mul__(self, other):
    other = self.coerce(other)
    if other == None: return NotImplemented
    if self.degree == -1: return self
    if other.degree == -1: return other
    L = [0] * (self.degree + other.degree + 1)
    for i in range(self.degree + 1):
      for j in range(other.degree + 1):
        L[i+j] += self.coeffs[i] * other.coeffs[j]
    return self.newPoly(L)
  __rmul__ = __mul__
  def __repr__(self):
    return 'Polynomial(%s, %s)'%(self.coeffs, self.mod)
  __str__ = __repr__
  def __mod__(self, other):
    return other.__rdivmod__(self)[1]
  def __divmod__(self, other):
    return other.__rdivmod__(self)
  def __floordiv__(self, other):
    return other.__rdivmod__(self)[0]
  def __rdivmod__(self, other):
    other = self.coerce(other)
    if other is None: return NotImplemented
    if self.degree < 0:
       raise Exception("Division by 0")
    if self.degree == 0:
       if self[0] == 1:
         return other, self.newPoly([])
       inv = pow(self[0], -1, self.mod)
       return inv * other, self.newPoly([])
    if self[self.degree] != 1:
       inv = pow(self[self.degree], -1, self.mod)
       r,s = divmod(other, self * inv)
       return inv * r, s
    L = other.coeffs[:]
    d = self.degree
    if other.degree < self.degree:
      return self.newPoly([]), other
    quot = [None] * (other.degree - d + 1)
    for j in range(other.degree - d, -1, -1):
      w = L[j + d] % self.mod
      quot[j] = w
      for i in range(self.degree):
         L[j + i] -= self.coeffs[i] * w
    C = [L[i] % self.mod for i in range(d)]
    return self.newPoly(quot), self.newPoly(C)
  def __pow__(self, exp, mod):
    if not isinstance(exp, int):
      raise Exception("Only implemented for integer exponents")
    if exp < 0:
      raise Exception("Not implemented for negative integers")
    mod = self.coerce(mod)
    res = self.newPoly([1])
    p = self % mod
    while exp:
      if exp & 1:
        res = res * p % mod
      exp //= 2
      if exp:
        p = p * p % mod
    return res

  def multiply_by_x_to(self, m):
    return self.newPoly([0]*m + self.coeffs)

  def gcd(self, b):
    a = self
    while a.degree >= 0:
      a, b = b % a, a
    return b

  def roots(self) -> typing.List[int]:
    '''Returns the roots of this polynomial.
       self.mod must be prime.
    '''
    def split(w, x, a):
      if w.degree < 1:
        return []
      if w.degree == 1:
        return [w[0] * pow(-w[1], -1, p) % p]
      assert a < p
      s = pow(x + a, (p - 1) // 2, w) - 1
      f = w.gcd(s)
      return split(f, x, a + 1) + split(w // f, x, a + 1) 

    p = self.mod
    if pow(3, p - 1, p) != 1:
      raise ValueError("Only implemented over prime order fields")
    x = Polynomial([0, 1], p)
    w = self.gcd(pow(x, p, self) - x)
    return split(w, x, 1)

def berlekamp_massey(s):
  p = s.mod
  c = Polynomial([1], p)
  b = Polynomial([1], p)
  l = 0
  m = 1
  f = 1
  for n in range(s.degree + 1):
    assert c[0] == 1
    d = (s[n] + sum(c[i]*s[n-i] for i in range(1, l+1))) % p
    if d == 0:
      m += 1
    else:
      finv = pow(f, -1, p)
      t = c
      c = c - d * finv * b.multiply_by_x_to(m)
      if 2 * l <= n:
        b = t
        l = n + 1 - l
        f = d
        m = 1
      else:
        m += 1
  return l,c



