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

# This is experimental code that is not necessary for Wycheproof.

def nim_mul(x, y):
  '''Multiplies to nimbers. 
  >>> nim_mul(123, 12345)
  35336

  1 is the neutral element of the multiplication
  >>> nim_mul(1, 123)
  123

  Multiplication is distributive
  >>> nim_mul(23 ^ 67, 123) == nim_mul(23, 123) ^ nim_mul(67, 123)
  True
  '''
  if x > y: x,y = y,x
  if x == 0: return 0
  if x == 1: return y
  k = (y.bit_length() - 1).bit_length() - 1
  B = 1 << (2**k)
  yh, yl = divmod(y, B)
  if x < B:
    return nim_mul(x, yh) * B ^ nim_mul(x, yl)
  else:
     xh, xl = divmod(x, B)
     w = B // 2
     # compute (xh*B + xl)(yh*B + yl)
     # using Karatsuba and B^2 = B+w
     rh = nim_mul(xh, yh)
     rm = nim_mul(xl ^ xh, yl ^ yh)
     rl = nim_mul(xl, yl)
     hi = rm ^ rl
     lo = rl ^ nim_mul(rh, w)
     return (hi * B) ^ lo

def nim_inv(n):
  '''Computes the inverse of n
  >>> nim_inv(6)
  9
  >>> nim_inv(nim_inv(12345))
  12345
  >>> nim_mul(1234567, nim_inv(1234567))
  1
  '''
  assert n > 0
  if n == 1: return 1
  k = (n.bit_length() - 1).bit_length() - 1
  B = 1 << (2**k)
  conj = n ^ (n >> 2**k)
  norm = nim_mul(n, conj)
  inv = nim_inv(norm)
  return nim_mul(inv, conj)

# Nimbers form an infinite field of character 2.
# https://en.wikipedia.org/wiki/Nimber
class Nimber:
  def __init__(self, n):
    self.n = n
  def __add__(self, other):
    assert isinstance(other, Nimber)
    return Nimber(other.n ^ self.n)
  def __mul__(self, other):
    assert isinstance(other, Nimber)
    return Nimber(nim_mul(self.n, other.n))
  def __pow__(self, n):
    assert isinstance(n, int)
    p = self
    r = Nimber(1)
    if n < 0:
      n,p = -n, p.inverse()
    while n:
      if n%2: r*=p
      n,p = n//2, p*p
    return r
  def inverse(self):
    return Nimber(nim_inv(self.n))
  def __repr__(self):
    return 'Nimber(%s)'%self.n
  __str__ = __repr__

if __name__ == "__main__":
  import doctest
  doctest.testmod()

