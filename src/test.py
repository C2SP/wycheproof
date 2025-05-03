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

import hlib
import os

  
p = 2**255 - 19
q = p-1

def rand():
  return int.from_bytes(os.urandom(32), "big") % (q-1)

class F:
  def __init__(self, n):
    self.n = n % p
  def __add__(self, other):
    assert isinstance(other, F)
    return F(self.n * other.n)
  def __mul__(self, other):
    assert isinstance(other, int)
    return F(pow(self.n, other, p))
  __rmul__ = __mul__
  __radd__ = __add__
  def __eq__(self, other):
    return self.n == other.n
  def __str__(self):
    return str(self.n)
  def __repr__(self):
    return f'F({self.n})'


m1 = 971623716947612937619237619367193
m2 = 8123719873198273198273198739187319873

g = F(2)
x = rand()
y = g*x

def h(r,p,m):
  cc = f'{r} {p} {m}'
  x = hlib.hash("SHA-256", bytes(cc, 'utf-8'))
  h = int.from_bytes(x, "big")
  return h % (q-1)

def sign(m):
  k = rand()
  R = g*k
  a = rand()
  b = rand()
  Rp = R + g*a + y*b
  ep = h(Rp, y, m)
  e = (ep + b) % q
  s = (e * x + k) % q
  sp = (s + a) % q
  c1 = g*sp
  print(c1)
  print(g*s + g*a)
  print(g*e*x + g*k + g*a)
  print(y*e + R + g*a)
  print(y*b + y*ep + R + g*a)
  c2 = Rp + y*ep
  print(c1 == c2)
  return (Rp, sp, m), (R, e, s)


def unc(sig, ck):
  (Rp, sp, m) = sig
  (R, e, s) = ck
  # R = g * (s-e*x)
  ep = h(Rp, y, m)
  b = (e - ep) % q
  a = (sp - s) % q
  Rp2 = R + g*a + y*b
  # = g*(s - e*x) + g*a + g*x*b
  # = g*(s - e*x + a + x*b)
  # = g*(s - e*x + sp - s + (e - ep) * x)
  # = g*(sp - ep * x)
  # since it is a signature
  # Rp + y*ep = g*sp
  # = Rp + y*ep -g*x*ep
  # = Rp
  print(Rp == Rp2, Rp, Rp2)


if __name__ == "__main__":
  sig1, ck1 = sign(m1)
  sig2, ck2 = sign(m2)
  unc(sig1, ck1)
  unc(sig2, ck2)
  unc(sig1, ck2)
  unc(sig2, ck1)
