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

import berlekamp_massey
import bin_matrix
import gf
import util

class Xorshift128plus:
  def __init__(self, x=None, y=None):
    self.mod = 2 ** 64
    if x is None:
      x = util.randomint(0, self.mod)
    else:
      x %= self.mod
    if y is None:
      y = util.randomint(0, self.mod)
    else:
      y %= self.mod
    self.x, self.y = x,y
    # The state must not be 0.
    assert x or y

  def output(self):
    return (self.x + self.y) % 2**64

  def step(self):
    '''Generate the next 64-bits of the sequence'''
    x,y = self.x, self.y
    x = (x ^ (x << 23)) % 2**64
    x ^= x >> 17
    x ^= y ^ (y >> 26)
    self.x, self.y = y, x
    return self.output()

  def stepback(self):
    y,x = self.x, self.y
    x ^= y ^ (y >> 26)
    x ^= x >> 17
    x ^= x >> 34
    x = (x ^ (x << 23) ^ (x << 46)) % 2**64
    self.x, self.y = x, y

  def stepN(self, n):
    '''Steps the LFSR forward by n steps.
       This uses that the new state can be computed by a matrix
       multiplication as
         state = self.y * 2**64 + self.x
         newstate = BinMatrix([state], 128) * XorshiftMatrix**n
         self.y, self.x = divmod(newstate.L[0], 2**64)
      This again can be simplified by using that the characteristic
      polynomial CharPoly(x) satisfies CharPoly(XorshiftMatrix) == 0.
      Hence we can compute x**n mod CharPoly(x) and use this
      to compute the new state.'''
    n %= 2**128 - 1
    poly = (Xorshift128Step ** n).poly
    x, y = self.x, self.y
    self.x, self.y = 0, 0
    for i in range(128, -1, -1):
      self.step()
      if (poly >> i) & 1:
        self.x ^= x
        self.y ^= y

XorshiftTransform = [None] * 128
for i in range(128):
  y,x = divmod(1 << i, 2**64)
  R = Xorshift128plus(x,y)
  R.step()
  XorshiftTransform[i] = R.y * 2**64 + R.x
XorshiftMatrix = bin_matrix.BinMatrix(XorshiftTransform, 128)
XorshiftCharPoly = XorshiftMatrix.charPoly()
Xorshift128 = gf.GF(XorshiftCharPoly, name = "Xorshift128")
Xorshift128Step = Xorshift128(2)

def testOrder():
  Id = bin_matrix.BinMatrix.identy(128)
  assert XorshiftMatrix ** (2**128 - 1) == Id
  for p in gf.mersenne_factorization(128):
    assert XorshiftMatrix ** ((2**128 - 1)//p) != Id

def testCharPoly(M=None):
  if M == None:
    M = XorshiftMatrix
  cols = M.cols
  charPoly = M.charPoly()
  print(bin(charPoly))
  res = bin_matrix.BinMatrix([0] * cols, cols)
  id = bin_matrix.BinMatrix.identity(cols)
  for i in range(cols, -1, -1):
    res *= M
    if (charPoly >> i) & 1:
      res += id
  assert not res

def testInverse(M = None):
  if M == None:
    M = XorshiftMatrix
  T = M * M.inverse()
  assert T == bin_matrix.BinMatrix.identity(M.cols)

def testLsb(n):
  '''The lsb of the XorShift algorithm satisfies
     a linear recurrence of degree 128.
     Running this test with n >= 256 will notice
     the linear recurrence and hence will return
     this result:
     (128, 342909507027747593010286227356456005881L)'''
  xs = Xorshift128plus()
  bits = 0
  for i in range(n):
    bits += bits + xs.step() % 2
  return berlekamp_massey.BerlekampMassey(bits, n)

def testBM(steps, bit=0):
  lsb = 0
  R = Xorshift128plus(128311298427123, 1983198319873219)
  for i in range(steps):
    lsb |= ((R.step() >> bit) & 1) << i
  length, rec = berlekamp_massey.BerlekampMassey(lsb)
  if bit == 0:
    assert length <= 128
    print(bin(rec))
  else:
    print(length)

def testBase():
  def printBase(f):
    M = bin_matrix.BinMatrix([f(b).poly for b in B], 128)
    print()
    print(M * invB)

  x = gf.F128(2)
  g = x+x.inverse()
  # A normal base
  B = [g ** 2 ** i for i in range(128)]
  MB = bin_matrix.BinMatrix([b.poly for b in B], 128)
  invB = MB.inverse()
  # Conversion of polynomial base into normal base
  printBase(lambda b:b*g)
  
def testMsb(n, bits=8, debug=False):
  '''Experiment for distinguishing xorshift128 from random
     given msbs only.
     A naive test would need about 20'000 samples.
  '''
  xs = Xorshift128plus()
  this = xs.step()
  cnt = 0
  cntguess = 0
  for i in range(n):
     last = this
     lasts = xs.x
     this = xs.step()
     diff = (this - last) % 2 ** 64
     msb = diff >> (64 - bits)
     if msb in (0, 2**(bits-1)):
       ok = (msb != 0) == ((lasts ^ xs.y) >> 63)
       if debug: print(i, msb, '%016x'%lasts, '%016x'%xs.y, '%016x'%(lasts ^ xs.y), ok)
       cnt += 1
       cntguess += ok
  print(cnt, cntguess)
