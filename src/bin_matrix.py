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

class BinMatrix:
  def __init__(self, L, cols):
    '''L[i] is an integer whose bits represent the
       coefficients of row[i]'''
    self.L = L
    self.cols = cols

  @staticmethod
  def identity(n: int):
    """Returns a identity matrix of dimension nxn.
    
    Args:
      n: the dimension of the matrix
    """
    return BinMatrix([1<<i for i in range(n)], n)

  def is_square(self):
    return len(self.L) == self.cols
  def __str__(self, delim="\n"):
    return delim.join(''.join('01'[(x >> i) % 2] for i in range(self.cols))
                      for x in self.L)
  def __repr__(self):
    return "BinMatrix(%s,%d)" % (str(self.L), self.cols)
  def __eq__(self, other):
    if not isinstance(other, BinMatrix):
      return False
    return self.cols == other.cols and self.L == other.L
  def __ne__(self, other):
    return not self == other
  def __bool__(self):
    return any(self.L)
  __nonzero__ = __bool__
  def __add__(self, other):
    assert isinstance(other, BinMatrix)
    assert len(other.L) == len(self.L)
    assert self.cols == other.cols
    return BinMatrix([x^y for x,y in zip(self.L, other.L)], self.cols)
  def __mul__(self, other):
    assert self.cols == len(other.L)
    R = []
    for x in self.L:
      res = 0
      for y in other.L:
        if x & 1:
          res ^= y
        x >>= 1
      R.append(res)
    return BinMatrix(R, other.cols)
  def __pow__(self, n):
    assert n >= 0
    res = BinMatrix.identity(self.cols)
    p = self
    while n:
      if n%2 == 1:
        res *= p
      p *= p
      n //= 2
    return res

  def inverse(self):
    assert self.is_square()
    cols = self.cols
    A = [1 << i for i in range(cols)]
    B = self.L[:]
    # invariant A * self == B
    for j in range(cols):
      for k in range(j, cols):
        if (B[k] >> j) & 1:
          break
      else:
        raise Exception('Inverse does not exist')
      if k != j:
        A[k], A[j] = A[j], A[k]
        B[k], B[j] = B[j], B[k]
      for i in range(cols):
        if i != j:
          if (B[i] >> j) & 1:
            B[i] ^= B[j]
            A[i] ^= A[j]
    return BinMatrix(A, cols)

  def charPoly(self):
    '''Returns the characteristic polynomial as a bitstring.
       I.e. the integer charPoly_self(2)'''
    assert self.is_square()
    # a list of quadruples row, col, poly, Matrix
    n = self.cols
    T = []
    P = BinMatrix.identity(self.cols)
    for i in range(self.cols+1):
      polyR = 1 << i
      R = P
      for row, col, polyM, M in T:
        if (R.L[row] >> col) & 1:
          R = R + M
          polyR ^= polyM
      if not R:
        return polyR
      for row in range(n):
        if R.L[row]: break
      for col in range(n):
        if (R.L[row] >> col) & 1: break
      T.append((row, col, polyR, R))
      P = P * self
    raise Exception('Could not compute characteristic polynomial')


