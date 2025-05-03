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

def BerlekampMassey0(S, length=None):
  if length is None:
    length = S.bit_length()
  B, C = 1,1
  SB, SC = S, S
  L = 0
  for n in range(length):
    B <<= 1
    SB <<= 1
    T = SC
    if C & 1 == 0: T ^= S
    if (T >> n) & 1:
      if 2 * L <= n:
        B, C = C, C ^ B
        SB, SC = SC, SC ^ SB
        L = n + 1 - L
      else:
        C ^= B
        SC ^= SB
  return L, C


def BerlekampMassey1(S, length=None, debug=True):
  '''Berlekamp Massey algorithm.
     The algorithm finds the shortest LFSR that produces the bits of S.
     Here S is simply a positive integer.
     length is the length of the bit sequence.
     If length is None then S.bit_length() is used.'''
  if length is None:
    length = S.bit_length()
  B, C = 1, 1
  db, dc = 0, 0
  SB, SC = S, S
  for n in range(length):
    # Invariants are: 
    #   SB = S x B (where x denotes a polynomial multiplication)
    #   SC = S x C
    #   degree of C <= dc
    #   degree of B <= db
    #   n = db + dc
    #   C & 1 == 1
    #   bits db .. n - 2 in SB are 0
    #   bits dc .. n - 1 in SC are 0
    if debug:
      # print(n, B, SB, db, C, SC, dc)
      assert B.bit_length() <= db + 1
      assert C.bit_length() <= dc + 1
      assert db + dc == n
      assert C & 1 == 1
      if n > 0:
        assert (SB % 2**(n - 1)) >> db == 0
      if db < n - 1:
        # TODO: Why does this follow?
        assert (SB >> (n - 1)) & 1 == 1
      assert (SC % 2**n) >> dc == 0
    B <<= 1
    SB <<= 1
    db += 1
    if (SC >> n) & 1:
      if dc < db:
        B, C = C, B
        SB, SC = SC, SB
        db, dc = dc, db
      C ^= B
      SC ^= SB
  return dc, C

def BerlekampMassey(S, length=None, debug=True):
  '''Berlekamp Massey algorithm.
     The algorithm finds the shortest LFSR that produces the bits of S.
     Here S is simply a positive integer.
     length is the length of the bit sequence.
     If length is None then S.bit_length() is used.'''
  if length is None:
    length = S.bit_length()
  B, C = 2, 1
  db, dc = 1, 0
  TB ,TC = S << 1, S
  for n in range(length):
    # Invariants are: 
    #   TB = (S x B) >> n (where x denotes a polynomial multiplication)
    #   TC = (S x C) >> n
    #   degree of C <= dc
    #   degree of B <= db
    #   n + 1 = db + dc
    #   C & 1 == 1
    if debug:
      assert B.bit_length() <= db + 1
      assert C.bit_length() <= dc + 1
      assert db + dc == n + 1
      assert C & 1 == 1
      if db < n:
        # TODO: Why does this follow?
        assert TB & 1 == 1
    if TC & 1:
      if dc < db:
        B, C = C, B
        TB, TC = TC, TB
        db, dc = dc, db
      C ^= B
      TC ^= TB
    db += 1
    B <<= 1
    TC >>= 1
  return dc, C

def BerlekampMassey2(S, length=None, debug = False):
  if length is None:
    length = S.bit_length()
  B, C = 1,1
  SB, SC = S, S
  L = 0
  for n in range(length):
    bit = SC & 1
    SC >>= 1
    B <<= 1
    if debug: print(n, SB, SC, bit)
    if bit:
      if 2 * L <= n:
        B, C = C, B
        SB, SC = SC, SB
        L = n + 1 - L
      C ^= B
      SC ^= SB
  return L, C

def BerlekampMassey3(S, length=None):
  if length is None:
    length = S.bit_length()
  B, C = 1,1
  SB, SC = S, S
  L = 0
  m = 0
  for n in range(length):
    if SC & (1 << m):
      SC >>= (m+1)
      B <<= (m+1)
      m = 0
      if 2 * L <= n:
        B, C = C, B
        SB, SC = SC, SB
        L = n + 1 - L
      C ^= B
      SC ^= SB
    else: m+=1
  return L, C

def testCompare():
  def test(i, bits=None):
    a = BerlekampMassey0(i)
    b = BerlekampMassey(i)
    c = BerlekampMassey2(i)
    if a != b or a != c:
      print(i,a,b,c)
     
  for i in range(1,50000):
    test(i)
  for i in [981247098124621639216491847619631982631461098247981270192473098214701740921740981724,
            19237198461082731024610273210947109174092987109248712095871209487120947109471098471024,
            2**64 + 1,
            2**64 - 1,
            2**71]:
    test(i)
  for i in range(1, 300):
    test(i, 255)
  for k in range(3, 1050, 2):
    i = 2**256 // k
    test(i, 256)
  

if __name__ == "__main__":
  testCompare()


