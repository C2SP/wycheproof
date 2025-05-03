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
import sys
import util
from typing import Optional, Union

# A table of prime factors for 2**i-1 for commonly used field sizes. This
# is necessary since the factorization in this file just uses trial division.
PRIME_FACTORS = {
    61: [2**61 - 1],
    64: [3, 5, 17, 257, 641, 65537, 6700417],
    67: [193707721, 761838257287],
    71: [228479, 48544121, 212885833],
    73: [439, 2298041, 9361973132609],
    77: [23, 89, 127, 581283643249112959],
    79: [2687, 202029703, 1113491139767],
    83: [167, 57912614113275649087721],
    85: [31, 131071, 9520972806333758431],
    89: [2**89 - 1],
    91: [127, 911, 8191, 112901153, 23140471537],
    93: [7, 2147483647, 658812288653553079],
    95: [31, 191, 524287, 420778751, 30327152671],
    96: [3, 3, 5, 7, 13, 17, 97, 193, 241, 257, 673, 65537, 22253377],
    97: [11447, 13842607235828485645766393],
    107: [2**107 - 1],
    127: [2**127 - 1],
    128: [3, 5, 17, 257, 641, 65537, 274177, 6700417, 67280421310721],
    160: [
        3, 5, 5, 11, 17, 31, 41, 257, 61681, 65537, 414721, 4278255361,
        44479210368001
    ],
    163: [150287, 704161, 110211473, 27669118297, 36230454570129675721],
    192: [
        3, 3, 5, 7, 13, 17, 97, 193, 241, 257, 641, 673, 65537, 6700417,
        22253377, 18446744069414584321
    ],
    224: [
        3, 5, 17, 29, 43, 113, 127, 257, 449, 2689, 5153, 65537, 15790321,
        183076097, 54410972897, 358429848460993
    ],
    233: [
        1399, 135607, 622577,
        116868129879077600270344856324766260085066532853492178431
    ],
    239: [
        479, 1913, 5737, 176383, 134000609,
        7110008717824458123105014279253754096863768062879
    ],
    255: [
        7, 31, 103, 151, 2143, 11119, 106591, 131071, 949111,
        9520972806333758431, 5702451577639775545838643151
    ],
    256: [
        3, 5, 17, 257, 641, 65537, 274177, 6700417, 67280421310721,
        59649589127497217, 5704689200685129054721
    ],
    283: [
        9623, 68492481833,
        23579543011798993222850893929565870383844167873851502677311057483194673
    ],
    384: [
        3, 3, 5, 7, 13, 17, 97, 193, 241, 257, 641, 673, 769, 65537, 274177,
        6700417, 22253377, 67280421310721, 18446744069414584321,
        442499826945303593556473164314770689
    ],
    409: [
        4480666067023, 76025626689833,
        int("388119657591324467371942577087124648789568693795169094445383"
            "8586764072695131586617955811936945129")
    ],
    448: [
        3, 5, 17, 29, 43, 113, 127, 257, 449, 641, 2689, 5153, 65537, 6700417,
        15790321, 183076097, 54410972897, 358429848460993,
        167773885276849215533569, 37414057161322375957408148834323969],
    512: [
        3, 5, 17, 257, 641, 65537, 274177, 6700417, 67280421310721,
        1238926361552897, 59649589127497217, 5704689200685129054721,
        93461639715357977769163558199606896584051237541638188580280321
    ],
    521: [2**521 - 1],
    571: [
        5711, 27409,
        6969336604531667168509871230100794095801832527002849548226132675916172927,
        7084851186360580941633572744569751943590093912197024061201633650193388126309578906138706239
    ],
    607: [2**607 - 1],
    768: [
        # factors of 2**384 - 1
        3, 3, 5, 7, 13, 17, 97, 193, 241, 257, 641, 673, 769, 65537, 274177,
        6700417, 22253377, 67280421310721, 18446744069414584321,
        442499826945303593556473164314770689,
        # factors of 2**128 + 1
        59649589127497217, 5704689200685129054721,
        # factors of 2**256 - 2**128 + 1
        349621839326921795694385454593,
        331192380488114152600457428497953408512758882817
    ],
    1024: [
        3, 5, 17, 257, 641, 65537, 274177, 6700417, 67280421310721,
        1238926361552897, 59649589127497217, 5704689200685129054721,
        93461639715357977769163558199606896584051237541638188580280321, 2424833,
        7455602825647884208337395736200454918783366342657,
        int("741640062627530801524787141901937474059940781097519023905821316"
            "144415759504705008092818711693940737")
    ],
    1279: [2**1279 - 1],
    2048: [
        3, 5, 17, 257, 641, 65537, 274177, 6700417, 67280421310721,
        1238926361552897, 59649589127497217, 5704689200685129054721,
        93461639715357977769163558199606896584051237541638188580280321, 2424833,
        7455602825647884208337395736200454918783366342657, 45592577, 6487031809,
        4659775785220018543264560743076778192897,
        int("741640062627530801524787141901937474059940781097519023905821316"
            "144415759504705008092818711693940737"),
        int("1304398744054881897274847687965099039466085308416118921868952957"
            "7683241625147186357414022797757310489589878392884292384483114903"
            "2913798729088601617946094119449010595906710130531906171018354491"
            "609619193912488538116080712299672322806217820753127014424577")
    ]
}


def parity(x: int):
  res = 0
  while x:
    x = x & -x
    res = 1 - res
  return res


def mersenne_factorization(m: int) -> list[int]:
  """Returns the factorization of 2**m-1.

  Args:
    m: the exponent
    max_m: the maximal exponent for which trial division is attempted.
  Returns:
    The factorization of 2**m-1
  Throws:
    Value error, if the exponent is too large and the factorization
    is not known.
  """
  assert m > 0
  if m in PRIME_FACTORS:
    return PRIME_FACTORS[m]
  if m > 100:
    raise ValueError("m too large:" + str(m))
  if m % 2 == 0:
    factors = mersenne_factorization(m // 2) + _factor(2**(m // 2) + 1)
  else:
    factors = _factor(2**m - 1)
  factors = sorted(factors)
  PRIME_FACTORS[m] = factors
  return factors


def _factor(r: int) -> list[int]:
  """Simple integer factorization using trial division.
  
  This function is only used for small cases.
  No attempts has been made to optimize this.
  For large fields one should simply complete the factorization
  tables.
  
  Args:
    r: the integer to factor
  Returns:
    the list of prime factors
  """
  assert r > 0
  factors = []
  while r % 2==0:
    factors.append(2)
    r>>=1
  k = 3
  while k * k <= r:
    if r % k == 0:
      factors.append(k)
      r //= k
    else:
      k += 2
  if r > 1:
    factors.append(r)
  return factors

# Possible representations for polynomials in GF_2[x].
# * int: bit i is the coefficient of x^i
# * list: a list L of integers represents sum(x^i for i in L)
# * tuple, set: same as list
# * str: hexadecimal representation of the polynomial
#        a prefix 0xL is used for little endian representation.
PolyRep = Union[int, list, tuple, set, str]
BinPoly = int

def poly2int(x: PolyRep)-> BinPoly:
  """Converts various representations of a binary polynomial
     into an integer representation of the binary polynomial.
  """
  if isinstance(x, int):
    return x
  if isinstance(x, list) or isinstance(x, tuple) or isinstance(x, set):
    # list or tuple of elements that are set
    return sum(2**i for i in x)
  if isinstance(x, str):
    if x[:3] == "0xL":
      # prefix 0xL: hexadecimal little endian byte order
      # e.g. "0xL0107" -> 1 + x^8+x^9+x^10
      # This representation is used in AES-GCM-SIV
      x = x[3:]
      assert len(x) % 2 == 0
      res = 0
      for i in range(0, len(x), 2):
        res += int(x[i:i+2],16) << (4*i)
      return res
  raise Exception("not implemented")

def is_generator(g: BinPoly, poly: BinPoly) -> bool:
  """Determines whether g is a generator in the field GF_2[x]/(poly).
     The factorization of the Mersenne number 2^(degree(poly)) - 1 is needed
     for this. Hence this function only works for small degrees and
     degrees for which the factorization is precomputed in PrimeFactor.

     Args:
       g: the generator as integer
       poly: the polynomial as integer
     Returns:
       True if g is a generator, False if g is not a generator and None if
       there was an error, e.g. if poly is not irreducible.
  """
  g = poly2int(g)
  P = poly2int(poly)
  d = P.bit_length() - 1
  t = 2**d - 1
  if bin_exp(g, t, P) != 1:
    return None
  for p in mersenne_factorization(d):
    if bin_exp(g, t//p, P) == 1:
      return False
  return True


def _bin_mult4(x: BinPoly, y: BinPoly) -> BinPoly:
  """Multiplies two polynomials over GF_2[x].
  
  This version uses a small lookup table for the multiplication.
  """
  tab = [None] * 16
  tab[0] = 0
  tab[1] = y
  for i in range(2, len(tab), 2):
    tab[i] = tab[i >> 1] << 1
    tab[i + 1] = tab[i] ^ y
  res = 0
  k = 0
  while x:
    res ^= tab[x & 15] << k
    k += 4
    x >>= 4
  return res

def bin_mult(x: BinPoly, y: BinPoly) -> BinPoly:
  """Multiplies two polynomials over GF_2[x]"""
  if x > y:
    x, y = y, x
  if x.bit_length() > 16:
    return _bin_mult4(x, y)
  res = 0
  k = 0
  while x:
    if x & 1: res ^= y << k
    k += 1
    x >>= 1
  return res

def bin_square(x: BinPoly) -> BinPoly:
  """Computes the square of a polynomial over GF_2[x]."""
  res = 0
  for i in range(x.bit_length()):
    if x & (1 << i):
      res ^= 1 << (2*i)
  return res

def bin_mod(x: BinPoly, y: BinPoly) -> BinPoly:
  """Computes the remainder of x modulo y over GF_2[x]."""
  k = y.bit_length()
  bl = x.bit_length()
  while bl >= k:
    x^= y << (bl - k)
    bl = x.bit_length()
  return x

def bin_mod_sparse(x: BinPoly, bits: tuple) -> BinPoly:
  """Computes the remainder of x modulo sum(x^i for i in bits)
  
  Args:
    x: the polynomial to reduce
    bits: the bits of the modulus, this must be an ordered tuple.
  Returns:
    the remainder
  """
  degree = bits[-1]
  while x.bit_length() > degree:
    quot = x >> degree
    for i in bits:
      x ^= quot << i
  return x

def bin_mulmod(x: BinPoly, y: BinPoly, mod: BinPoly) -> BinPoly:
  return bin_mod(bin_mult(x, y), mod)

def bin_divmod(x: BinPoly, y: BinPoly) -> BinPoly:
  """Computes the quotiend and remainder of the division
     of x by y over GF_2[x]."""
  k = y.bit_length()
  q = 0
  t = x.bit_length()
  while (t - k) >= 0:
    x^= y << (t - k)
    q^= 1 << (t - k)
    t = x.bit_length()
  return q, x

def bin_div(x: BinPoly, y: BinPoly) -> BinPoly:
  """Divides the polynomial x by y over GF_2[x].
     I.e. if z = bin_div(x, y) then
     x ^ bin_mult(z, y) has degree smaller than y."""
  return bin_divmod(x,y)[0]

def bin_exp(x: BinPoly, n: int, y: BinPoly) -> BinPoly:
  """Computes x ** n % y over GF_2[x].
     Rsp. this is x ** n over GF_2[x]/(y)"""
  assert isinstance(n, int)
  if n < 0:
    n = -n
    x = bin_invmod(x, y)
  res = 1
  p = x
  while n:
    if n & 1:
      res = bin_mod(bin_mult(res, p), y)
    p = bin_mod(bin_mult(p, p), y)
    n >>= 1
  return res

def bin_inverse(x: BinPoly, k: int) -> BinPoly:
  """Returns p such that p is the inverse of x modulo x^k in GF_2[x]."""
  assert x & 1
  y = 1
  # Uses the following lifting:
  # If x * y == 1 (mod x^k) then
  #    (x * y)^2 == 1 (mod x^(2k)).
  mask = 2**k - 1
  r = x & mask
  while r != 1:
    y = bin_mult(y, r) & mask
    r = bin_mult(x, y) & mask
  return y


def bin_gcd(x: BinPoly, y: BinPoly) -> BinPoly:
  """GCD of binary polynomials.

  Args:
    x: 1st polynomial
    y: 2nd polynomial
  Returns:
    The GCD
  """
  while x:
    if x > y:
      x, y = y, x
    x, y = y ^ (x << (y.bit_length() - x.bit_length())), x
  return y


def bin_gcd_ex(a: BinPoly, b: BinPoly) -> BinPoly:
  """Extended GCD with polynomials.

  Args:
    a: 1st polynomial
    b: 2nd polynomial
  Returns:
    a triple g, r, s such that
    g = bin_gcd(r, s) = bin_mult(a, r) ^ bin_mult(b, s)
  """
  x, ax, bx = a, 1, 0
  y, ay, by = b, 0, 1
  while x:
    if x > y:
      x, y = y, x
      ax, ay = ay, ax
      bx, by = by, bx
    shift = y.bit_length() - x.bit_length()
    x, y = y ^ (x << shift), x
    ax, ay = ay ^ (ax << shift), ax
    bx, by = by ^ (bx << shift), bx
  # Invariants
  # assert bin_mult(ax, a) ^ bin_mult(bx, b) == x
  assert bin_mult(ay, a) ^ bin_mult(by, b) == y
  return y, ay, by


def bin_invmod(x: BinPoly, y: BinPoly) -> BinPoly:
  g, r, s = bin_gcd_ex(x, y)
  if g != 1:
    raise Exception("not invertible")
  return r


def bin_chrem(x0: BinPoly, p0: BinPoly, x1: BinPoly, p1: BinPoly) -> BinPoly:
  """Chinese remaindering with binary polynomials

  Args:
    x0: 1st remainder
    p0: 1st modulus
    x1: 2nd remainder
    p1: 2nd modulus (must be relatively prime to p0)
 
  Returns:
    x such that bin_mod(x, p0) == x0 and bin_mod(x, p1) == x1
  """
  g, a, b = bin_gcd_ex(p0, p1)
  if g != 1:
    raise ValueError("p0 and p1 are not coprime")
  s = bin_mulmod(x0 ^ x1, a, p1)
  res = x0 ^ bin_mult(s, p0)
  assert bin_mod(res, p1) == x1
  return res


def is_primitive(poly: BinPoly) -> bool:
  """Determines whether a polynomial is primitive.
  
  This function requires that the factorization of 2**degree-1
  can be computed in reasonable time. The table PRIME_FACTORS is used
  as a lookup table for polynomials of high degree.
  
  Args:
    poly: the polynomial to check
  Returns:
    True if the polynomial is primitive, False otherwise
  """
  d = poly.bit_length() - 1
  t = 2**d - 1
  if bin_exp(2, t, poly) != 1:
    return False
  for f in mersenne_factorization(d):
    if bin_exp(2, t//f, poly) == 1:
      return False
  return True


def Basis(v: list[BinPoly]) -> list[BinPoly]:
  """Returns a basis for a list of binary polynomial.

  """
  b = []
  # Find basis
  for x in v:
    for y in b:
      x = min(x, x^y)
    if x:
      b.append(x)
  # Simplify basis
  r = []
  for x in sorted(b):
    for y in r:
      x = min(x, x^y)
    r.append(x)
  return r


def little_endian_rep(poly: BinPoly) -> str:
  """Represents a polynomial using little endian ordering."""
  chars = "0123456789abcdef"
  res = '"0xL'
  while poly:
    rem = poly % 256
    poly = poly // 256
    res += chars[rem // 16]+chars[rem % 16]
  return res + '"'

# Forward reference to Element
ElementRef = "Element"
PolyRef = "Poly"
LinearPolyRef = "LinearPoly"

class GF:
  """Implements a finite binary field.
  """
  def __init__(self,
               poly: PolyRep,
               name: Optional[str] = None,
               polyrep=hex,
               generator: Optional[PolyRep] = None,
               trace_constant: Optional[PolyRep] = None,
               references: list[str] = []):
    """Constructs a new field.
 
    Args:
      poly: the polynomial that the defines the field. Must be irreducible.
      name: the name of the field
      polyrep: by default elements of the field are converted to hex when
         printed. This function can be selected to override the representation.
      trace_constant: A constant that is used to compute the absolute trace
         of an element. Since the trace is a linear function it can be computed
         as a sum of traces over all bits in the element. I.e., bit j of
         trace_constant is 1 iff the trace of (1 << j) is 1.
      references: a list of references for the given field.
    """
    self.poly = poly2int(poly)
    if isinstance(poly, tuple) and len(poly) <= 5:
      # Use sparse reduction
      self.sparse_poly = tuple(sorted(poly))
    else:
      self.sparse_poly = None
    self.name = name
    self.polyrep = polyrep
    self.references = references
    if generator is None:
      self.generator = None
    else:
      self.generator = self(generator)
    if trace_constant is None:
      self.trace_constant = None
    else:
      self.trace_constant = poly2int(trace_constant)

  def __call__(self, value: PolyRep):
    """Converts a binary polynomial into an element of this field."""
    return Element(self, poly2int(value))

  def get_generator(self):
    """Returns a generator of this field.
       This is either a generator defined in the initialization of the field,
       or the polynomial with the smallest integer representation.
       Computing a generator need the factorization of the order of the
       multiplicative group. Hence this only works for small fields or
       fields where the factorization of the Mersenne number is precomputed
       in PrimeFactor.
    """
    if self.generator :
      return self.generator
    i = 2
    while True:
      g = self(i)
      if g.is_generator():
        self.generator = g
        return g
      i += 1

  def trace1(self):
    """Returns an element of with trace 1.

    This is useful for solving quadratic equations.
    """
    if self.trace_constant:
      return Element(self, self.trace_constant & -self.trace_constant)
    else:
      raise ValueError("Not implemented")

  def degree(self) -> int:
    """Returns the degree of the field"""
    return self.poly.bit_length() - 1

  def reduce(self, poly: BinPoly) -> BinPoly:
    if self.sparse_poly:
      return bin_mod_sparse(poly, self.sparse_poly)
    else:
      return bin_mod(poly, self.poly)

  def __str__(self) -> str:
    if self.name:
      return self.name
    return "GF(2^" + str(self.degree()) + ")"

  def __repr__(self) -> str:
    if self.name:
      return self.name
    return "GF(" + self.polyrep(self.poly)+")"

class Element:
  """Represents an element of a binary field."""

  @util.type_check
  def __init__(self, field: GF, poly: BinPoly):
    assert 0 <= poly
    self.field = field
    self.poly = field.reduce(poly)

  def newelem(self, poly: BinPoly) -> ElementRef:
    """Converts a polynomial into an element in the same Field as self."""
    return Element(self.field, poly)

  # TODO: Should probably be removed, since operations are no
  #   longer associative:  e.g. (1 + 1) + field(1) != 1 + (1 + field(1)).
  #   Maybe 0 could remain as alias for field(0).
  def coerce(self, other) -> int:
    """Returns the polynomial of other converted to self"""
    if isinstance(other, Element):
      assert other.field == self.field
      return other.poly
    elif other == 1 or other == 0:
      return other
    else:
      raise ValueError("not implemented for type " + str(type(other)))

  def __add__(self, x) -> ElementRef:
    return self.newelem(self.poly ^ self.coerce(x))

  __sub__ = __add__

  def __mul__(self, x) -> ElementRef:
    return self.newelem(bin_mult(self.poly, self.coerce(x)))

  def inverse(self) -> ElementRef:
    g, r, s = bin_gcd_ex(self.poly, self.field.poly)
    if g != 1:
      raise Exception("not invertible")
    return self.newelem(r)

  def __int__(self) -> int:
    """Converts self to an integer.

    The conversion is the same as Section 2.3.9 of secg.org/sec1-v2.pdf
    """
    return self.poly

  def __truediv__(self, other) -> ElementRef:
    return self * other.inverse()

  __div__ = __truediv__

  def __eq__(self, other) -> ElementRef:
    if not isinstance(other, Element): return False
    if other.field != self.field: return False
    return self.poly == other.poly

  def __ne__(self, other) -> ElementRef:
    return not self == other

  def __neg__(self) -> ElementRef:
    return self

  def __pow__(self, n:int) -> ElementRef:
    return self.newelem(bin_exp(self.poly, n, self.field.poly))

  def __str__(self) -> str:
    return self.field.polyrep(self.poly)

  def __repr__(self) -> str:
    return repr(self.field) + "(" + self.field.polyrep(self.poly) + ")"

  def __hash__(self) -> int:
    return hash(self.poly)

  def __bool__(self) -> bool:
    return self.poly != 0

  def sqrt(self) -> int:
    return self ** 2 ** (self.field.degree() - 1)

  # can be optimized
  def order(self) -> int:
    """Computes the order of the element.
       This requires the factorization of the multiplicative group.
       Hence for large fields the factorization should be precomputed
       in PrimeFactor."""
    deg = self.field.degree()
    exp= 2**deg-1
    res = 1
    x = self
    one = self.newelem(1)
    factors = mersenne_factorization(deg)
    for p in factors[::-1]:
      # Loop invariants: x**exp == one  and  x == self**res
      exp = exp // p
      if x**exp != one:
        x = x**p
        res = res * p
    if x != one:
      if self**(2**deg - 1) != one:
        raise ValueError("Not a field")
      # Something wrong with the code?
      print(x, self, self**(2**deg - 1))
      raise AssertionError("Can't compute order")
    return res

  def is_generator(self) -> bool:
    """Return true iff self is a generator of the multiplicative
       group."""
    deg = self.field.degree()
    exp = 2**deg-1
    return self.order() == exp

  def norm(self, degree:int) -> ElementRef:
    """Return the norm over the subfield of given degree"""
    deg = self.field.degree()
    # Check that there is a proper subfield of degree degree.
    assert deg % degree == 0 and 1 < degree < deg
    r = self
    x = self
    for i in range(1, deg//degree):
      x = x ** (2**degree)
      r *= x
    return r

  def absolute_trace(self) -> ElementRef:
    """Computes the trace over GF(2)."""
    if self.field.trace_constant is not None:
      return self.field(parity(self.poly & self.field.trace_constant))
    else:
      return self.trace(1)

  def trace(self, degree:int) -> ElementRef:
    """Return the trace over the subfield of given degree"""
    deg = self.field.degree()
    # Check that there is a proper subfield of degree degree.
    assert deg % degree == 0 and 1 <= degree < deg
    r = self
    x = self
    for i in range(1, deg//degree):
      x = x ** (2**degree)
      r += x
    return r

  def dot(self, other) -> ElementRef:
    """self*other*x^{-degree}
       this operation is used in AES-GCM-SIV"""
    return self * other * self.field([self.field.degree()]).inverse()

  def _log_baby_step_giant_step(self, g: ElementRef, order: int) -> int:
    m = int(order**0.5 + 1)
    Log = {}
    p = self.newelem(1)
    for i in range(m):
      Log[p] = i
      p *= g
    q = p / self
    for j in range(m, order + 2 * m, m):
      if q in Log:
        return j - Log[q]
      q *= p
    raise Exception("can't compute log")

  def log(self) -> int:
    """computes log(self, g) using Pohlig-Hellman"""
    g = self.field.get_generator()
    if g is None:
      raise Exception("Field does not specify a generator")
    factors = mersenne_factorization(self.field.degree())
    if len(factors) != len(set(factors)):
      raise Exception("Log is only implemented for squarefree orders")
    # invariant: log(self) % m == xm
    xm = 0
    m = 1
    order = 2**self.field.degree() - 1
    for p in factors:
      gq = g ** (order // p)
      sq = self ** (order // p)
      xp = sq._log_baby_step_giant_step(gq, p)
      xm = mod_arith.chrem(xm, m, xp, p)
      m *= p
    assert g**xm == self
    return xm

class Poly:
  """Implements polynomials over a binary field."""

  def __init__(self, field: GF, coeffs: list[BinPoly]):
    """coefficients are just integers"""
    self.field = field
    while coeffs and coeffs[-1] == 0:
      coeffs.pop()
    self.coeffs = coeffs
  def __str__(self):
    return "Poly(" + repr(self.field) + ", [" + ", ".join(hex(x) for x in self.coeffs) + "])"
  def __repr__(self):
    return "[" + ", ".join(hex(x) for x in self.coeffs) + "]"
  def __bool__(self):
    return len(self.coeffs) > 0
  def coerce(self, other):
    """Returns the coefficients of other as polynomial"""
    if isinstance(other, Poly):
      assert other.field == self.field
      return other.coeffs
    elif isinstance(other, Element):
      assert other.field == self.field
      return [other.poly]
    elif other == 0:
      return []
    elif other == 1:
      return [1]
    else:
      raise ValueError("Not implemented for " + str(type(other)))

  def __add__(self, other) -> PolyRef:
    A = self.coeffs
    B = self.coerce(other)
    if len(A) < len(B): A,B = B,A
    A = A[:]
    for i in range(len(B)): A[i] ^= B[i]
    return Poly(self.field, A)

  def __mul__(self, other) -> PolyRef:
    A = self.coeffs
    B = self.coerce(other)
    if len(A) == 0 or len(B) == 0:
      R = []
    else:
      R = [0]*(len(A) + len(B) - 1)
      for i in range(len(A)):
        for j in range(len(B)):
          R[i+j] ^= bin_mult(A[i], B[j])
    for i in range(len(R)):
      R[i] = self.field.reduce(R[i])
    return Poly(self.field, R)

  def square(self) ->PolyRef:
    R = [0] * (len(self.coeffs) * 2 - 1)
    for i, c in enumerate(self.coeffs):
      R[2 * i] = self.field.reduce(bin_square(c))
    return Poly(self.field, R)

  def squarefree(self) -> PolyRef:
    x = Poly(self.field, [0,1])
    t = x
    for _ in range(self.field.degree()):
      t = t.square() % self
    return self.gcd(t + x)

  def monic(self) -> PolyRef:
    """Multiplies self by a scalar such that the result is monic"""
    if not self:
      return self
    if self.coeffs[-1] == 1:
      return self
    return self * self.field(self.coeffs[-1]).inverse()

  def __mod__(self, other) -> PolyRef:
    A = self.coeffs[:]
    B = self.coerce(other)
    degB = len(B) - 1
    if degB == -1:
      raise ValueError("degree is -1")
    elif degB == 0:
      assert B[degB] != 0
      return Poly(self.field, [])
    if B[degB] != 1:
      inv = self.field(B[degB]).inverse().poly
      B = [self.field.reduce(bin_mult(x, inv)) for x in B]
    for i in range(len(A)-1, degB-1, -1):
      c = self.field.reduce(A[i])
      if c == 0: continue
      for j in range(degB):
        A[i-degB+j] ^= bin_mult(B[j], c)
    A = [self.field.reduce(x) for x in A[:degB]]
    return Poly(self.field, A)

  def gcd(self, other):
    a, b = self, other
    while a:
      a, b = b % a, a
    return b.monic()

  def eval(self, x) -> PolyRef:
    if isinstance(x, Element):
      assert x.field == self.field
      x = x.poly
    if isinstance(x,int):
      res = 0
      for c in self.coeffs[::-1]:
        res = bin_mult(res, x)
        res = self.field.reduce(res) ^ c
      return Element(self.field, res)
    if isinstance(x, Poly):
      if len(self.coeffs) == 0: return Poly(self.field,[])
      r = Poly(self.field, [self.coeffs[-1].poly])
      for i in range(len(self.coeffs)-2,-1,-1):
        r *= x
        r += Poly(self.field, [self.coeffs[i].poly])
      return r
    raise Exception("not implemented for type:" + str(type(x)))

class LinearPoly:
  """Implements polynomials of the form sum(c[i]* x ** 2 ** i).
     Evaluating such polynomials is linear. I.e.
     p(y ^ z) == p(y) ^ p(z)."""
  def __init__(self, const, coeffs):
    """Represents the polynomial const + sum(coeffs[i]*x**(2**i))"""
    self.const = const
    self.coeffs = coeffs
    self.field = const.field

  def __add__(self, other) -> LinearPolyRef:
    if isinstance(other, Element):
      return LinearPoly(self.const+other, self.coeffs)
    assert isinstance(other, LinearPoly)
    A, B = self.coeffs, other.coeffs
    if len(A) < len(B): A,B = B,A
    R = A[:]
    for i in range(len(B)):
      R[i] += B[i]
    return LinearPoly(self.const + other.const, R)

  def __mul__(self, other) -> LinearPolyRef:
    if isinstance(other, LinearPoly):
      # Multiplying two linear polynomials typically does not result
      # in another linear polynomial.
      raise Exception("not implemented")
    return LinearPoly(self.const * other, [x * other for x in self.coeffs])

  def __mod__(self, other):
    if isinstance(other, Poly):
      if self.field != other.field:
        raise TypeError("not the same field")
      mod = other.monic()
      res = Poly(self.field, [self.const.poly])
      p = Poly(self.field, [0, 1]) % mod
      for x in self.coeffs:
        res += p * x
        p = p.square() % mod
      return res
    else:
      raise TypeError("wrong type")

  def square(self) -> LinearPolyRef:
    return LinearPoly(self.const * self.const,
       [self.field(0)] + [x * x for x in self.coeffs])

  def eval(self, other) -> ElementRef:
    if isinstance(other, LinearPoly):
      res = LinearPoly(self.const, [])
      for x in self.coeffs:
        res += other * x
        other = other.square()
      return res
    else:
      res = self.const
      for x in self.coeffs:
        res += other * x
        other = other * other
    return res

  def __repr__(self):
    coeffs = "[" + ", ".join(repr(x) for x in self.coeffs) + "]"
    return "LinearPoly(" + repr(self.const) + ", " + coeffs + ")"

  def __str__(self):
    res = str(self.const)
    for i in range(len(self.coeffs)):
      res += " + " + str(self.coeffs[i]) + " x^" + str(2**i)
    return res

def Fgen(field, generators):
  """Computes the polynomial prod_{a\in A}(x-a), where
     A is the set of sums of all subsets of generators).
     E.g. Fgen(F,[a,b]) computes x*(x-a)*(x-b)*(x-a-b)."""
  L = LinearPoly(field(0), [field(1)])
  for g in generators:
    # compute L(x) * L(x+g)
    L = L.square() + L * L.eval(field(g))
  return L

def solve_quad(a):
  """Solves x^2 + x + a  == 0
  >>> x = F32(12345)
  >>> S = solve_quad(x**2+x)
  >>> set(S) == {x, x+1}
  True
  """
  field = a.field
  m = field.trace1()
  y, c = field(0), field(0)
  for i in range(1,field.degree()):
    m = m * m
    c = c * c + a
    y += c * m
  y2 = y + field(1)
  if y * y2 == a: return [y, y2]
  return []


def solve_quadratic(a: Element, b: Element, c: Element) -> list[Element]:
  """Returns the solutions to a*x**2 + b*x + c == 0,
     where a,b,c are element of some binary field."""
  if a:
    ainv = a.inverse()
    b *= ainv
    c *= ainv
    if b:
      binv = b.inverse()
      c *= binv * binv
      return tuple(y * b for y in solve_quad(c))
    else:
      return [c.sqrt()]
  else:
    assert b
    return [c / b]

# References
BC_CMAC = "bouncycastle/crypto/mac/CMac.java"
SEC1 = "http://www.secg.org/sec1-v2.pdf"
SIV = "https://datatracker.ietf.org/doc/draft-madden-generalised-siv/"

# Some fields
F4 = GF((0, 1, 4), name="F4", trace_constant=(3,))

# used in AES
F8 = GF((0, 1, 3, 4, 8), name="F8", trace_constant=(5, 7), references=["AES"])

# used by different encryption modes: OCB, GCM, ...
F128 = GF((0, 1, 2, 7, 128), name="F128", trace_constant=(121, 127))

# used for Aes-gcm-siv
F128siv = GF((0, 121, 126, 127, 128),
             name="F128siv",
             trace_constant=0x370a6e14dc29b85370a6e14dc29b8536,
             polyrep=little_endian_rep,
             references=["AES-GCM-SIV"])

# Potential alternatives:
F32 = GF((0, 3, 13, 16, 32), name="F32", trace_constant=(19, 29))
F127 = GF((0, 1, 127), name="F127", trace_constant=(0,))

# Fields from http://www.secg.org/sec1-v2.pdf
F163 = GF((0, 3, 6, 7, 163), name="F163", trace_constant=(0, 157))
F233 = GF((0, 74, 233), name="F233", trace_constant=(0, 159))
F239 = GF((0, 36, 239), name="F239", trace_constant=(0, 203))
F239alt = GF((0, 158, 239), name="F239alt", trace_constant=(0, 81, 162))
F283 = GF((0, 5, 7, 12, 283), name="F283", trace_constant=(0, 271))
F409 = GF((0, 87, 409), name="F409", trace_constant=(0,))
F571 = GF((0, 2, 5, 10, 571), name="F571", trace_constant=(0, 561, 569))

# Probably X9.62
F191 = GF((0, 9, 191), name="F191", trace_constant=(0,))
F359 = GF((0, 68, 359), name="F359", trace_constant=(0, 291))
F431 = GF((0, 120, 431), name="F431", trace_constant=(0, 311))

# Fields from https://datatracker.ietf.org/doc/draft-madden-generalised-siv/
# The draft falsly claims that the polynomial are primitive, but some are only
# irreducible.
F96 = GF((0, 6, 9, 10, 96), name="F96", trace_constant=(87,), references=[SIV])
F160 = GF((0, 2, 3, 5, 160),
          name="F160",
          trace_constant=(155, 157),
          references=[SIV, BC_CMAC])
F192 = GF((0, 1, 2, 7, 192),
          name="F192",
          trace_constant=(185, 191),
          references=[SIV, BC_CMAC])
F224 = GF((0, 3, 8, 9, 224),
          name="F224",
          trace_constant=(215, 221),
          references=[SIV, BC_CMAC])
F256 = GF((0, 2, 5, 10, 256),
          name="F256",
          trace_constant=(251,),
          references=[SIV, BC_CMAC])
F384 = GF((0, 2, 3, 12, 384),
          name="F384",
          trace_constant=(381,),
          references=[SIV, BC_CMAC])
F512 = GF((0, 2, 5, 8, 512),
          name="F512",
          trace_constant=(507,),
          references=[SIV, BC_CMAC])

# Simpler reduction
F128ex = GF((0, 7, 17, 24, 128), trace_constant=(111, 121), name="F128ex")

# Addional fields from bouncycastle/crypto/mac/CMac.java
F64 = GF((0, 1, 3, 4, 64),
         name="F64",
         trace_constant=(61, 63),
         references=[BC_CMAC])
F320 = GF((0, 2, 3, 5, 160),
          name="F320",
          trace_constant=(155, 157),
          references=[BC_CMAC])
F448 = GF((0, 4, 6, 11, 448),
          name="F448",
          trace_constant=(437,),
          references=[BC_CMAC])
F768 = GF((0, 4, 17, 19, 768),
          name="F768",
          trace_constant=(749, 751),
          references=[BC_CMAC])
F1024 = GF((0, 1, 6, 19, 1024),
           name="F1024",
           trace_constant=(1005, 1023),
           references=[BC_CMAC])
F2048 = GF((0, 13, 14, 19, 2048),
           name="F2048",
           trace_constant=(2029, 2035),
           references=[BC_CMAC])


def defined_fields():
  for n, f in globals().items():
    if isinstance(f, GF):
      yield n, f

if __name__ == "__main__":
  pass
