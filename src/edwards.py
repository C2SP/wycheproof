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

# Allows forward declarations
from __future__ import annotations

import group

# Determines is all point operations should be verified
VERIFY_POINTS = False

class EdwardsPoint(group.Point):

  def __init__(self, curve: Edwards, x: int, y: int, verify=True):
    if verify:
      if not curve.is_on_curve(x, y):
        raise ValueError('Point is not on curve', x, y)
    self.curve = curve
    self.x = x
    self.y = y

  def __add__(self, point: EdwardsPoint) -> EdwardsPoint:
    if self.curve == point.curve:
      prod = self.x * self.y * point.x * point.y
      xnum = self.x * point.y + self.y * point.x
      xden = 1 + self.curve.d * prod
      ynum = self.y * point.y - self.x * point.x
      yden = 1 - self.curve.d * prod
      x = self.curve.reduce(xnum, xden)
      y = self.curve.reduce(ynum, yden)
      return self.curve.point(x, y, VERIFY_POINTS)
    else:
      raise ValueError('Points are not on the same curve')

  def __neg__(self) -> EdwardsPoint:
    return self.curve.point(self.curve.reduce(-self.x), self.y, VERIFY_POINTS)

  def __eq__(self, p: EdwardsPoint):
    return (self.curve == p.curve and self.x == p.x and self.y == p.y)

  def __repr__(self):
    return '(' + str(self.x) + ', ' + str(self.y) + ')'

  def __bool__(self):
    return self.x != 0 or self.y != 1

  def zero(self):
    return self.curve.zero()

# TODO: Merge curves.
#   There are some additional proposals for curves using
#     k * x**2 + y**2 + 1 = d*x**2 * y**2.
#   E.g., Bandersnatch uses k = -5
#   The code here does not have to be very efficient.
#   Hence a generalisation should be possible.
class Edwards:
  """Curve x**2 + y**2 = 1 + d*x**2*y**2 over Z/(modZ)"""

  def __init__(self, d: int, mod: int, name: str):
    self.d = d
    self.mod = mod
    self.name = name

  def reduce(self, num: int, den: int = 1) -> int:
    if den == 1:
      return num % self.mod
    else:
      return num * pow(den, -1, self.mod) % self.mod

  def is_on_curve(self, x: int, y: int) -> bool:
    xx = x * x
    yy = y * y
    return self.reduce(xx + yy - self.d * xx * yy - 1) == 0

  def point(self, x: int, y: int, verify: bool = True) -> EdwardsPoint:
    return EdwardsPoint(self, x, y, verify)

  def zero(self) -> EdwardsPoint:
    return self.point(0, 1)


class TwistedEdwardsPoint(group.Point):

  def __init__(self,
               curve: TwistedEdwards,
               x: int,
               y: int,
               verify: bool = True):
    if verify:
      if not curve.is_on_curve(x, y):
        raise ValueError('Point is not on curve', x, y)
    self.curve = curve
    self.x = x
    self.y = y

  def __add__(self, point: TwistedEdwardsPoint) -> TwistedEdwardsPoint:
    if self.curve == point.curve:
      prod = self.x * self.y * point.x * point.y
      xnum = self.x * point.y + self.y * point.x
      xden = 1 + self.curve.d * prod
      ynum = self.y * point.y + self.x * point.x
      yden = 1 - self.curve.d * prod
      x = self.curve.reduce(xnum, xden)
      y = self.curve.reduce(ynum, yden)
      return self.curve.point(x, y, VERIFY_POINTS)
    else:
      raise ValueError('Points are not on the same curve')

  def __neg__(self) -> TwistedEdwardsPoint:
    return self.curve.point(self.curve.reduce(-self.x), self.y, VERIFY_POINTS)

  def __eq__(self, p) -> TwistedEdwardsPoint:
    return (isinstance(p, TwistedEdwardsPoint) and self.curve == p.curve and
            self.x == p.x and self.y == p.y)

  def __repr__(self) -> str:
    return '(' + str(self.x) + ', ' + str(self.y) + ')'

  def __bool__(self) -> str:
    return self.x != 0 or self.y != 1

  def zero(self) -> TwistedEdwardsPoint:
    return self.curve.zero()

class TwistedEdwards:
  """Curve -x**2 + y**2 = 1 + d*x**2*y**2 over Z/(modZ).

       This curve is used for Ed25519.
  """

  def __init__(self, d: int, mod: int, name: str):
    self.d = d
    self.mod = mod
    self.name = name
    self.I = pow(2, (mod - 1) // 4, mod)

  def reduce(self, num: int, den: int = 1):
    if den == 1:
      return num % self.mod
    else:
      return num * pow(den, -1, self.mod) % self.mod

  def is_on_curve(self, x: int, y: int) -> bool:
    xx = x * x
    yy = y * y
    return self.reduce(-xx + yy - self.d * xx * yy - 1) == 0

  def point(self, x: int, y: int, verify: bool = True) -> TwistedEdwardsPoint:
    return TwistedEdwardsPoint(self, x, y, verify)

  def point_from_y(self, y: int, xbit: int = 0) -> TwistedEdwardsPoint:
    xx = self.reduce((y * y - 1), self.d * y * y + 1)
    x = pow(xx, (self.mod + 3) // 8, self.mod)
    if (x * x - xx) % self.mod != 0:
      x = (x * self.I) % self.mod
    if x & 1 != xbit:
      x = self.mod - x
    return self.point(x, y)

  def zero(self) -> TwistedEdwardsPoint:
    return self.point(0, 1)


edwards25519 = TwistedEdwards(
    d = -121665 * pow(121666, -1, 2**255 - 19),
    mod = 2**255 - 19,
    name = 'edwards25519')

edwards448 = Edwards(
    d = -39081,
    mod = 2**448 - 2**224 - 1,
    name = 'edwards448')

# The Edwards curve from Section 4.2 in RFC 7748
edwards448Rfc7748 = Edwards(
    d = int('611975850744529176160423220965553317543219696871016626328968936415'
            '087860042636474891785599283666020414768678979989378147065462815545'
            '017'),
    mod = 2**448 - 2**224 - 1,
    name = 'edwards448Rfc7748')

# Other curves that might be added here:
#  - Bandersnatch (requires somewhat extended curve definitions)
#    Maybe the curves can be merged
#

