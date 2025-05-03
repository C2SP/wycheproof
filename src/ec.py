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

# This is crappy quick and dirty code that must only be used for experiments.
# Implements elliptic curves

import group
import mod_arith
from typing import Optional, Union

# Verify all point operations by checking if the points are on the curve.
EcVerify = False

# TODO: This definition is lose. Explicit type aliases in python 3.10
#   might allow stricter type hints.
EcPoint = group.Point


class EcInfPoint(EcPoint):

  def __init__(self, curve):
    self.curve = curve

  def __add__(self, p: EcPoint) -> EcPoint:
    return p

  __radd__ = __add__

  def __sub__(self, p: EcPoint) -> EcPoint:
    return -p

  def __rsub__(self, p: EcPoint) -> EcPoint:
    return p

  def __mul__(self, n: int) -> EcPoint:
    return self

  __rmul__ = __mul__

  def __neg__(self) -> EcPoint:
    return self

  def __str__(self) -> str:
    return "Inf"

  __repr__ = __str__

  def __bool__(self) -> bool:
    return False

class EcMod:
  """An elliptic curve over Z/(mod Z) in Weierstrass form"""

  def __init__(self, a: int, b: int, mod: int):
    self.a = a
    self.b = b
    self.mod = mod

  def reduce(self, x: int) -> int:
    return x % self.mod

  def fraction(self, numer: int, denom: int) -> int:
    return numer * pow(denom, -1, self.mod) % self.mod

  def discriminant(self) -> int:
    return (-4 * self.a**3 - 27 * self.b**2) % self.mod

  def is_on_curve(self, x, y) -> bool:
    return (y * y - ((x * x + self.a) * x + self.b)) % self.mod != 0

  def j(self) -> int:
    return self.fraction(1728 * 4 * self.a**3, 27 * self.b**2 + 4 * self.a**3)

  def zero(self) -> EcPoint:
    return EcInfPoint(self)

  def point(self, x: int, y: int, verify: bool = False) -> EcPoint:
    if verify:
      assert self.is_on_curve(x, y)
    return EcModPoint(self, x, y)

  def point_from_x(self, x) -> Optional[EcPoint]:
    rhs = ((x * x % self.mod + self.a) * x + self.b) % self.mod
    y = mod_arith.modsqrt(rhs, self.mod)
    if y is not None:
      return self.point(x, y)

  def twist(self) -> "EcMod":
    """Returns a quadratic twist curve"""
    assert self.mod % 4 == 3
    return EcMod(self.a, -self.b % self.mod, self.mod)


class EcModPoint(group.Point):
  """A point on a Weierstrass curve"""

  def __init__(self, curve: EcMod, x: int, y: int, verify: bool = True):
    if verify:
      x = x % curve.mod
      y = y % curve.mod
      if not curve.is_on_curve(x, y):
        raise ValueError("Point is not on curve")
    self.curve = curve
    self.x = x
    self.y = y

  def __neg__(self) -> EcPoint:
    c = self.curve
    return c.point(self.x, c.reduce(-self.y), EcVerify)

  def __eq__(self, p: EcPoint) -> bool:
    return (isinstance(p, EcModPoint) and self.curve == p.curve and
            self.x == p.x and self.y == p.y)

  def __repr__(self) -> str:
    return "(%s, %s)" % (repr(self.x), repr(self.y))

  def __bool__(self) -> bool:
    return True

  def zero(self) -> EcPoint:
    return self.curve.zero()

  def affine(self) -> tuple[int, int]:
    return (self.x, self.y)

  def affine_x(self) -> int:
    return self.x

  def affine_y(self) -> int:
    return self.y

  def __add__(self, point: EcPoint) -> EcPoint:
    mod = self.curve.mod
    if isinstance(point, EcModPoint) and self.curve == point.curve:
      if self.x == point.x:
        if self.y + point.y == mod or (self.y == 0 and point.y == 0):
          return EcInfPoint(self.curve)
        elif self.y == point.y:
          num = (3 * self.x * self.x + self.curve.a) % mod
          den = 2 * self.y
          t = num * pow(den, -1, mod) % mod
        else:
          raise Exception("Unexpected points:")
      else:
        inv = pow(self.x - point.x, -1, mod)
        t = (self.y - point.y) * inv % mod
      x = (t * t - self.x - point.x) % mod
      y = (t * (self.x - x) - self.y) % mod
      return EcModPoint(self.curve, x, y, EcVerify)
    else:
      return NotImplemented

class EcModPointJacobian(group.Point):
  """A point on a Weierstrass curve using Jacobian coordinates.

  Based on
  https://en.wikibooks.org/wiki/Cryptography/Prime_Curve/Jacobian_Coordinates
  """

  def __init__(self,
               curve: "EcModJacobian",
               x: int,
               y: int,
               z: int = 1,
               verify: bool = True):
    if z == 0:
      raise ValueError("Use EcInfPoint for point at infinity")
    if verify:
      mod = curve.mod
      if not 0 <= x < mod:
        raise ValueError("x not reduced")
      if not 0 <= y < mod:
        raise ValueError("y not reduced")
      if not 0 <= z < mod:
        raise ValueError("z not reduced")
      if x == y == z == 0:
        raise ValueError("x, y and z cannot all be 0")
      if not curve.is_on_curve(x, y, z):
        raise ValueError("Point is not on curve")
    self.curve = curve
    self.x = x
    self.y = y
    self.z = z

  def __repr__(self):
    x, y = self.affine()
    return f"({x}, {y})"

  def __bool__(self):
    return True

  def __eq__(self, p: EcPoint) -> False:
    if not isinstance(p, EcModPointJacobian):
      return False
    if self.curve != p.curve:
      return False
    mod = self.curve.mod
    dx = self.x * p.z**2 - p.x * self.z**2
    if dx % mod != 0:
      return False
    dy = self.y * p.z**3 - p.y * self.z**3
    if dy % mod != 0:
      return False
    return True

  def affine(self) -> tuple[int, int]:
    """Returns affine coordinates of this point."""
    mod = self.curve.mod
    inv = pow(self.z, -1, mod)
    x = self.x * inv**2 % mod
    y = self.y * inv**3 % mod
    return (x, y)

  def affine_x(self) -> int:
    return self.affine()[0]

  def affine_y(self) -> int:
    return self.affine()[1]

  def double(self) -> EcPoint:
    mod = self.curve.mod
    x, y, z = self.x, self.y, self.z
    if y == 0:
      return EcInfPoint(self.curve)
    s = 4 * x * y * y % mod
    # or m = 3 *  (x+z  **  2) *  (x-z  **  2) if a == -3
    m = (3 * x * x + self.curve.a * z**4) % mod
    x2 = (m * m - 2 * s) % mod
    y2 = (m * (s - x2) - 8 * y**4) % mod
    z2 = 2 * y * z % mod
    return EcModPointJacobian(self.curve, x2, y2, z2, EcVerify)

  def zero(self) -> EcPoint:
    return self.curve.zero()

  def __neg__(self) -> EcPoint:
    return EcModPointJacobian(self.curve, self.x, -self.y % self.curve.mod, self.z)

  def __add__(self, other: EcPoint) -> Union[EcPoint, type(NotImplemented)]:
    if not isinstance(other, EcModPointJacobian) or other.curve != self.curve:
      return NotImplemented
    mod = self.curve.mod
    x1, y1, z1 = self.x, self.y, self.z
    x2, y2, z2 = other.x, other.y, other.z
    u1 = x1 * z2 * z2 % mod
    u2 = x2 * z1 * z1 % mod
    s1 = y1 * z2**3 % mod
    s2 = y2 * z1**3 % mod
    if u1 == u2:
      if s1 != s2:
        return EcInfPoint(self.curve)
      else:
        return self.double()
    h = u2 - u1 % mod
    r = s2 - s1 % mod
    x3 = (r * r - h**3 - 2 * u1 * h**2) % mod
    y3 = (r * (u1 * h**2 - x3) - s1 * h**3) % mod
    z3 = h * z1 * z2 % mod
    return EcModPointJacobian(self.curve, x3, y3, z3, EcVerify)

class EcModJacobian:
  """An elliptic curve over Z/(mod Z) using Jacobian coordinates."""

  def __init__(self, a: int, b: int, mod: int):
    self.a = a
    self.b = b
    self.mod = mod

  def reduce(self, x: int) -> int:
    return x % self.mod

  def fraction(self, numer: int, denom: int) -> int:
    return self.reduce(numer * pow(denom, -1, self.mod))

  def zero(self) -> EcPoint:
    return EcInfPoint(self)

  def is_on_curve(self, x: int, y: int, z: int = 1) -> bool:
    mod = self.mod
    if z % mod == 0:
      raise ValueError("z must not be 0")
    d = y * y - (x * x + self.a * z**4) * x - self.b * z**6
    return d % mod == 0

  def point(self, x: int, y: int, z: int = 1, verify=True) -> EcPoint:
    return EcModPointJacobian(self, x, y, z, verify=verify)

  def point_from_x(self, x: int) -> Optional[EcPoint]:
    rhs = ((x * x % self.mod + self.a) * x + self.b) % self.mod
    y = mod_arith.modsqrt(rhs, self.mod)
    if y is not None:
      return self.point(x, y)

  def twist(self) -> "EcModJacobian":
    """Returns a quadratic twist curve"""
    assert self.mod % 4 == 3
    return EcModJacobian(self.a, -self.b % self.mod, self.mod)
