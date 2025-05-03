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

# Elliptic curve multiplication over binary curves using projective
# coordinates. This would be more efficient than using affine coordinates
# if a fast carryless multiplication were available.
# Such a multiplication is currently missing, hence this implementation is
# quite slow.
import ec
import ec_binary
import gf
import group
import util
from typing import Optional, Any

Point = tuple[Any, Any]


class EcBinaryProjective:
  """A binary elliptic curve defined by

       y^2 + xy = x^3 + ax^2 + b
    """

  def __init__(self, field: gf.GF, a: gf.Element, b: gf.Element,
               verify_points:bool = False):
    if a.field != field:
      raise ValueError("a not an element of the field")
    if b.field != field:
      raise ValueError("b not an element of the field")
    self.a = a
    self.b = b
    self.field = field
    self.verify_points = verify_points

  @util.type_check
  def is_on_curve(self, x: gf.Element, y: gf.Element, z:gf.Element) -> bool:
    if x.field != self.field:
      raise ValueError("x is not an element of the field")
    if y.field != self.field:
      raise ValueError("y is not an element of the field")
    if z.field != self.field:
      raise ValueError("z is not an element of the field")
    if not z:
      raise ValueError("z must not be zero")
    return y * (y + x) * z == (x + self.a * z) * x * x + self.b * z * z * z

  def get_ys(self, x: gf.Element) -> list[gf.Element]:
    c = (x + self.a) * x * x + self.b
    return gf.solve_quadratic(self.field(1), x, c)

  @util.type_check
  def get_y(self, x: gf.Element) -> Optional[gf.Element]:
    ys = self.get_ys(x)
    if ys:
      return ys[0]

  def point_from_x(self, x):
    """Returns a point with x-coordinate x or None if no such point exists.

    Args:
      x: the x-coordinate

    Returns:
      a point or None
    """
    if isinstance(x, int):
      x = self.field(x) 
    y = self.get_y(x)
    if y is not None:
      return self.point(x, y)

  def zero(self):
    return ec.EcInfPoint(self)

  def point(self,
            x: gf.Element,
            y: gf.Element,
            z: Optional[gf.Element] = None,
            verify: bool = True):
    return EcBinaryPointProjective(self, x, y, z, verify)

  # def twist(self):
  #  '''Returns a quadratic twist curve'''
  #  assert self.mod % 4 == 3
  #  return EcMod(self.a, -self.b % self.mod, self.mod)


class EcBinaryPointProjective(group.Point):
  """Based on 
  """
  def __init__(self,
               curve,
               x: gf.Element,
               y: gf.Element,
               z: Optional[gf.Element] = None,
               verify: bool = False):
    if z is None:
      z = curve.field(1)
    if verify or curve.verify_points:
      if not curve.is_on_curve(x, y, z):
        raise ValueError('Point is not on curve')
    if not z:
      raise ValueError('Use EcInfPoint for point at infinity')
    self.curve = curve
    self.x = x
    self.y = y
    self.z = z

  def __repr__(self):
    return '(%s, %s)' % self.affine()

  def __bool__(self):
    return True

  def __eq__(self, p):
    if not isinstance(p, EcBinaryPointProjective):
      return False
    if self.curve != p.curve:
      return False
    if self.x * p.z != p.x * self.z:
      return False
    if self.y * p.z != p.y * self.z:
      return False
    return True

  def affine(self):
    return self.x / self.z, self.y / self.z

  def affine_x(self):
    return self.x / self.z

  def affine_y(self):
    return self.y / self.z

  def __neg__(self):
    return EcBinaryPointProjective(
      self.curve, self.x, self.y + self.x, self.z)

  def zero(self):
    return self.curve.zero()

  def __add__(self, point):
    p = point
    one = self.curve.field(1)
    if isinstance(point, EcBinaryPointProjective) and self.curve == point.curve:
      xz = self.x * p.z
      yz = self.y * p.z
      zx = self.z * p.x
      zy = self.z * p.y
      if xz == zx:
        if xz + yz == zy:
          return ec.EcInfPoint(self.curve)
        else:
          assert yz == zy
          xx = self.x * self.x
          l_num = self.y * self.z + xx
          l_den = self.x * self.z
          l_den2 = l_den * l_den
          l_den3 = l_den * l_den2
          z3 = l_den3
          x3 = l_num * (l_num + l_den) + self.curve.a * l_den2
          y3 = (xx * xx + x3) * l_den + l_num * x3 
          # y3 = y3num / z3
          return EcBinaryPointProjective(self.curve, x3 * l_den, y3, z3)
      else:
        zz = self.z * p.z
        l_num = yz + zy
        l_den = xz + zx
        l_den2 = l_den * l_den   # = (xz)^2 + (zx)^2
        l_den3 = l_den2 * l_den
        z3 = l_den3 * zz
        x3 = (l_den3 
              + l_num * (l_num + l_den) * zz
              + self.curve.a * l_den2 * zz)
        y3 = (l_num * l_den2 * xz
              + (l_den + l_num) * x3
              + l_den3 * yz )
        return EcBinaryPointProjective(self.curve, x3 * l_den, y3, z3)
    else:
      return NotImplemented


def test_projective(verify:bool=True):
  from time import time
  start = time()
  for group in ec_binary.groups():
    gx, gy = group.generator().affine()
    c = group.curve
    c_proj = EcBinaryProjective(c.field, c.a, c.b, verify_points=verify)
    assert c_proj.is_on_curve(gx, gy, c_proj.field(1))
    assert c_proj.is_on_curve(gx * gx, gy * gx, gx)
    g_proj = c_proj.point(gx * gx, gy * gx, gx)
    t = g_proj * group.n
    assert not t
  print(time() - start)

def test_comparison():
  from time import time
  start = time()
  for group in ec_binary.groups():
    g = group.generator()
    gx, gy = g.affine()
    c = group.curve
    c_proj = EcBinaryProjective(c.field, c.a, c.b)
    g_proj = c_proj.point(gx * gx, gy * gx, gx)
    for i in range(1, 35):
      gi = (g * i).affine()
      gip = (g_proj * i).affine()
      assert gi == gip 
  print(time() - start)

if __name__ == "__main__":
  test_projective(True)
  test_projective(False)
  test_comparison()
