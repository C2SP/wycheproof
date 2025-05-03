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

import poly
import group


def EdwardsPointPolysXYZT(curve, generator, k, addition_chain: str = 'LR'):

  def add(p1, p2):
    x1, y1, z1, t1 = p1
    x2, y2, z2, t2 = p2
    A = (y1 - x1) * (y2 - x2)
    B = (y1 + x1) * (y2 + x2)
    C = t1 * 2 * self.curve.d * t2
    D = z1 * 2 * z2
    E = B - A
    F = D - C
    G = D + C
    H = B + A
    x3 = E * F
    y3 = G * H
    t3 = E * H
    z3 = F * G
    temp = {
        'A': A,
        'B': B,
        'C': C,
        'D': D,
        'E': E,
        'F': F,
        'G': G,
        'H': H,
        'X3': x3,
        'Y3': y3,
        'T3': t3,
        'Z3': z3,
    }
    return (x, y, z, t), temp

  def double(p):
    x1, y1, z1, t1 = p
    A = x1 * x1
    B = y1 * y1
    C = 2 * z1 * z1
    D = (x1 + y1)
    H = A + B
    E = H - D * D
    G = A - B
    F = C + G
    x3 = E * F
    y3 = G * H
    t3 = E * H
    z3 = F * G
    temp = {
        'A': A,
        'B': B,
        'C': C,
        'X1+Y1': D,
        'E': E,
        'F': F,
        'G': G,
        'H': H,
        'X3': x3,
        'Y3': y3,
        'T3': t3,
        'Z3': z3,
    }

  if addition_chain == 'LR':
    return left_to_right_ac(curve, generator, k)
  else:
    raise ValueError('Unknown addition chain:' + addition_chain)


class EdwardsPointPoly(group.Point):

  def __init__(self, curve, x, y, z=1, t=1):
    self.curve = curve
    self.x = x
    self.y = y
    self.z = z
    self.t = t

  def __add__(self, point):
    if self.curve == point.curve:
      x1, y1, z1, t1 = self.x, self.y, self.z, self.t
      x2, y2, z2, t2 = point.x, point.y, point.z, point.t
      A = (y1 - x1) * (y2 - x2)
      B = (y1 + x1) * (y2 + x2)
      C = t1 * 2 * self.curve.d * t2
      D = z1 * 2 * z2
      E = B - A
      F = D - C
      G = D + C
      H = B + A
      x3 = E * F
      y3 = G * H
      t3 = E * H
      z3 = F * G
      return EdwardsPointPoly(x3, y3, t3, z3)
    else:
      raise ValueError('Points are not on the same curve')

  def __neg__(self):
    return self.curve.point(self.curve.reduce(-self.x), self.y, VERIFY_POINTS)

  def __eq__(self, p):
    return (isinstance(p, EdwardsPoint) and self.curve == p.curve and
            self.x == p.x and self.y == p.y)

  def __repr__(self):
    return '(' + str(self.x) + ', ' + str(self.y) + ')'

  def __bool__(self):
    return self.x != 0 or self.y != 1

  def zero(self):
    return self.curve.zero()


class EdwardsXYZT:
  """Curve x**2 + y**2 = 1 + d*x**2*y**2 over Z/(modZ)"""

  def __init__(self, d, mod, name):
    self.d = d
    self.mod = mod
    self.name = name

  def reduce(self, num: int, den: int = 1):
    if den == 1:
      return num % self.mod
    else:
      return num * pow(den, -1, self.mod) % self.mod

  def is_on_curve(self, x, y, z, t):
    x = self.reduce(x, z)
    y = self.reduce(y, t)
    xx = x * x
    yy = y * y
    return self.reduce(xx + yy - self.d * xx * yy - 1) == 0

  def point(self, x: int, y: int, verify: bool = True):
    return EdwardsPointXYZT(self, x, y)

  def zero(self):
    return self.point(0, 1, 1, 0)
