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

from poly import Polynomial
import ec_groups
# use as Polynomial(coeffs, mod)


def division_polynomial(a: int, b: Polynomial, p: int, n: int) -> Polynomial:
  """Returns a factor of a division polynomial or order n.

  The roots of the result are the x-coordinate of points of
  order n on the curve y^2 = x^3 + ax + b.
  Args:
    a: coefficient of the curve
    b: coefficient of the curve. This is a polynomial in x.
    p: the characteristic of the field
    n: the order of the point.
  Returns: a factor of the division polynomial
  """
  if n == 3:
    # 3x^4 + 6ax^2 + 12bx - a^2
    return (Polynomial([-a**2, 0, 6 * a, 0, 3], p) + Polynomial([0, 12], p) * b)
  elif n == 4:
    # x^6 + 5ax^4 + 20bx^3 - 5a^2x^2 - 8b^2 - a^3
    return (Polynomial([-a**3, 0, -5 * a**2, 0, 5 * a, 0, 1], p) +
            Polynomial([0, -4 * a, 0, 20], p) * b + Polynomial([-8], p) * b * b)
  else:
    raise ValueError("not implemented")


def gen_special_point(curve1, curve2, n: int = 3):
  """Yields test vectors for invalid curve attacks.

  The function yields tuples (p, b) such that p is a point
  on curve1 and p is a point of order n curve2 with modified
  parameter b
  """

  # I have no idea how to do this if the curves don't use
  # the same field
  if curve1.p != curve2.p:
    raise ValueError("Not implemented")
  p = curve1.p
  a1 = curve1.a
  a2 = curve2.a
  b1 = curve1.b

  div_poly = division_polynomial(a2, Polynomial([b1, a1 - a2], p), p, n)
  for x in div_poly.roots():
    y = curve1.get_y(x)
    if y is not None:
      b = ((a1 - a2) * x + b1) % p
      yield (x, y), b


def find_points(groups=None):
  if groups is None:
    groups = ec_groups.predefined_curves
    for i in range(len(groups)):
      for j in range(len(groups)):
        if i == j:
          continue
        g1 = groups[i]
        g2 = groups[j]
        if g1.p != g2.p:
          continue
        for order in (3, 4):
          for point, b in gen_special_point(g1, g2, order):
            x, y = point
            # Checks that point is on g1
            assert g1.is_on_curve(x, y)
            # Checks that point has order 'order' on modified curve.
            generator = point  # Could be chosen arbitrarily
            modified_group = ec_groups.EcPrimeGroup(g2.p, order, g2.a, b, generator,
                                               None)
            p = modified_group.get_point(x, y)
            actual_order = None
            for k in range(1, order + 1):
              if not p * k:
                actual_order = k
                break
            assert actual_order is not None
            if actual_order < order:
              continue
            print("  { 'group1': %s,\n"
                  "    'group2': %s,\n"
                  "    'x': %d,\n"
                  "    'y': %d,\n"
                  "    'b': %d,\n"
                  "    'order': %d}," %
                  (repr(g1.name), repr(g2.name), x, y, b, order))


if __name__ == "__main__":
  find_points()
