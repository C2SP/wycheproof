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

import AST
import collections
import ec_groups
import json
import poly
import pprint
from typing import Optional

def special_x(group: ec_groups.EcPrimeGroup):
  """Yields x-coordinates of special points."""
  for x in [0, 1, 2, 3]:
    yield x % group.p, f"point with coordinate x = {x}"

def special_y(group: ec_groups.EcPrimeGroup):
  """Yields x-coordinates of points with special y."""
  p = group.p
  a = group.a
  b = group.b
  x = poly.Polynomial([0, 1], p)
  for y in [0, 1, 2, 3]:
    y_sqr = (x * x + a) * x + b
    for x0 in (y_sqr - y * y).roots():
      yield x0, f"point with coordinate y = {y}"


def special_projective(group: ec_groups.EcPrimeGroup, target: list[int] = None):
  """Yields x-coordinates of special points for doubling a point using

     projective coordinates.

     if (Y == 0)
       return POINT_AT_INFINITY
     W = 3*X^2 + a*Z^2
     S = Y*Z
     B = X*Y*S
     H = W^2 - 8*B
     X' = 2*H*S
     Y' = W*(4*B - H) - 8*Y^2*S^2
     Z' = 8*S^3
     return (X', Y', Z')
  """
  if target is None:
    target = [-2, -1, 0, 1, 2]
  p = group.p
  a = group.a
  b = group.b
  x = poly.Polynomial([0, 1], p)
  w = poly.Polynomial([a, 0, 3], p)
  y_sqr = (x*x + a) * x + b
  B = x*y_sqr
  h = w*w - 8*B
  j = 4*B - h

  # The valuve W is also computed during the doubling of a
  # point in Jacobian coordinates.
  for t in target:
    for x in (w - t).roots():
      yield x, "edge case for Jacobian and projective coordinates"

  # These points are sometimes skipped, since its
  # double is an edge case too.
  for t in target:
    for x in (h - t).roots():
      yield x, "edge case for computation of x with projective coordinates"

  # So far no curve has points corresponding to this case.
  for t in target:
    for x in (j - t).roots():
      yield x, "edge case for computation of y with projective coordinates"


def special_jacobian(group: ec_groups.EcPrimeGroup,
                     target: Optional[list[int]] = None):
  """Returns the x-coordinate of special points for doublic a point with

     Jacobian coordinates.

     if (Y == 0)
       return POINT_AT_INFINITY
     S = 4*X*Y^2
     M = 3*X^2 + a*Z^4
     X" = M^2 - 2*S
     Y' = M*(S - X') - 8*Y^4
     Z' = 2*Y*Z
     return (X', Y', Z')
  """
  if target is None:
    target = [-2, -1, 0, 1, 2]
  p = group.p
  a = group.a
  b = group.b
  x = poly.Polynomial([0, 1], p)
  m = poly.Polynomial([a, 0, 3], p)
  y_sqr = (x*x + a) * x + b
  s = 4*x*y_sqr
  x2 = m*m - 2*s

  for t in target:
    for x in (s - x2 - t).roots():
      yield x, "edge case for Jacobian coordinates"

def special(group: ec_groups.EcPrimeGroup):
  yield from special_projective(group)
  yield from special_jacobian(group)
  yield from special_x(group)
  yield from special_y(group)

def special_points(group, skip_half_points=False):
  done = set()
  for x, comment in special(group):
    if x in done:
      continue
    done.add(x)
    y = group.get_y(x)
    if y is not None:
      if skip_half_points:
        pt = group.get_point(x, y)
        if (2*pt).affine_x() == 0:
          continue
      yield comment, x, y

def all_special_points(skip_half_points=False):
  points = {}
  for c in ec_groups.predefined_curves:
    ptlist = list(special_points(c, skip_half_points))
    if ptlist:
      points[c.name] = ptlist
  return points

def all_special_points_json(skip_half_points=False):
  points = {}
  for c in ec_groups.predefined_curves:
    ptlist = []
    for comment, x, y in special_points(c, skip_half_points):
      pt = {}
      pt["comment"] = comment
      pt["x"] = AST.BigInt(x).json()
      pt["y"] = AST.BigInt(y).json()
      ptlist.append(pt)
    if ptlist:
      points[c.name] = ptlist
  res = {}
  res["header"] = [
      "A list of special points for ECDH.",
      "Special points are edge cases, such as the points described in the paper",
      "\"Zero-Value Point Attacks on Elliptic Curve Cryptosystem\" by T.Akishita",
      "T. Takagi, ISC 2003."
  ]
  res["points"] = all_special_points(skip_half_points)
  return res

def pp_special_points():
  pp = pprint.PrettyPrinter(indent=2)
  pp.pprint(all_special_points(True))


if __name__ == "__main__":
  print(json.dumps(all_special_points_json(), indent=2, sort_keys=True))
