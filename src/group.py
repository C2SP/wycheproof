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

class Element:
  """This is an abstract implementation of an element in a group."""

  # abstract methods
  def __add__(self, point):
    return NotImplemented

  def __neg__(self):
    return NotImplemented

  def __bool__(self):
    return NotImplemented

  def __zero__(self):
    """Returns the neutral element of the group of this."""
    return NotImplemented

  def __radd__(self, point):
    return self.__add__(point)

  def __sub__(self, point):
    return self + (-point)

  def __rsub__(self, point):
    return (-self) + point

  def __mul__(self, n):
    if isinstance(n, int):
      # TODO: should be self.zero()
      res = self.curve.zero()
      g = self
      if n < 0:
        g = -g
        n = -n
      while True:
        if n % 2 == 1:
          res = res + g
        n //= 2
        if n == 0:
          # TODO: Maybe add a generic option for point
          #   verification. E.g. binary elliptic curves with point
          #   verification after each operation is slow, but doing
          #   it at the end of a scalar multiplication would be
          #   reasonable.
          return res
        g = g.double()
    else:
      return NotImplemented

  def __rmul__(self, other):
    return self.__mul__(other)

  def __str__(self):
    return self.__repr__()

  def __ne__(self, p):
    return not self == p

  def double(self):
    """Doubling a point.
    
    Many EC implementations have special code for doubling.
    """
    return self + self

class Point(Element):
  """An empty subclass for elements that are points.

  This class has been added simply for readability."""
  
  
class EcGroup:
  """Defines a cyclic group over an elliptic curve.

  This definition is mainly just a type hint, since
  individual groups (e.g. over binary curves, prime curves
  using Weierstrass representation or Edwards curves share
  little to no code.
  """

