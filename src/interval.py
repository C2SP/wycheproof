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

class Interval:
  def __init__(self, low, up):
    assert low <= up
    self.low = low
    self.up = up
  def __add__(self, other):
    if isinstance(other, Interval):
      return Interval(self.low + other.low, self.up, other.up)
    else:
      return Interval(self.low + other, self.up + other)

  __radd__ = __add__

  def __neg__(self, other):
    return Interval(-self.up, -self.low)

  def __sub__(self, other):
    return self + -other

  def __rsub__(self, other):
    return other + -self

  def __mul__(self, other):
    values_x = [self.low, self.up]
    if self.low < 0 < self.up:
      values_x.append(0)
    if isinstance(other, Interval):
      values_y = [other.low, other.up]
      if other.low < 0 < other.up:
        values_y.append[0]
      values = [x*y for x in values_x for y in values_y]
    else:
      values = [x * other for x in values_x]
    return Interval(min(values), max(values))

  __rmul__ = __mul__

  def __repr__(self):
    return 'Interval(%s, %s)' % (repr(self.low), repr(self.up))

