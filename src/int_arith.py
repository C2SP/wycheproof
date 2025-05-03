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

# Contains some utils for integer arithmetic.

import math

def isqrt(n: int) -> int:
  """Returns floor(sqrt(n))"""
  if n < 0:
    raise ValueError("n is negative")
  if n == 0:
    return 0
  # Finds a first approximation of the square root using
  # floating point arithmetic.
  if n.bit_length() < 1024:
    w = int(math.sqrt(n))
  else:
    # This is a special case for integers longer than
    # 1023 bits, since these integers are too big to be
    # converted into a double.
    exp = (n.bit_length() - 52) // 2
    w = int(math.sqrt(n >> (2 * exp))) << exp
  q = n // w
  while abs(w - q) > 1:
    w = (q + w) // 2
    q = n // w
  if w > q: w,q = q,w
  if q * q <= n:
    res = q
  else:
    res = w
  assert res**2 <= n < (res + 1)**2
  return res

