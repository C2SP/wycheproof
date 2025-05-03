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

def integer_partitions(m: int):
  """Returns the number of integer partitions with distinct parts.
  Partitions must have at least two parts.
  I.e. this is the same as (OEIS A0000009) - 1
  """
  a = [0] * (m + 1)
  a[0] = 1
  for i in range(1, m + 1):
    # At this point we have the following loop invariant:
    # a[j] is the number of partitions of j with distinct integers < i.
    for j in range(m, i - 1, -1):
      a[j] += a[j - i]

  # Subtract 1, because partitions with less than two parts are excluded.
  return a[m] - 1

