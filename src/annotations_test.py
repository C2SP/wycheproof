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

# Allows to use generic type hints like list[int]
# in some python versions below 3.9.
# But typing is unable to use them and throws.
from __future__ import annotations
import typing

def sum1(x: typing.List[int]) -> int:
  return sum(x)

# Simplified type annotations for python 3.9 (PEP 585)
def sum2(x: list[int]) -> int:
  return sum(x)


def test():
  t1 = typing.get_type_hints(sum1)
  print(t1)
  # Throws an exception in with python 3.8.5
  t2 = typing.get_type_hints(sum2)
  print(t2)
  
if __name__ == "__main__":
  test()
