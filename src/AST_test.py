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
def test_int2bytes():
  for (v, enc) in [
    (0, "00"),
    (1, "01"),
    (-1, "ff"),
    (127, "7f"),
    (128, "0080"),
    (-128, "80"),
    (-129, "ff7f"),
    (255, "00ff"),
    (256, "0100"),
    (-255, "ff01"),
    (-256, "ff00"),
    (12378612123, "02e1d2a19b"),
    (-19823719831, "fb626a0a69")]:
    res = AST._int2hex(v)
    print(res, enc)
    assert enc == res
  
if __name__ == "__main__":
  test_int2bytes() 
