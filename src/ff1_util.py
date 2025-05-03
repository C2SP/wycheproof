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


def show_states(cipher, tweak: bytes, pt: 'NumeralString'):
  n = len(pt)
  u = n // 2
  v = n - u
  for r, (num_a, num_b, num_c, y) in enumerate(cipher.states(tweak, pt)):
    m = (u, v)[r % 2]
    print('round', r)
    print('A', hex(num_a), cipher.num_str(num_a, n-m))
    print('B', hex(num_b), cipher.num_str(num_b, m))
    if num_c is not None:
      print('C', hex(num_c), cipher.num_str(num_c, m))
    if y is not None:
      print('y', hex(y))

def debug_sizes(cipher, minlen: int, maxlen: int):
  """Prints some internal sizes for different input lengths.
    
  Things to check:
  d == 8: 64-bit integer overflow.
  d == 16: 128-bit integer overflow.
  d >= 20: expand does encryptions. 
    
  """
  print('radix', cipher.radix)
  for n in range(minlen, maxlen+1):
    u, v, b, d = cipher.get_sizes(n)
    print(f'n={n} u={u} v={v} b={b} d={d}')

