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

import ff1
import ff1_ktv
import ff1_util

def test():
  key = bytes(range(16))
  tweak = bytes()
  for radix in (16, 26, 771):
    for n in (2, 5, 19, 71):
      ff = ff1.AesFf1(key, radix)
      msg = [i % radix for i in range(n)]
      ct = ff.encrypt(tweak, msg)
      dec = ff.decrypt(tweak, ct)
      assert msg == dec

def test_tv():
  errors = 0
  for t in ff1_ktv.FF1_KTV:
    key = bytes.fromhex(t['key'])
    radix = t['radix']
    pt = t['pt']
    ct = t['ct']
    tweak = bytes.fromhex(t['tweak'])
    ff = ff1.AesFf1(key, radix)
    enc = ff.encrypt(tweak, pt)
    if ct != enc:
      print(t)
      print('expected', ct)
      print('computed', enc)
      errors += 1
  assert not errors


def test_invert():
  print('test_invert')
  import os
  key = bytes(range(16))
  tweak = bytes(range(7))
  radix = 97
  n = 20
  v = (n+1)//2
  y = radix ** v - 1
  fpe = ff1.AesFf1(key, radix)
  for i in range(4000):
    tweak_prefix = os.urandom(16)
    random_block = os.urandom(16)
    r, num_b, tweak = fpe.invert_round_function(y, n, tweak_prefix, random_block)
    y2 = fpe.round_function(r, num_b, tweak, n)
    if r < 10 and num_b < radix ** v:
      print(r, num_b, tweak.hex())
    assert y2 == y

def test_invert2(log=True):
  print('test_invert2')
  import os
  key = bytes(range(16))
  tweak = bytes(range(7))
  radix = 97
  fpe = ff1.AesFf1(key, radix)
  n = 16
  u, v, b, d = fpe.get_sizes(n)
  # y = radix ** v - 1
  y = 256 ** d - 1
  assert d == 12
  found = 0
  for i in range(10000):
    tweak_prefix = bytes()
    random_block = os.urandom(16)
    r, num_b, tweak = fpe.invert_round_function(y, n, tweak_prefix, random_block)
    y2 = fpe.round_function(r, num_b, tweak, n)
    assert y2 == y
    if 0 <= r < 10 and num_b < radix ** v:
      print(r, 'num_b =', hex(num_b), 'tweak =', tweak.hex())
      found += 1
      A = [0] * u
      B = fpe.num_str(num_b, v)
      pt = fpe.pt_with_state(tweak, r, A, B)
      if found == 1 and log:
        ff1_util.show_states(fpe, tweak, pt)
      deb = fpe.states(tweak, pt)[r]
      assert deb[3] == y 

def test_state(log=True):
  key = bytes(range(16))
  tweak = bytes(range(7))
  radix = 62
  fpe = ff1.AesFf1(key, radix)
  A = [0] * 5
  B = [7] * 5
  r = 3
  pt = fpe.pt_with_state(tweak, r, A, B)
  if log: 
    ff1_util.show_states(fpe, tweak, pt)
  d = fpe.states(tweak, pt)[r]
  assert d[0] == fpe.num(A)
  assert d[1] == fpe.num(B)
  

if __name__ == "__main__":
  test()
  test_tv()
  test_state()
  test_invert()
  test_invert2()
  print('done')
