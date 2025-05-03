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

import eddsa
import eddsa_ktv
import time

def test_groups():
  for group in [eddsa.ed25519_group, eddsa.ed448_group]:
    # quick pseudoprimality test
    assert pow(3, group.order, group.order) == 3
    assert not group.B * group.order

def test():
  start = time.time()
  errors = 0
  for t in eddsa_ktv.Tests:
    try:
      t.runTest()
      print(t.tc + " ok")
    except Exception as ex:
      print("Exception:" + str(ex) + " in " + t.tc)
      errors += 1
  print(time.time()-start)
  assert not errors

def test_points():
  for group in [eddsa.ed25519_group]:
    print(group)
    low_order_points = []
    for y in range(100):
      try:
        p = group.curve.point_from_y(y)
        q = p * group.order
        pt = group.encodepoint(q)
        if pt not in low_order_points:
          print(q)
          low_order_points.append(pt)
      except Exception as ex:
        pass
    for pt in low_order_points:
      print(pt.hex())

if __name__ == "__main__":
  test_groups()
  test()
  test_points()
