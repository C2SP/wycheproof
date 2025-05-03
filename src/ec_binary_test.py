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

import ec_binary
from time import time

def test(verify_points: bool = True):
  start = time()
  for group in ec_binary.groups():
    c = group.curve
    verify = c.verify
    c.verify = verify_points
    g = group.generator()
    assert c.is_on_curve(g.x, g.y)
    assert pow(3, group.n, group.n) == 3
    assert not group.n * g
    for pt in group.low_order_points():
      assert not pt * group.h
    c.verify = verify
  print(time() - start)


# 6.014366865158081
#         18211511 function calls (18178367 primitive calls) in 6.014 seconds
#
#   ncalls  tottime  percall  cumtime  percall filename:lineno(function)
#    58626    2.593    0.000    2.593    0.000 gf.py:224(bin_mult)
#    97044    1.305    0.000    1.862    0.000 gf.py:242(bin_mod)
#     5478    0.794    0.000    1.905    0.000 gf.py:313(bin_gcd_ex)
# 15525538    0.743    0.000    0.743    0.000 {method 'bit_length' of 'int' objects}
#v102568/69424    0.130    0.000    3.091    0.000 util.py:94(wrapper)
#   210660    0.106    0.000    0.180    0.000 util.py:41(has_type)
#   410272    0.066    0.000    0.247    0.000 util.py:65(check_type)
#  1060873    0.058    0.000    0.058    0.000 {built-in method builtins.isinstance}
#    96976    0.033    0.000    2.293    0.000 gf.py:471(newelem)
#    97044    0.033    0.000    1.895    0.000 gf.py:465(__init__)
#   210660    0.030    0.000    0.044    0.000 typing.py:324(__eq__)
#    54784    0.022    0.000    0.295    0.000 gf.py:488(__add__)
#    36714    0.021    0.000    3.702    0.000 gf.py:493(__mul__)
#     5512    0.021    0.000    5.999    0.001 ec_binary.py:111(__add__)
#    91498    0.019    0.000    0.024    0.000 gf.py:478(coerce)
#     5524    0.011    0.000    1.806    0.000 ec_binary.py:31(is_on_curve)
def profile():
  from cProfile import run
  run("test(verify_points=False)", sort=1)


if __name__ == "__main__":
  test(verify_points=True)
  test(verify_points=False)
  profile()
