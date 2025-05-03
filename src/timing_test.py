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

"""Tests for google3.third_party.py"""

import collections
import os
import time

import google3
import ecdsa

from google3.pyglib import resources
from google3.testing.pybase import googletest
from google3.testing.pybase import parameterized

CURVES = {
    'secp256k1': ecdsa.SECP256k1,
    'secp192r1': ecdsa.NIST192p,
    'secp224r1': ecdsa.NIST224p,
    'secp256r1': ecdsa.NIST256p,
    'secp384r1': ecdsa.NIST384p,
    'secp521r1': ecdsa.NIST521p
}

# baselen 32
# NIST256p
# m: 40000 avgm: 0.07247610079050064 quot: 1.0
# m: 20000 avgm: 0.05734063757658005 quot: 0.9859969864937025
# m: 10000 avgm: 0.046831882190704346 quot: 0.9863740072828083
# m: 5000 avgm: 0.045021958208084106 quot: 0.9471743890612019
# m: 2500 avgm: 0.04439120893478393 quot: 0.874894102477156
# m: 1250 avgm: 0.04396694450378418 quot: 0.7984265417308692
# m: 625 avgm: 0.04364023323059082 quot: 0.7486601640821675
# m: 312 avgm: 0.04337222912372687 quot: 0.6902389009760083
# m: 156 avgm: 0.043127830211932845 quot: 0.5808043681104564
# m: 78 avgm: 0.042897349748855985 quot: 0.41164523432300504
# m: 39 avgm: 0.042666380222027116 quot: 0.35158050239863886
# m: 19 avgm: 0.04245052839580335 quot: 0.30497878856564914
# m: 9 avgm: 0.042271587583753795 quot: 0.49799715255052895
# m: 4 avgm: 0.04211592674255371 quot: 0.37915121991575623
# m: 2 avgm: 0.04194808006286621 quot: 0.7163382880212062
# m: 1 avgm: 0.04178023338317871 quot: 1.4102790030135945
class TimingTest(parameterized.TestCase):

  # @parameterized.named_parameters(*CURVES.items())
  @parameterized.named_parameters(('NISTP256', ecdsa.NIST256p))
  def testTiming(self, curve):
    """Signs a message a few times and measures timing differences.

    The library is susceptible to timing attacks. The test simply tries
    to find out how serious this is. Typically, one would also test if the
    timing differences are correlated with the choice of k.
    This is not done here.
    """
    tests = 40000
    print('baselen', curve.baselen)
    k = [int.from_bytes(os.urandom(curve.baselen), "big") for _ in range(tests)]
    t = []
    for x in k:
      start = time.time()
      res = curve.generator * x
      runtime = time.time() - start
      t.append([runtime, x])
    print(curve.name)
    t = sorted(t)
    sumk = sum(x[1] for x in t) / tests
    avg = sum(x[0] for x in t) / tests
    m = tests
    while m:
       avgm = sum(x[0] for x in t[:m]) / m
       sumkm = sum(x[1] for x in t[:m]) / m
       print('m:', m, 'avgm:', avgm, 'quot:', sumkm / sumk)
       m //= 2


if __name__ == '__main__':
  googletest.main()

