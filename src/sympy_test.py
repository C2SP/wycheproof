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

import json
import pathlib

from google3.testing.pybase import googletest
from google3.pyglib import resources
from sympy.ntheory.primetest import isprime
from sympy.ntheory.factor_ import factorint
from sympy import rem, ZZ, Poly
from sympy.abc import x


TEST_VECTOR_PATH = "google3/third_party/wycheproof/testvectors/"

def get_test_vectors(fname: str):
  txt = resources.GetResource(TEST_VECTOR_PATH + fname)
  return json.loads(txt)

class SympyTest(googletest.TestCase):

  def testPoly(self):
    '''checks that rem works as expected'''
    self.assertEqual(22, rem(x**2 + 4*x + 1, x - 3, domain=ZZ))
    self.assertEqual(x+5, rem(x**2 + x, x**2 - 5, domain=ZZ))

  def testGF(self):
    p = Poly(x+1,x,domain='GF(7)')
    r = Poly(x**7+1,x,domain='GF(7)')
    self.assertEqual(p**7, r)

  def _hexToInt(self, val: str) -> int:
    b = bytes.fromhex(val)
    return int.from_bytes(b, "big", signed=True)

  def testNtheory(self):
    if isprime(-19):
      print("sympy accepts negatives of primes")
    else:
      print("sympy doesn't accept negatives of primes")
    print("factorization of -120", factorint(-120))

  def testPrimes(self):
    '''Sympy fails, since the primality test is deterministic'''
    test = get_test_vectors("primality_test.json")
    passed = 0
    for group in test["testGroups"]:
      for tc in group["tests"]:
        tcId = tc["tcId"]
        val = self._hexToInt(tc["value"])
        res = tc["result"]
        if isprime(val):
          self.assertNotEqual(res, "invalid")
        else:
          self.assertNotEqual(res, "valid")
        passed += 1
    print("passed tests:", passed)

if __name__ == "__main__":
  googletest.main()


