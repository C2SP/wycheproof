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
from Crypto.PublicKey import DSA
from Crypto.PublicKey import _fastmath
from Crypto.Util.number import isPrime

TEST_VECTOR_PATH = "google3/third_party/wycheproof/testvectors/"

def get_test_vectors(fname: str):
  txt = resources.GetResource(TEST_VECTOR_PATH + fname)
  return json.loads(txt)

class PyCryptoTest(googletest.TestCase):
  """TODO: The test here does not verify the _slowmath
  implementation, which is that code that suffers from most of the
  bugs.
  """

  def _hexToInt(self, val: str) -> int:
    b = bytes.fromhex(val)
    return int.from_bytes(b, "big", signed=True)


  def testPrimes(self):
    test = get_test_vectors("primality_test.json")
    passed = 0
    for group in test["testGroups"]:
      for tc in group["tests"]:
        tcId = tc["tcId"]
        val = self._hexToInt(tc["value"])
        res = tc["result"]
        if isPrime(val):
          self.assertNotEqual(res, "invalid")
        else:
          self.assertNotEqual(res, "valid")
        passed += 1
    print("passed tests:", passed)

if __name__ == "__main__":
  googletest.main()


