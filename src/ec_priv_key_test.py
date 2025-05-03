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

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from google3.experimental.users.bleichen.wycheproof.py3.hazmat import test_util
import collections

import json

from google3.pyglib import resources

TEST_VECTOR_PATH = "google3/experimental/users/bleichen/wycheproof/testvectors/cavium/"

def test_all_ec_priv_keys(log: bool = False):
  for name, test_vectors in test_util.get_all_test_vectors(
      "ec_priv_key.*_pem_test.json",
      path = TEST_VECTOR_PATH):
    if log:
      print()
      print("File:", name)
    errors = collections.defaultdict(int)
    tests = 0
    accepted = 0
    for group in test_vectors["testGroups"]:
      for test in group["tests"]:
        priv_pem = test["encodedKey"].encode('ascii')
        tests += 1
        try:
          priv = serialization.load_pem_private_key(priv_pem, password=None,
                     backend=default_backend())
        except Exception as ex:
          errors[repr(ex)] += 1
          continue
        accepted += 1
        if log and test["result"] == "invalid":
          print("accepted", test["result"], test["tcId"], test["comment"])
    if log:
      print('number of accepted keys:', accepted)
      if accepted:
        for k, v in errors.items():
          print(k, v)
        print("number of tests:", tests)


if __name__ == '__main__':
  test_all_ec_priv_keys(log=True)
