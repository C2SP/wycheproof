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

from google3.experimental.users.bleichen.wycheproof.py3.hazmat import test_util

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm


class DsaTest(googletest.TestCase):

  def testDsaVerify(self):

    def fail(tc, msg):
      nonlocal errors
      errors += 1
      print(msg, tc)

    expected_schema = "dsa_verify_schema.json"
    cnt = 0
    total_errors = 0
    total_files = 0
    for fname, test in test_util.get_all_test_vectors("^dsa.*test\.json$",
                                                      expected_schema):
      errors = 0
      total_files += 1
      for g in test["testGroups"]:
        pem = bytes(g["keyPem"], "ascii")
        pub = serialization.load_pem_public_key(pem, backend=default_backend())
        md = test_util.get_hash(g["sha"])
        for t in g["tests"]:
          cnt += 1
          msg = bytes.fromhex(t["msg"])
          sig = bytes.fromhex(t["sig"])
          result = t["result"]
          try:
            pub.verify(sig, msg, md)
            if result == "invalid":
              fail(t, "Invalid signature verified")
          except InvalidSignature:
            if result == "valid":
              fail(t, "Did not verify valid signature")
          except Exception as e:
            fail(t, "Unexpected exception " + str(e))
      print(f"File:{fname}, number of tests:{test['numberOfTests']},"
            f" tests performed:{cnt}, errors:{errors}")
      total_errors += errors
    assert total_errors == 0
    assert total_files > 0


if __name__ == "__main__":
  googletest.main()
