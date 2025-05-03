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
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec 

  
class EckeyTest(googletest.TestCase):

  def testLoad(self):
    def fail(tc, msg):
      nonlocal errors
      errors += 1
      print(msg, tc)

    # TODO: ASN and PEM encoded key need distinct encodings.
    expected_schema = "ec_public_key_verify_schema.json"
    backend = default_backend()
    total_errors = 0
    total_files = 0
    unsupportedCurves = set()
    failedCurves = set()
    for fname, test in test_util.get_all_test_vectors("^eckey.*test\.json$",
                                                      expected_schema):
      total_files += 1
      cnt = 0
      errors = 0
      skipped_keys = 0
      valid = 0
      for g in test["testGroups"]:
        for t in g["tests"]:
          cnt += 1
          pub_data = bytes.fromhex(t["encoded"])
          pub_key = None
          try:
            if g["encoding"] == "asn":
              pub_key = serialization.load_der_public_key(pub_data, backend)
            elif g["encoding"] == "pem":
              pub_key = serialization.load_pem_public_key(pub_data, backend)
            else:
              print(f"Unknown encoding {g['encoding']}")
              continue
            print(f"Read public key {t['tcId']}, {t['result']}, {t['comment']}")
            if t["result"] == "invalid":
              errors += 1
          except Exception as e:
            print(f"Failed to read public key {t['tcId']}, {t['result']}, {t['comment']} {e}")
          continue
      print(f"File:{fname}, number of tests:{test['numberOfTests']},"
            f" test performed:{cnt}, valid:{valid},"
            f" skipped keys:{skipped_keys} errors:{errors}'")
      total_errors += errors
    assert total_errors == 0
    assert total_files > 0

if __name__ == "__main__":
  googletest.main()


