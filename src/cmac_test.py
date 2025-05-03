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
from cryptography.hazmat.primitives.cmac import CMAC
from cryptography.hazmat.primitives.ciphers import algorithms

class CmacTest(googletest.TestCase):

  def testCmac(self):
    def fail(tc, msg):
      nonlocal errors
      errors += 1
      print(msg, tc)

    backend = default_backend()
    expected_schema = "mac_test_schema.json"
    cnt = 0
    total_errors = 0
    total_files = 0
    for fname, test in test_util.get_all_test_vectors("^aes_cmac.*test\.json$",
                                                      expected_schema):
      errors = 0
      verified = 0
      total_files += 1
      for g in test["testGroups"]:
        tag_size = g['tagSize']
        if tag_size != 128:
          # not supported
          continue
        for t in g["tests"]:
          cnt += 1
          key = bytes.fromhex(t["key"])
          msg = bytes.fromhex(t["msg"])
          tag = bytes.fromhex(t["tag"])
          result = t["result"]
          # Test mac
          try:
            mac = CMAC(algorithms.AES(key), backend)
            mac.update(msg)
            tag2 = mac.finalize()
            if result == "invalid":
              if tag == tag2:
                fail(t, "Generated MAC for invalid test case")
            elif result == "valid":
              if tag != tag2:
                fail(t, "Generated incorrect MAC")
            else:
              verified += 1
          except Exception as e:
            if result == "valid":
              fail(t, "Mac failed " + str(e))
          # Test verification
          try:
            mac = CMAC(algorithms.AES(key), backend)
            mac.update(msg)
            mac.verify(tag)
            if result == "invalid":
              fail(t, "Verified invalid MAC")
          except Exception as e:
            if result == "valid":
              fail(t, "Failed verifying MAC" + str(e))
      print(f"File:{fname}, number of tests:{test['numberOfTests']},"
            f" tests performed:{cnt}, verified:{verified},"
            f" errors:{errors}")
      total_errors += errors
    assert total_errors == 0
    assert total_files > 0


if __name__ == "__main__":
  googletest.main()


