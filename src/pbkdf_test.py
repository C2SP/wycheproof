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
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class PbdfTest(googletest.TestCase):

  def md_for_algorithm(self, algorithm: str):
    if algorithm == "PBKDF2-HMACSHA1":
      return hashes.SHA1()
    elif algorithm == "PBKDF2-HMACSHA224":
      return hashes.SHA224()
    elif algorithm == "PBKDF2-HMACSHA256":
      return hashes.SHA256()
    elif algorithm == "PBKDF2-HMACSHA384":
      return hashes.SHA384()
    elif algorithm == "PBKDF2-HMACSHA512":
      return hashes.SHA512()
    else:
      raise ValueError("Unknown algorithm:" + algorithm)

  def Pbkdf(self, alg:str, password: bytes, salt: bytes, count: int, length: int) -> bytes:
    md = self.md_for_algorithm(alg)
    kdf = PBKDF2HMAC(
         algorithm=md,
         length=length,
         salt=salt,
         iterations=count)
    return kdf.derive(password)

  def testPbkdf(self):
    def fail(tc, msg):
      nonlocal errors
      errors += 1
      print(msg, tc)

    expected_schema = "pbkdf_test_schema.json"
    total_errors = 0
    total_files = 0
    for fname, test in test_util.get_all_test_vectors("^pbkdf2_.*test\.json$",
                                                      expected_schema):
      cnt = 0
      errors = 0
      verified = 0
      skipped = 0
      total_files += 1
      algorithm = test["algorithm"]
      try:
        md = self.md_for_algorithm(algorithm)
      except ValueError as e:
        print("Skipping test " + fname + " reason:" + str(e))
        continue
      for g in test["testGroups"]:
        for t in g["tests"]:
          cnt += 1
          password = bytes.fromhex(t["password"])
          salt = bytes.fromhex(t["salt"])
          iterCount = t["iterationCount"]
          size = t["dkLen"]
          expected = bytes.fromhex(t["dk"])
          result = t["result"]
          try:
            dk = self.Pbkdf(algorithm, password, salt, iterCount, size)
            if result == "invalid":
              if expected == dk:
                fail(t, "Generated PBKDF for invalid test case")
              else:
                skipped += 1
            elif result == "valid":
              if expected != dk:
                fail(t, "Generated incorrect PBKDF output")
              else:
                verified += 1
          except Exception as e:
            if result == "valid":
              fail(t, "PBKDF failed " + str(e))
            else:
              skipped += 1
      print(f"File:{fname}, number of tests:{test['numberOfTests']},"
            f" tests performed:{cnt}, verified:{verified},"
            f" skipped:{skipped}, errors:{errors}")
      total_errors += errors
    assert total_errors == 0
    assert total_files > 0


if __name__ == "__main__":
  googletest.main()


