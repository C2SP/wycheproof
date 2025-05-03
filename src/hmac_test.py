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
from cryptography.hazmat.primitives import hmac
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm

class HmacTest(googletest.TestCase):

  def hash_for_algorithm(self, name: str):
    try:
      if name == "HMACSHA1":
        return hashes.SHA1()
      elif name == "HMACSHA224":
        return hashes.SHA224()
      elif name == "HMACSHA256":
        return hashes.SHA256()
      elif name == "HMACSHA384":
        return hashes.SHA384()
      elif name == "HMACSHA512":
        return hashes.SHA512()
      elif name == "HMACSHA3-224":
        return hashes.SHA3_224()
      elif name == "HMACSHA3-256":
        return hashes.SHA3_256()
      elif name == "HMACSHA3-384":
        return hashes.SHA3_384()
      elif name == "HMACSHA3-512":
        return hashes.SHA3_512()
      elif name == "HMACSHA512/224":
        return hashes.SHA512_224()
      elif name == "HMACSHA512/256":
        return hashes.SHA512_256()
    except Exception as ex:
      print(type(ex), ex)
    raise ValueError("unknown name:" + name)

  def Hmac(self, md, key: bytes, message: bytes, mac_size: int) -> bytes:
    mac = hmac.HMAC(key, md, backend=default_backend())
    mac.update(message)
    return mac.finalize()[:mac_size]

  def HmacVerifyFullSize(self, md, key: bytes, message: bytes, tag: bytes) -> bool:
    mac = hmac.HMAC(key, md, backend=default_backend())
    mac.update(message)
    try:
      mac.verify(tag)
      return True
    except InvalidSignature:
      return False

  def testHmac(self):
    def fail(tc, msg, tag=None, expected_tag=None):
      nonlocal errors
      errors += 1
      if tag is not None and expected_tag is not None:
        print(tc["tcId"], msg)
        print("computed:", tag.hex())
        print("expected:", expected_tag.hex())
      else:
        print(msg, tc)

    expected_schema = "mac_test_schema.json"
    total_errors = 0
    total_files = 0
    for fname, test in test_util.get_all_test_vectors("^hmac_.*test\.json$",
                                                      expected_schema):
      cnt = 0
      errors = 0
      generated = 0
      verified = 0
      skipped = 0
      total_files += 1
      algorithm = test["algorithm"]
      try:
        md = self.hash_for_algorithm(algorithm)
      except ValueError as e:
        print("Skipping test " + fname + " reason:" + str(e))
        continue
      for g in test["testGroups"]:
        mac_size = g["tagSize"] // 8
        for t in g["tests"]:
          cnt += 1
          key = bytes.fromhex(t["key"])
          msg = bytes.fromhex(t["msg"])
          expected_tag = bytes.fromhex(t["tag"])
          result = t["result"]
          try:
            tag = self.Hmac(md, key, msg, mac_size)
            if expected_tag == tag:
              if result == "invalid":
                fail(t, "Generated MAC for invalid test case",
                     tag, expected_tag)
              else:
                generated += 1
            else:
              if result == "valid":
                fail(t, "Generated incorrect HMAC tag", tag, expected_tag)
            if mac_size == md.digest_size:
              valid = self.HmacVerifyFullSize(md, key, msg, expected_tag)
              if valid and result != "invalid":
                verified += 1
              elif valid and result == "invalid":
                fail(t, "Verified invalid HMAC")
              elif not valid and result == "valid":
                fail(t, "Valid HMAC not verifed")
          except UnsupportedAlgorithm:
            skipped += 1
          except Exception as e:
            if result == "valid":
              fail(t, "HMAC failed " + str(type(e)) + str(e))
      print(f"File:{fname}, number of tests:{test['numberOfTests']},"
            f" tests performed:{cnt}, generated:{generated},"
            f" verified:{verified}, skipped:{skipped}, errors:{errors}")
      total_errors += errors
    assert total_errors == 0
    assert total_files > 0


if __name__ == "__main__":
  googletest.main()


