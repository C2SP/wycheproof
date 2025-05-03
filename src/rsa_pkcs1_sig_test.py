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

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding


class RsaPkcs1SigTest(googletest.TestCase):

  def testRsaPkcs1SigVerify(self):

    def fail(tc, msg):
      nonlocal errors
      errors += 1
      print(msg, tc)

    expected_schema = "rsassa_pkcs1_verify_schema.json"
    total_errors = 0
    total_files = 0
    for fname, test in test_util.get_all_test_vectors("^rsa_sig.*test\.json$",
                                                      expected_schema):
      errors = 0
      cnt = 0
      verified = 0
      skipped_keys = 0
      skipped_tests = 0
      exceptions = set()
      total_files += 1
      for g in test["testGroups"]:
        pem = bytes(g["keyPem"], "ascii")
        try:
          pub = serialization.load_pem_public_key(
              pem, backend=default_backend())
        except ValueError:
          skipped_keys += 1
          continue
        md = test_util.get_hash(g["sha"])
        pad = padding.PKCS1v15()
        for t in g["tests"]:
          cnt += 1
          msg = bytes.fromhex(t["msg"])
          sig = bytes.fromhex(t["sig"])
          result = t["result"]
          try:
            pub.verify(sig, msg, pad, md)
            if result == "invalid":
              fail(t, "Invalid signature verified")
            else:
              verified += 1
          except InvalidSignature:
            if result == "valid":
              fail(t, "Did not verify valid signature")
          except Exception as e:
            ex = str(e)
            if ex.find("not") > -1 and ex.find("supported") > -1:
              skipped_tests += 1
              exceptions.add(ex)
            else:
              fail(t, "Unexpected exception " + str(e))
      print(f"File:{fname}, number of tests:{test['numberOfTests']},"
            f" test performed:{cnt}, verified:{verified},"
            f" skipped keys:{skipped_keys} errors:{errors}"
            f" skipped tests:{skipped_tests}")
      if exceptions:
        print("Skipped exceptions")
        for e in exceptions:
          print(' ', e)
      total_errors += errors
    assert total_errors == 0
    assert total_files > 0

  def testRsaPkcs1SigGenerate(self):

    def fail(tc, msg):
      nonlocal errors
      errors += 1
      print(msg, tc)

    expected_schema = "rsassa_pkcs1_generate_schema.json"
    total_errors = 0
    total_files = 0
    for fname, test in test_util.get_all_test_vectors("^rsa_sig.*test\.json$",
                                                      expected_schema):
      skipped_keys = 0
      skipped_tests = 0
      cnt = 0
      errors = 0
      verified = 0
      total_files += 1
      exceptions = set()
      for g in test["testGroups"]:
        pem = bytes(g["privateKeyPem"], "ascii")
        try:
          priv = serialization.load_pem_private_key(
              pem, backend=default_backend(), password=None)
        except ValueError:
          skipped_keys += 1
          continue
        md = test_util.get_hash(g["sha"])
        pad = padding.PKCS1v15()
        for t in g["tests"]:
          cnt += 1
          msg = bytes.fromhex(t["msg"])
          expected_sig = bytes.fromhex(t["sig"])
          result = t["result"]
          try:
            sig = priv.sign(msg, pad, md)
            if result == "invalid":
              fail(t, "Expected signing to fail")
            else:
              verified += 1
          except Exception as e:
            if result == "valid":
              ex = str(e)
              if ex.find("not") > -1 and ex.find("supported") > -1:
                skipped_tests += 1
                exceptions.add(ex)
              else:
                fail(t, "Unexpected exception " + str(e))
      print(f"File:{fname}, number of tests:{test['numberOfTests']},"
            f" test performed:{cnt}, verified:{verified},"
            f" skipped keys:{skipped_keys}, errors:{errors},"
            f" skipped tests:{skipped_tests}")
      if exceptions:
        print("Skipped exceptions")
        for e in exceptions:
          print(' ', e)
      total_errors += errors
    assert total_errors == 0
    assert total_files > 0


if __name__ == "__main__":
  googletest.main()
