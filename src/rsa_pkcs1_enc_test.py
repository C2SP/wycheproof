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
import traceback

from google3.testing.pybase import googletest

from google3.experimental.users.bleichen.wycheproof.py3.hazmat import test_util

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric import padding


class RsaPkcs1EncTest(googletest.TestCase):

  def testRsaPkcs1Enc(self):

    def fail(tc, msg):
      nonlocal errors
      errors += 1
      print(msg, tc)

    expected_schema = "rsaes_pkcs1_decrypt_schema.json"
    cnt = 0
    total_errors = 0
    total_files = 0
    skipped_keys = 0
    for fname, test in test_util.get_all_test_vectors("^rsa_pkcs1.*test\.json$",
                                                      expected_schema):
      errors = 0
      verified = 0
      total_files += 1
      padding_exceptions = set()
      for g in test["testGroups"]:
        pem = bytes(g["privateKeyPem"], "ascii")
        priv = serialization.load_pem_private_key(
            pem, password=None, backend=default_backend())
        for t in g["tests"]:
          cnt += 1
          msg = bytes.fromhex(t["msg"])
          ct = bytes.fromhex(t["ct"])
          result = t["result"]
          pad = padding.PKCS1v15()
          try:
            msg2 = priv.decrypt(ct, pad)
            if result == "invalid":
              fail(t, "Decrypted invalid test case")
            elif msg != msg2:
              fail(t, "Incorrect decryption")
            else:
              verified += 1
          except Exception as e:
            if result == "valid":
              fail(t, "Decryption failed " + str(e))
            if "InvalidPkcs1Padding" in t["flags"]:
              exception = str(e) + "".join(traceback.format_tb(e.__traceback__))
              padding_exceptions.add(exception)
      print(f"File:{fname}, number of tests:{test['numberOfTests']},"
            f" test performed:{cnt}, verified:{verified},"
            f" number of padding exceptions:{len(padding_exceptions)},"
            f" errors:{errors}'")
      if len(padding_exceptions) > 1:
        errors += 1
        for x in padding_exceptions:
          print(x)
      total_errors += errors
    assert total_errors == 0
    assert total_files > 0


if __name__ == "__main__":
  googletest.main()
