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
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm

class EcdsaTest(googletest.TestCase):

  def testEcdsaVerify(self):

    def fail(tc, msg):
      nonlocal errors
      errors += 1
      print(msg, tc)

    expected_schema = "ecdsa_verify_schema.json"
    total_errors = 0
    total_files = 0
    unsupported_curves = set()
    unsupported_hashes = set()
    # TODO: avoid loading files containing _webcrypto, _p1363, _bitcoin

    for fname, test in test_util.get_all_test_vectors("^ecdsa.*test\.json$",
                                                      expected_schema):
      total_files += 1
      cnt = 0
      verified = 0  # verified signatures
      errors = 0  # real errors
      value_errors = 0  # ValueErrors during parsing
      missing = 0  # errors because of missing algorithms in the backend
      for g in test["testGroups"]:
        pem = bytes(g["keyPem"], "ascii")
        try:
          pub = serialization.load_pem_public_key(
              pem, backend=default_backend())
        except UnsupportedAlgorithm:
          unsupported_curves.add(g["key"]["curve"])
          continue
        except ValueError:
          value_errors += 1
          continue
        try:
          md = test_util.get_hash(g["sha"])
        except ValueError:
          unsupported_hashes.add(g["sha"])
          continue
        alg = ec.ECDSA(md)
        for t in g["tests"]:
          cnt += 1
          msg = bytes.fromhex(t["msg"])
          sig = bytes.fromhex(t["sig"])
          result = t["result"]
          try:
            pub.verify(sig, msg, alg)
            if result == "invalid":
              fail(t, "Invalid signature verified")
            else:
              verified += 1
          except InvalidSignature:
            if result == "valid":
              fail(t, "Did not verify valid signature")
          except UnsupportedAlgorithm:
            # TODO: this happens when the backend does not
            #   support algorithms, e.g., when an old version of openssl or
            #   boringssl is used.
            missing += 1
          except Exception as e:
            fail(t, "Unexpected exception " + str(type(e)) + ":" + str(e))
      if cnt:
        print("File: %s number of tests: %d, groups:%d, test performed: %d,"
              " verified: %d, errors:%d, value_errors:%d missing:%d" %
              (fname, test["numberOfTests"], len(test["testGroups"]), cnt,
                 verified, errors, value_errors, missing))
      else:
        print("File: %s no tests performed" % fname)
      total_errors += errors
    if unsupported_curves:
      print("unsupported curves:", unsupported_curves)
    if unsupported_hashes:
      print("unsupported hashes:", unsupported_hashes)
    assert total_errors == 0
    assert total_files > 0


if __name__ == "__main__":
  googletest.main()
  test_path = pathlib.Path('../../testvectors/')
  for path in test_path.glob("ecdsa_*.json"):
    test_ecdsa(path)
