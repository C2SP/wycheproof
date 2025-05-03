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

def get_curve(name: str):
  '''Returns the elliptic curve with a given name or
     None if not supported by hazmat.'''
  try:
    if name == "secp192r1": return ec.SECP192R1()
    elif name == "secp224r1": return ec.SECP224R1()
    elif name == "secp256r1": return ec.SECP256R1()
    elif name == "secp256k1": return ec.SECP256K1()
    elif name == "secp384r1": return ec.SECP384R1()
    elif name == "secp521r1": return ec.SECP521R1()
    elif name == "brainpoolP256r1": return ec.BrainpoolP256R1()
    elif name == "brainpoolP384r1": return ec.BrainpoolP384R1()
    elif name == "brainpoolP512r1": return ec.BrainpoolP512R1()
    elif name == "sect233k1" : return ec.SECT233K1()
    elif name == "sect163k1" : return ec.SECT163K1()
    elif name == "sect571r1" : return ec.SECT571R1()
    elif name == "sect409r1" : return ec.SECT409R1()
    elif name == "sect283r1" : return ec.SECT283R1()
    elif name == "sect233r1" : return ec.SECT233R1()
    elif name == "sect233r1" : return ec.SECT233R2()
    elif name in [
        "secp224k1",
        "brainpoolP224r1",
        "brainpoolP320r1",
        "brainpoolP224t1",
        "brainpoolP256t1",
        "brainpoolP320t1",
        "brainpoolP384t1",
        "brainpoolP512t1"]:
      # Implemented in Wycheproof but not in hazmat
      return None
  except Exception:
    # Implemented in Wycheproof and hazmat, but an old hazmat version is used.
    return None
  # Unknown curve
  raise Exception("Unknown curve:" + name)
  
def get_private_key(curve, hexstr):
  assert len(hexstr) > 0 and hexstr[0] in '01234567'
  x = int(hexstr, 16)
  return ec.derive_private_key(x, curve, default_backend())

class EcdhTest(googletest.TestCase):

  def testEcdh(self):
    def fail(tc, msg):
      nonlocal errors
      errors += 1
      print(msg, tc)

    expected_schema = "ecdh_test_schema.json"
    backend = default_backend()
    total_errors = 0
    total_files = 0
    unsupportedCurves = set()
    failedCurves = set()
    for fname, test in test_util.get_all_test_vectors("^ecdh_.*test\.json$",
                                                      expected_schema):
      total_files += 1
      cnt = 0
      errors = 0
      skipped_keys = 0
      valid = 0
      for g in test["testGroups"]:
        if g["encoding"] != "asn":
          print("unexpected encoding:" + g["encoding"])
          continue
        # This is the curve of the private key
        curvename = g["curve"]
        curve = get_curve(curvename)
        if curve is None:
          unsupportedCurves.add(curvename)
          continue
        for t in g["tests"]:
          cnt += 1
          pub_data = bytes.fromhex(t["public"])
          try:
            priv_key = get_private_key(curve, t["private"])
          except Exception as e:
            # print(f"Exception {e} getting private key on {curvename}")
            failedCurves.add(curvename)
            continue
          result = t["result"]
          try:
            pub_key = serialization.load_der_public_key(pub_data, backend)
            shared = priv_key.exchange(ec.ECDH(), pub_key)
            if bytes.fromhex(t["shared"]) != shared:
              fail(t, "computed wrong shared secret")
            elif result == "invalid":
              fail(t, "computed shared secret invalid input")
            else:
              valid += 1
          except Exception as e:
            if result == "valid":
              fail(t, "did not compute shared secret " + str(e))
      print(f"File:{fname}, number of tests:{test['numberOfTests']},"
            f" test performed:{cnt}, valid:{valid},"
            f" skipped keys:{skipped_keys} errors:{errors}'")
      total_errors += errors
    if unsupportedCurves:
      print("unsupported curves:", unsupportedCurves)
    if failedCurves:
      print("failed curves:", failedCurves)
    assert total_errors == 0
    assert total_files > 0

  def testEcdhPem(self):
    def fail(tc, msg):
      nonlocal errors
      errors += 1
      print(msg, tc)

    expected_schema = "ecdh_pem_test_schema.json"
    backend = default_backend()
    total_errors = 0
    total_files = 0
    unsupportedCurves = set()
    failedCurves = set()
    for fname, test in test_util.get_all_test_vectors("^ecdh_.*test\.json$",
                                                      expected_schema):
      total_files += 1
      errors = 0
      cnt = 0
      skipped_keys = 0
      valid = 0
      for g in test["testGroups"]:
        # TODO: could be removed
        if g["encoding"] != "pem":
          print("unexpected encoding:" + g["encoding"])
          continue
        # This is the curve of the private key
        curvename = g["curve"]
        curve = get_curve(curvename)
        if curve is None:
          unsupportedCurves.add(curvename)
          continue
        for t in g["tests"]:
          pub_pem = bytes(t["public"], "ascii")
          priv_pem = bytes(t["private"], "ascii")
          try:
            priv_key = serialization.load_pem_private_key(
                priv_pem, password=None, backend=default_backend())
          except Exception as e:
            if curve not in failedCurves:
              print(f'Exception "{e}" getting private key on {curve}')
            failedCurves.add(curvename)
            skipped_keys += 1
            continue
          try:
            pub_key = serialization.load_pem_public_key(
                pub_pem, backend=default_backend())
          except Exception as e:
            skipped_keys += 1
            continue
          cnt += 1
          result = t["result"]
          try:
            shared = priv_key.exchange(ec.ECDH(), pub_key)
            if bytes.fromhex(t["shared"]) != shared:
              fail(t, "computed wrong shared secret")
            elif result == "invalid":
              fail(t, "computed shared secret invalid input")
            else:
              valid += 1
          except Exception as e:
            if result == "valid":
              fail(t, "did not compute shared secret " + str(e))
      print(f"File:{fname}, number of tests:{test['numberOfTests']},"
            f" test performed:{cnt}, valid:{valid},"
            f" skipped keys:{skipped_keys} errors:{errors}'")
      total_errors += errors
    if unsupportedCurves:
      print("unsupported curves:", unsupportedCurves)
    if failedCurves:
      print("failed curves:", failedCurves)
    assert total_errors == 0
    assert total_files > 0

if __name__ == "__main__":
  googletest.main()


