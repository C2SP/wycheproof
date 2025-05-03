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

import collections
import json
import pathlib
import test_util
import traceback
import time

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

# TODO: Other things that can be tested.
#   Decryption with exceptional values such as 0.

def gcd(a, b):
  while a:
    a, b = b % a, a
  return abs(b)

def test_rsa_private_key(path):
  test = json.load(path.open())
  print('=' * 80)
  print('File:', path)
  expected_schema = "rsa_private_key_pem_test_schema.json"
  if test["schema"] != expected_schema:
    print('schema expected:%s actual:%s' % (expected_schema, test["schema"]))
  cnt = collections.Counter()
  algorithm = test["algorithm"]
  key_load_exceptions = collections.defaultdict(int)
  failed_sign_exceptions = collections.defaultdict(int)
  
  for g in test["testGroups"]:
    priv_pem = bytes(g["privateKeyPem"], 'ascii')
    priv = serialization.load_pem_private_key(priv_pem, password=None,
               backend=default_backend())
    pub_pem = bytes(g["publicKeyPem"], 'ascii')
    pub = serialization.load_pem_public_key(pub_pem, backend=default_backend())
    n = int(g['privateKey']['n'], 16)

    # Sign an arbitrary message
    msg = bytes(range(5))
    md = test_util.get_hash("SHA-256")
    pad = padding.PKCS1v15()
    sig = priv.sign(msg, pad, md)
    for t in g["tests"]:
      cnt["test"] += 1
      mod_pem = bytes(t["encoded"], 'ascii')
      try:
        mod_key = serialization.load_pem_private_key(mod_pem, password=None,
                      backend=default_backend())
      except Exception as e:
        cnt["rejected key"] += 1
        key_load_exceptions[str(e)] += 1
        continue
      # Tries signing a few times to see if signing is deterministic.
      exceptions = []
      signatures = []
      start = time.time()
      for i in range(5):
        try:
          s = mod_key.sign(msg, pad, md)
          signatures.append(s)
        except Exception as e:
          exceptions.append(str(e))
      runtime = time.time() - start
      # Counts distinct cases.
      if signatures and exceptions:
         cnt["flaky sign"] += 1
      if signatures:
        if len(set(signatures)) > 1:
          cnt["non-deterministic signature"] += 1
        elif signatures[0] == sig:
           cnt["correct signature"] += 1
           print("correct signature for :", t["tcId"], runtime, t["comment"])
        else:
           cnt["incorrect signature"] += 1
      if exceptions:
        if len(set(exceptions)) > 1:
          cnt["non-deterministic signature failure"] += 1
        else:
          cnt["signature failure"] += 1
        for e in exceptions:
          failed_sign_exceptions[e] += 1
      # Prints out modified signatures and tries to factor
      # the key. These are the interesting cases, since
      # OpenSSL should in principle check results for faults.
      cnt_modified = 0
      s = int(sig.hex(), 16)
      mod = sorted(int(s.hex(), 16) for s in signatures)
      for m in mod:
        if s != m:
          if not cnt_modified:
            print("Generated modified signature for :", t["tcId"], t["comment"])
            cnt["critical error"] += 1
          cnt_modified += 1
          print(hex(m))
          diff = s - m
          if 1 < gcd(n, s - m) < n:
            print("Diff leaks a factor:", gcd(n, s - m))
            cnt["factored keys"] += 1
          elif 1 < gcd(n, m) < n:
            print("Sig leaks a factor:", gcd(n, m))
            cnt["factored keys"] += 1

  for k, v in cnt.items():
    print(v, k + "(s)" * (v!=1))
  print('Key load exceptions:')
  for k, v in key_load_exceptions.items():
    print('  ', v, k)
  print('Signing exceptions:')
  for k, v in failed_sign_exceptions.items():
    print('  ', v, k)
  # Anything that returns an incorrect signature is suspicious.
  # The test fails even if the simple method above are not able to find
  # the factors. Such a failure to factor the key may simply mean that the
  # error is in an unexpected place and that the code just did not use the
  # right method to find the key.
  return cnt["critical error"] == 0

if __name__ == "__main__":
  test_path = pathlib.Path('../../testvectors/')
  for path in test_path.glob("rsa_private_key_pem_*.json"):
    test_rsa_private_key(path)
  for path in test_path.glob("rsa_three_prime_private_key_pem_*.json"):
    test_rsa_private_key(path)

