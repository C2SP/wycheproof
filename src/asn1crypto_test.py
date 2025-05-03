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

import asn1crypto.keys as keys
import json

def test_keys(filename: str, asn_struct, kn):
  with open('../../testvectors/' + filename) as fp:
    test_vectors = json.load(fp)
  errors = 0
  for tg in test_vectors['testGroups']:
    for t in tg['tests']:
      asn = bytes.fromhex(t[kn])
      try:
        res = asn_struct.load(asn).native
        if t['result'] == "invalid":
          errors += 1
          print(t['tcId'], 'accepted', t['result'], t['flags'], t['comment'] )
      except Exception as ex:
        accepted = False
        if t['result'] == 'valid':
          errors += 1
          print(t['tcId'], 'rejected', t['result'], t['comment'], ex)
  print(errors, 'errors out of ', test_vectors['numberOfTests'])

TESTS = [
  ("eckey_secp256k1_test.json", keys.PublicKeyInfo, 'encoded'),
  ("ec_priv_key_secp256r1_asn_test.json", keys.PrivateKeyInfo, 'encodedKey'),
]

def tv():
  for fn, asn_struct, kn in TESTS:
    test_keys(fn, asn_struct, kn)
 
if __name__ == "__main__":
  tv() 

