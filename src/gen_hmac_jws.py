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

import jws_hmac
import json

def gen_jwk_tv(hs, msg: bytes, group_comment: str, comment: str, valid: bool):
  jws = hs.mac(msg).decode("ascii")
  group = {
    "type" : "JsonWebSignature",
    "comment" : group_comment,
    "private" : {"keys" : [hs.as_struct()]},
    "tests" : [{
       "tcId": None,
       "comment" : comment,
       "jws" : jws,
       "result" : "valid" if valid else "invalid",
       "flags" :[]}]
    }
  return group

def gen_short_keys():
  groups = []
  for alg, params in jws_hmac.MAC_ALGORITHMS.items():
     min_key_size = params["min_key_size"]
     for key, comment, label in [
       (b"", "empty key", "empty_key"),
       (bytes(range(min_key_size // 2)), f"key of size {min_key_size // 2}", "short_key"),
       (bytes(range(min_key_size - 1)), f"key of size {min_key_size - 1}", "key_too_short") 
     ]:
       hs = jws_hmac.Hs(alg, key, kid = f"{alg.lower()}_key", validate=False)
       groups.append(gen_jwk_tv(hs, b"foo", alg, label, False))
  return groups

def gen_long_keys():
  groups = []
  for alg, params in jws_hmac.MAC_ALGORITHMS.items():
     key = bytes(range(65))
     hs = jws_hmac.Hs(alg, key, kid = f"long_{alg.lower()}_key")
     groups.append(gen_jwk_tv(hs, b"foo", alg, "long_key", True))
  return groups
  
def addtcids(groups):
  cnt = 0
  for g in groups:
    for tv in g["tests"]:
      cnt += 1
      tv["tcId"] = cnt
  return cnt

def gen_hs():
  groups = []
  groups += gen_short_keys()
  groups += gen_long_keys()

  cnt = addtcids(groups)
  
  test = {
    "generatorVersion" : "0.3",
    "numberOfTests" : cnt,
    "testGroups" : groups
  }
  return test

if __name__ == "__main__":
  v = gen_hs()
  res = json.dumps(v, indent=2)
  print(res)
