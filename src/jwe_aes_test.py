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

import jwe_aes
from jwe_aes_ktv import AesCbcHmac_KTV 

def test_aes_cbc_hmac():
  errors = 0
  for tv in AesCbcHmac_KTV:
    clz = jwe_aes.ALGORITHMS[tv["alg"]]
    key = bytes.fromhex(tv["key"])
    cipher = clz(key)
    msg = bytes.fromhex(tv["msg"])
    iv = bytes.fromhex(tv["iv"])
    aad = bytes.fromhex(tv["aad"])
    ct = bytes.fromhex(tv["ct"])
    tag = bytes.fromhex(tv["tag"])
    c,t = cipher.encrypt(iv, aad, msg)
    if c != ct or t != tag:
      print(c.hex())
      print(ct.hex())
      print(t.hex())
      print(tag.hex())
      errors += 1
      continue
    m = cipher.decrypt(iv, aad, ct, tag)
    if m != msg:
      errors += 1 
  print("test_aes_cbc_hmac", errors)
  assert errors == 0

if __name__ == "__main__":
  test_aes_cbc_hmac()
