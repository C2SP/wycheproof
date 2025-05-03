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

import aes_gcm
import aes_ccm
import aes_ktv

def test_ktv(aead, ktv):
  """Checks test vectors"""
  for test in ktv:
    msg, key, iv, aad, ct, tag = [
        bytes.fromhex(test[n]) for n in ("msg", "key", "iv", "aad", "ct", "tag")]
    A = aead(key, tagsize = len(tag))
    c2, t2 = A.encrypt(iv, aad, msg)
    if c2 != ct:
      print(c2.hex(), ct.hex())
      assert False
    assert t2 == tag
    msg2 = A.decrypt(iv, aad, ct, tag)
    assert msg2 == msg

# Stuff to test:
#   plain input validation: noncesize valid.
#   tag too short (or too long)
#     -> needs two versions because t is encoded.
#   aad, no aad
#   msg too long
#   invalid noncesize (i.e. 14, 15, 16, 17, 128, 266)

def test_ktv2(aead, ktv):
  for tv in ktv:
    tlen = tv["Tlen"] // 8
    k = bytes.fromhex(tv["K"])
    n = bytes.fromhex(tv["N"])
    a = bytes.fromhex(tv["A"])
    p = bytes.fromhex(tv["P"])
    c = bytes.fromhex(tv["C"])
    cipher = aead(k, tlen)
    c2, t2 = cipher.encrypt(n,a,p)
    if c != c2 + t2:
      print("------")
      print(c2.hex())
      print(t2.hex())
      for x in tv:
        if not isinstance(tv[x], str) or len(tv[x]) < 256:
          print("%s:%s"%(x, tv[x]))

if __name__ == "__main__":
  test_ktv(aes_gcm.AesGcm, aes_ktv.AES_GCM_KTV)
  test_ktv2(aes_ccm.AesCcm, aes_ktv.AES_CCM_KTV)

