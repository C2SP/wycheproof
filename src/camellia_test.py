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

import camellia
import camellia_ccm
import camellia_ktv

KTV = [
    {
        "key": "01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 10",
        "pt": "01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 10",
        "ct": "67 67 31 38 54 96 69 73 08 57 06 56 48 ea be 43"
    },
    {
        "key": "01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 10"
               "00 11 22 33 44 55 66 77",
        "pt": "01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 10",
        "ct": "b4 99 34 01 b3 e9 96 f8 4e e5 ce e7 d7 9b 09 b9"
    },
    {
        "key": "01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 10"
               "00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff",
        "pt": "01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 10",
        "ct": "9a cc 23 7d ff 16 d7 6c 20 ef 7c 91 9e 3a 75 09"
    },
]


def test_ktv(aead, ktv):
  errors = 0
  for t in ktv:
    key = bytes.fromhex(t["key"])
    msg = bytes.fromhex(t["msg"])
    iv = bytes.fromhex(t["iv"])
    tag = bytes.fromhex(t["tag"])
    aad = bytes.fromhex(t["aad"])
    ct = bytes.fromhex(t["ct"])
    cipher = aead(key, len(tag))
    c2, t2 = cipher.encrypt(iv, aad, msg)
    if c2 != ct or t2 != tag:
      for v in (ct, c2, tag, t2):
        print(v.hex())
        errors += 1
    m2 = cipher.decrypt(iv, aad, ct, tag)
    if m2 != msg:
      for v in (mst, m2):
        print(v.hex())
        errors += 1
  assert errors == 0


def test_block():
  for t in KTV:
    key, pt, ct = [bytes.fromhex(t[n]) for n in ["key", "pt", "ct"]]
    c = camellia.Camellia(key)
    enc = c.encrypt_block(pt)
    assert ct == enc
    dec = c.decrypt_block(ct)
    assert pt == dec


def equivalent_keys():
  k1 = bytes(range(24))
  k2 = k1 + bytes(~x & 0xff for x in k1[16:])
  c1 = camellia.Camellia(k1)
  c2 = camellia.Camellia(k2)
  m = bytes(range(16))
  assert c1.encrypt_block(m) == c2.encrypt_block(m)

if __name__ == "__main__":
  test_block()
  test_ktv(camellia_ccm.CamelliaCcm, camellia_ktv.CAMELLIA_CCM_KTV)
  equivalent_keys()
  print("--done--")
