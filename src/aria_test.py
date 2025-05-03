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

import aria
import aria_ccm
import aria_gcm
import aria_ktv

ARIA_KTV = [
    (
        "000102030405060708090a0b0c0d0e0f",
        "00112233445566778899aabbccddeeff",
        "d718fbd6ab644c739da95f3be6451778",
    ),
    (
        "000102030405060708090a0b0c0d0e0f"
        "1011121314151617",
        "00112233445566778899aabbccddeeff",
        "26449c1805dbe7aa25a468ce263a9e79",
    ),
    (
        "000102030405060708090a0b0c0d0e0f"
        "101112131415161718191a1b1c1d1e1f",
        "00112233445566778899aabbccddeeff",
        "f92bd7c79fb72e2f2b8f80c1972d24fc",
    ),
]


def test_block():
  for key, pt, ct in ARIA_KTV:
    a = aria.Aria(bytes.fromhex(key))
    ct2 = a.encrypt_block(bytes.fromhex(pt)).hex()
    pt2 = a.decrypt_block(bytes.fromhex(ct)).hex()
    assert ct == ct2
    assert pt == pt2


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


if __name__ == "__main__":
  test_block()
  test_ktv(aria_gcm.AriaGcm, aria_ktv.ARIA_GCM_KTV)
  test_ktv(aria_ccm.AriaCcm, aria_ktv.ARIA_CCM_KTV)
  print("--done--")
