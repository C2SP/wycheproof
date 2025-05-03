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

import aes_siv

KTV = [
    {
        "comment": "RFC 5297, A.1",
        "key": "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0"
               "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
        "aads": ["101112131415161718191a1b1c1d1e1f"
                 "2021222324252627"],
        "msg": "112233445566778899aabbccddee",
        "ct": "85632d07c6e8f37f950acd320a2ecc93"
              "40c02b9690c4dc04daef7f6afe5c"
    },
    {
        "comment": "RFC 5297, A.2",
        "key": "7f7e7d7c7b7a79787776757473727170"
               "404142434445464748494a4b4c4d4e4f",
        "aads": [
            "00112233445566778899aabbccddeeff"
            "deaddadadeaddadaffeeddccbbaa9988"
            "7766554433221100", "102030405060708090a0",
            "09f911029d74e35bd84156c5635688c0"
        ],
        "msg": "7468697320697320736f6d6520706c61"
               "696e7465787420746f20656e63727970"
               "74207573696e67205349562d414553",
        "ct": "7bdb6e3b432667eb06f4d14bff2fbd0f"
              "cb900f2fddbe404326601965c889bf17"
              "dba77ceb094fa663b7a3f748ba8af829"
              "ea64ad544a272e9c485b62a3fd5c0d"
    },
]

# The number of components passed to S2V must not be larger than
# 127. If an arbitrary number of components are used then an
# attack is possible.
# This is mentioned in RFC 5297 in section 7, but it has not been
# included into the standard.
def test_s2v_limit():
  # These parameters can be chosen arbitrarily.
  key = bytes(range(32))
  msg = b"Test"
  a0 = b"data 0"
  a1 = b"some other data"

  s = aes_siv.AesSiv(key)
  aads = [a0] * 129
  # Generates two equal ciphertexts with distinct AAD lists
  c1 = s.encrypt_raw(msg, *aads)
  for j in (128, 7, 2, 1, 0):
    aads[128 - j] = a1
  c2 = s.encrypt_raw(msg, *aads)
  assert c1 == c2

def test_ktv():
  for d in KTV:
    s = aes_siv.AesSiv(bytes.fromhex(d["key"]))
    msg = bytes.fromhex(d["msg"])
    aads = [bytes.fromhex(a) for a in d["aads"]]
    c, tag = s.encrypt_raw(msg, *aads)
    assert (tag + c).hex() == d["ct"]
    ct = bytes.fromhex(d["ct"])
    t,c = ct[:16], ct[16:]
    p = s.decrypt_raw(c,t, *aads)
    assert p.hex() == d["msg"]
  print("done")

if __name__ == "__main__":
  test_ktv()
  test_s2v_limit()
