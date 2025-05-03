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

import chacha
def test_quarter_round():
  res = chacha.quarter_round(0x11111111, 0x01020304, 0x9b8d6f43, 0x01234567)
  expected = ["0xea2a92f4", "0xcb1cf8ce", "0x4581472e", "0x5881c4bb"]
  assert [hex(x) for x in res] == expected


def test():
  key_hex = ("000102030405060708090a0b0c0d0e0f"
             "101112131415161718191a1b1c1d1e1f")
  key = bytes.fromhex(key_hex)
  nonce_hex = "000000090000004a00000000"
  nonce = bytes.fromhex(nonce_hex)
  cnt = 1
  block = chacha.chacha20_block(key, nonce, cnt)
  block_hex = block.hex()
  stream1 = ("10f1e7e4d13b5915500fdd1fa32071c4"
             "c7d1f4c733c068030422aa9ac3d46c4e"
             "d2826446079faa0914c2d705d98b02a2"
             "b5129cd1de164eb9cbd083e8a2503c4e")
  assert block_hex == stream1
  nonce_hex = "000000000000004a00000000"
  nonce = bytes.fromhex(nonce_hex)
  plaintext = (b"Ladies and Gentlemen of the class of '99: "
               b"If I could offer you only one tip for "
               b"the future, sunscreen would be it.")
  expected = ("6e2e359a2568f98041ba0728dd0d6981"
              "e97e7aec1d4360c20a27afccfd9fae0b"
              "f91b65c5524733ab8f593dabcd62b357"
              "1639d624e65152ab8f530c359f0861d8"
              "07ca0dbf500d6a6156a38e088a22b65e"
              "52bc514d16ccf806818ce91ab7793736"
              "5af90bbf74a35be6b40b8eedf2785e42"
              "874d")
  ct = chacha.chacha20_encrypt(key, cnt, nonce, plaintext)
  ct_hex = ct.hex()
  assert ct_hex == expected

if __name__ == "__main__":
  test_quarter_round()
  test()

