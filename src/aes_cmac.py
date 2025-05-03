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

import aes
import cmac
import util

class AesCmac(cmac.Cmac):
  """Defined in RFC 4493"""
  name = "AES-CMAC"
  block_cipher = aes.AES

  def __init__(self, key: bytes, macsize: int = 16):
    super().__init__(aes.AES(key), macsize)

class AesOmac(cmac.Omac):
  name = "AES-OMAC"
  block_cipher = aes.AES

  def __init__(self, key: bytes, macsize: int=16):
    super.__init__(aes.AES(key), macsize)


# Examples from
# http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38b.pdf
# The final version below does not contain test vectors.
# http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38b.pdf
# The test vectors should be here:
# https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/message-authentication
# But so far they are missing.
L = [
  {
    "comment" : "Example 1",
    "key" : "2b7e151628aed2a6abf7158809cf4f3c",
    "msg" : "",
    "tag" : "bb1d6929e95937287fa37d129b756746",
  },
  {
    "comment" : "Example 2",
    "key" : "2b7e151628aed2a6abf7158809cf4f3c",
    "msg" : "6bc1bee22e409f96e93d7e117393172a",
    "tag" : "070a16b46b4d4144f79bdd9dd04a287c",
  },
  {
    "comment": "Example 3",
    "key" : "2b7e151628aed2a6abf7158809cf4f3c",
    "msg": "6bc1bee22e409f96e93d7e117393172a"
          "ae2d8a571e03ac9c9eb76fac45af8e51"
          "30c81c46a35ce411",
    "tag": "dfa66747de9ae63030ca32611497c827",
  },
  {
    "comment": "Example 4:Mlen=512",
    "key" : "2b7e151628aed2a6abf7158809cf4f3c",
    "msg": "6bc1bee22e409f96e93d7e117393172a"
          "ae2d8a571e03ac9c9eb76fac45af8e51"
          "30c81c46a35ce411e5fbc1191a0a52ef"
          "f69f2445df4f9b17ad2b417be66c3710",
    "tag": "51f0bebf7e3b9d92fc49741779363cfe",
  },
  {
    "comment": "Examples 5: 192 bit key",
    "key" : "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
    "msg" : "",
    "tag": "d17ddf46adaacde531cac483de7a9367",
  },
  {
    "comment": "Example 6:Mlen=128",
    "key" : "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
    "msg": "6bc1bee22e409f96e93d7e117393172a",
    "tag": "9e99a7bf31e710900662f65e617c5184",
  },
  {
    "comment": "Example 7:Mlen=320",
    "key" : "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
    "msg": "6bc1bee22e409f96e93d7e117393172a"
          "ae2d8a571e03ac9c9eb76fac45af8e51"
          "30c81c46a35ce411",
    "tag": "8a1de5be2eb31aad089a82e6ee908b0e",
  },
  {
    "comment": "Example 8:Mlen=512",
    "key" : "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
    "msg" : "6bc1bee22e409f96e93d7e117393172a"
           "ae2d8a571e03ac9c9eb76fac45af8e51"
           "30c81c46a35ce411e5fbc1191a0a52ef"
           "f69f2445df4f9b17ad2b417be66c3710",
    "tag": "a1d5df0eed790f794d77589659f39a11"
  },
  {
    "comment": "Examples 9:256 bit key:",
    "key" : "603deb1015ca71be2b73aef0857d7781"
           "1f352c073b6108d72d9810a30914dff4",
    "msg": "",
    "tag": "028962f61b7bf89efc6b551f4667d983",
  },
  {
    "comment": "Example 10: Mlen=128",
    "key" : "603deb1015ca71be2b73aef0857d7781"
           "1f352c073b6108d72d9810a30914dff4",
    "msg": "6bc1bee22e409f96e93d7e117393172a",
    "tag": "28a7023f452e8f82bd4bf28d8c37c35c",
  },
  {
    "comment": "Example 11:Mlen=320",
    "key" : "603deb1015ca71be2b73aef0857d7781"
           "1f352c073b6108d72d9810a30914dff4",
    "msg": "6bc1bee22e409f96e93d7e117393172a"
          "ae2d8a571e03ac9c9eb76fac45af8e51"
          "30c81c46a35ce411",
    "tag": "aaf3d8f1de5640c232f5b169b9c911e6",
  },
  {
    "comment": "Example12:Mlen=512",
    "key" : "603deb1015ca71be2b73aef0857d7781"
           "1f352c073b6108d72d9810a30914dff4",
    "msg": "6bc1bee22e409f96e93d7e117393172a"
          "ae2d8a571e03ac9c9eb76fac45af8e51"
          "30c81c46a35ce411e5fbc1191a0a52ef"
          "f69f2445df4f9b17ad2b417be66c3710",
    "tag": "e1992190549f6ed5696a2c056c315410",
  },
]

# Special cases
# Cmac("")  = E(bytearray([8]+15*[0]) xor k2)
# Cmac("\0"*16) = E(k1)

def test():
  for d in L:
    key = bytes.fromhex(d["key"])
    c = AesCmac(bytes.fromhex(d["key"]))
    t = c.mac(bytes.fromhex(d["msg"]))
    assert t.hex() == d["tag"]

if __name__ == "__main__":
  test()
