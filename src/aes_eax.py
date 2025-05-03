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

import eax
import aes
from typing import Optional, Tuple
import util

class AesEax(eax.Eax):
  name = "AES-EAX"

  @util.type_check
  def __init__(self, key: bytes, tagsize: int = 16):
    super().__init__(aes.AES, key, tagsize)

def test():
  msg = bytes.fromhex("F7FB")
  key = bytes.fromhex("91945D3F4DCBEE0BF45EF52255F095A4")
  nonce = bytes.fromhex("BECAF043B0A23D843194BA972C66DEBD")
  aad = bytes.fromhex("FA3BFD4806EB53FA")
  expected = bytes.fromhex("19DD5C4C9331049D0BDAB0277408F67967E5")
  cipher = AesEax(key)
  ct, tag = cipher.encrypt(nonce, aad, msg)
  assert ct + tag == expected

if __name__ == "__main__":
  test()

