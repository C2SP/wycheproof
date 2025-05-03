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

import aes_gcm_siv

def main():
  key128 = bytes.fromhex("b1d28616c5d1a1027c38cd1221c2c00f")
  key256 = bytes.fromhex(
        "7283b1d12452616abd3c5d1a10327c329812732abc2876623313c0112bcdec0f")
  iv12 = bytes.fromhex("00112233445566778899aabb")
  aad = bytes.fromhex("00112233445566778899aabbccddeeff0011223344")

  for key in (key128, key256):
    a = aes_gcm_siv.AesGcmSiv(key)
    auth, enc = a.derive_sub_keys_raw(iv12)
    print("key =", key.hex())
    print("iv =", iv12.hex())
    print("auth =", auth.hex())
    print("enc =", enc.hex())
    print()

if __name__ == "__main__":
  main()
