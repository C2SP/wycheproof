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

import aes_xts
import aes_xts_ktv
import sm4_xts


def test_ktv(cipher_class, ktv):
  for t in ktv:
    key = bytes.fromhex(t["key"])
    tweak = t["seq"]
    pt = bytes.fromhex(t["pt"])
    cipher = cipher_class(key)
    ct = cipher.encrypt(pt, tweak)
    assert ct.hex() == t["ct"]


def test_encrypt_decrypt(cipher_class, key_sizes):
  for key_size in key_sizes:
    key = bytes(range(key_size))
    tweak = 0xf0112233445566778899aabbccddeeff
    cipher = cipher_class(key)
    for pt_size in range(16, 128):
      pt = bytes(range(pt_size))
      ct = cipher.encrypt(pt, tweak)
      dec = cipher.decrypt(ct, tweak)
      if pt != dec:
        print(key_size, pt_size, pt.hex(), dec.hex())


if __name__ == "__main__":
  test_encrypt_decrypt(aes_xts.AesXts, (32, 48, 64))
  test_encrypt_decrypt(sm4_xts.Sm4Xts, (32,))
  test_ktv(aes_xts.AesXts, aes_xts_ktv.AES_XTS_KTV)
