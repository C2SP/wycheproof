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

import morus
import morus_ktv


def test(cipher_cls, ktv):
  print(cipher_cls.__name__)
  errors = 0
  for t in ktv:
    key = bytes.fromhex(t["key"])
    iv = bytes.fromhex(t["iv"])
    aad = bytes.fromhex(t["aad"])
    pt = bytes.fromhex(t["pt"])
    ct = bytes.fromhex(t["ct"])
    m = cipher_cls(key)
    c, t = m.encrypt(iv, aad, pt)
    if c + t != ct:
      errors += 1
      print("incorrect encryption")
      print(pt.hex())
      print((c + t).hex())
      print(ct.hex())
    p = m.decrypt(iv, aad, c, t)
    if p != pt:
      print("incorrect decryption", p.hex(), pt.hex())
      errors += 1
  print(errors, "errors")
  assert errors == 0


if __name__ == "__main__":
  test(morus.Morus640, morus_ktv.MORUS640_KTV)
  test(morus.Morus1280, morus_ktv.MORUS1280_KTV)
