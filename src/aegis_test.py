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

import aegis
import aegis_ktv


def testCipher(clz, test_vectors):
  errors = 0
  for tv_hex in test_vectors:
    k, i, a, p, c, t = [bytes.fromhex(v) for v in tv_hex]
    cipher = clz(k)
    c2, t2 = cipher.encrypt(i, a, p)
    if c != c2 or t != t2:
      print("wrong encryption")
      print(tv_hex)
      print(c.hex())
      print(c2.hex())
      print(len(a), len(p))
      print(t.hex())
      print(t2.hex())
      print("---------")
      errors += 1
    try:
      p2 = cipher.decrypt(i, a, c, t)
      if p2 != p:
        print("wrong decryption")
        print(tv_hex)
        print(p.hex())
        print(p2.hex())
        errors += 1
    except Exception as e:
      print("decryption failed", e)
      errors += 1

  print("%s errors found" % errors)
  assert errors == 0


def testAegis():
  testCipher(aegis.Aegis128, aegis_ktv.TEST_VECTOR_AEGIS)
  testCipher(aegis.Aegis128L, aegis_ktv.TEST_VECTOR_AEGIS128L)
  testCipher(aegis.Aegis256, aegis_ktv.TEST_VECTOR_AEGIS256)


if __name__ == "__main__":
  testAegis()
