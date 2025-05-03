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

# Known test vectors for HKDF
import hkdf
import hkdf_ktv

def test():
  errors = 0
  for sha, ikm, salt, info, size, okm, comment in hkdf_ktv.get_vectors():
    f = hkdf.hkdf_for_hash(sha)
    res = f(ikm, salt, info, size)
    if okm != res:
      print("expected: %s computed: %s" % (okm.hex(), res.hex()))
      errors += 1
  assert errors == 0

if __name__ == "__main__":
  test()

