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

import xchacha_poly1305
import xchacha_poly1305_ktv

def h_chacha20_test():
  key = bytes(range(32))
  nonce = bytes.fromhex("000000090000004a0000000031415927")
  res = xchacha_poly1305.h_chacha20(key, nonce).hex()
  expected = "82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc"
  assert res == expected

def test_ktv():
  errors = 0
  for t in xchacha_poly1305_ktv.XCHACHA_POLY1305_KTV:
    key = bytes.fromhex(t.key)
    nonce = bytes.fromhex(t.nonce)
    pt = bytes.fromhex(t.pt)
    aad = bytes.fromhex(t.aad)
    aead = xchacha_poly1305.Xchacha20Poly1305(key)
    c,tag = aead.encrypt(nonce, aad, pt)
    if c.hex() != t.ct or tag.hex() != t.tag:
      print("========================")
      print("pt", pt)
      print("expected ct", t.ct)
      print("computed ct", c.hex())
      print("expected tag", t.tag)
      print("computed tag", tag.hex())
      errors += 1
    m = aead.decrypt(nonce, aad, c, tag)
    if m != pt:
      print("====== Incorrect decryption")
      print("pt", pt)
      print("decrypted", m.hex())
      print("ct", c.hex())
      print("tag", t.hex())
      errors += 1
  assert errors == 0

if __name__ == "__main__":
  h_chacha20_test()
  test_ktv()
  print("done")
