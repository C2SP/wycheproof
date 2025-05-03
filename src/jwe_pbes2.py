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

import keywrap
import pbkdf

ALGORITHMS = {
  "PBES2_HS256_A128KW" : {
     "md" : "SHA-256",
     "key_size": 128
   },
  "PBES2_HS384_A192KW" : {
     "md" : "SHA-384",
     "key_size": 192
   },
  "PBES2_HS512_A256KW" : {
     "md" : "SHA-512",
     "key_size": 256
   }
}

def compute_salt(alg: str, p2s: bytes) -> bytes:
  """Computes the PBES2 salt input.
  
  Described in Section 4.8.11
  """
  return alg.encode("utf8") + bytes(1) + jw_util.decode(p2s)

class JwePbes2:
  def __init__(self, md: str, key_size: int, password: bytes):
    self.md = md
    self.key_size = key_size
    self.pbkdf = pbkdf.PBKDF2(md)
    self.cipher = keywrap.AesKw
    self.password = password

  def kw(self, salt: bytes, count: int):
    pbes = pbes2.Pbes2(self.pbkdf, self.cipher, self.password, p2c, key_size)
    dk = self.pbkdf(self.password, salt, count, self.key_size)
    return self.cipher(dk)
  
  def encrypt(self, salt: bytes, count: int, msg: bytes) -> bytes:
    return self.kw(salt, count).wrap(msg)

  def decrypt(self, salt: bytes, p2c: int, ct: bytes) -> bytes:
    return self.kw(salt, count).unwrap(ct)

