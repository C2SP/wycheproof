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

import aes_modes
import hmac
    
class JweAesCbcHmac:
  def __init__(self, key: bytes):
    assert len(key) == self.aes_key_size + self.hmac_key_size
    self.hmac_key = key[:self.hmac_key_size]
    self.aes_key = key[self.hmac_key_size:]
    self.cipher = aes_modes.AesCbcPkcs5(self.aes_key)

  def tag(self, iv: bytes, aad: bytes, ct: bytes) -> bytes:
    data = aad + iv + ct + (8 * len(aad)).to_bytes(8, "big")
    return hmac.digest(self.hmac_key, data, self.hmac_sha)[:self.tagsize]

  def encrypt(self, iv: bytes, aad: bytes, payload: bytes) -> tuple[bytes, bytes]:
    ct = self.cipher.encrypt(iv, payload)
    return ct, self.tag(iv, aad, ct)
    
  def decrypt(self, iv: bytes, aad: bytes, ct: bytes, tag: bytes) -> bytes:
    t = self.tag(iv, aad, ct)
    if tag != t:
      raise ValueError("tag mismatch")
    return self.cipher.decrypt(iv, ct)

class JweAes128Sha256(JweAesCbcHmac):
  oid = "2.16.840.1.101.3.4.1.2"
  jwe_name = "A128CBC-HS256"
  aes_key_size = 16
  hmac_key_size = 16
  hmac_sha = "SHA-256"
  tagsize = 16

class JweAes192Sha384(JweAesCbcHmac):
  oid = "2.16.840.1.101.3.4.1.22"
  jwe_name = "A192CBC-HS384"
  aes_key_size = 24
  hmac_key_size = 24
  hmac_sha = "SHA-384"
  tagsize = 24
  
class JweAes256Sha512(JweAesCbcHmac):
  oid = "2.16.840.1.101.3.4.1.42"
  jwe_name = "A256CBC-HS512"
  aes_key_size = 32
  hmac_key_size = 32
  hmac_sha = "SHA-512"
  tagsize = 32
  
ALGORITHMS = {
  clz.jwe_name : clz for clz in [JweAes128Sha256, JweAes192Sha384, JweAes256Sha512] }
