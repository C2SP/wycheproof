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

import pbkdf

# Encryption schemes:
# RFC 8018 Section B.2.5:
#   AES-CBC-Pad    CBC encryption with PKCS #5 padding.
#   The IV is a parameter field associated with the OID.
#
# Legacy schemes are (DES-EDE3|RC2|RC5)-CBC-PAD



class Pbes2WithIv:
  """Implements PBES2 using a cipher that takes an IV as parameter."""
  def __init__(self, md: str, cipher, dklen: int, name: str):
    self.md = md
    self.kdf = pbkdf.PBKDF2(md)
    self.cipher = cipher
    self.dklen = dklen
    self.name = name
    self.iv_size = self.cipher(bytes(dklen)).iv_size

  def crypter(self, password: bytes, salt: bytes, count: int):
    dk = self.kdf(password, salt, count, self.dklen)
    return self.cipher(dk)

  def encrypt(self, pwd: bytes, salt: bytes, count: int, iv: bytes,
              msg: bytes) -> bytes:
    return self.crypter(pwd, salt, count).encrypt(iv, msg)

  def decrypt(self, pwd: bytes, salt: bytes, count: int, iv: bytes,
              ct: bytes) -> bytes:
    return self.crypter(pwd, salt, count).decrypt(iv, ct)


