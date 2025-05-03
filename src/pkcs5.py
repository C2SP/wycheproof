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

# Implements RFC 8018
# PKCS #5: Password-Based Cryptography Specification Version 2.1

import util
import oid
import typing


OneTimeCipher = typing.Any

# Oids
pkcs_5 = oid.Oid([1,2,840,113549,1,5], "pkcs_5", reference="RFC 8018")
id_pbkdf2 = oid.Oid(pkcs_5 + [12], "id-PBKDF2", reference="RFC 8018")
pbe_md2_des_cbc = oid.Oid(pkcs_5 + [1], "pbeWithMD2AndDES-CBC", reference="RFC 8018")
pbe_md2_rc2_cbc = oid.Oid(pkcs_5 + [4], "pbeWithMD2AndRC2-CBC", reference="RFC 8018")
pbe_md5_des_cbc = oid.Oid(pkcs_5 + [3], "pbeWithMD5AndDES-CBC", reference="RFC 8018")
pbe_md5_rc2_cbc = oid.Oid(pkcs_5 + [6], "pbeWithMD5AndRC2-CBC", reference="RFC 8018")
pbe_sha1_des_cbc = oid.Oid(pkcs_5 + [10], "pbeWithSHA1AndDES-CBC", reference="RFC 8018")
pbe_sha1_rc2_cbc = oid.Oid(pkcs_5 + [11], "pbeWithSHA1AndRC2-CBC", reference="RFC 8018")


class Pbes2:
  def __init__(self,
               kdf,
               cipher,
               dk_len: int,
               itercount: int):
    self.kdf = kdf
    self.cipher = cipher
    self.dk_len = dk_len
    self.itercount = itercount

  def encrypt(self,
              pw: bytes,
              salt: bytes,
              msg: bytes):
    dk = self.kdf(pw, salt, self.itercount, self.dk_len)
    c = self.cipher(dk)
    return c.encrypt(msg)

  def decrypt(self,
              pw: bytes,
              salt: bytes,
              msg: bytes):
    dk = self.kdf(pw, salt, self.itercount, self.dk_len)
    c = self.cipher(dk)
    return c.decrypt(msg)

