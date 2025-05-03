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

from pbes2 import Pbes2WithIv
from aes_cbc_pkcs5 import AesCbcPkcs5

# Supported by jdk11:
# Cipher.PBEWithHmacSHA1AndAES_128
# Cipher.PBEWithHmacSHA1AndAES_256
# Cipher.PBEWithHmacSHA224AndAES_128
# Cipher.PBEWithHmacSHA224AndAES_256
# Cipher.PBEWithHmacSHA256AndAES_128
# Cipher.PBEWithHmacSHA256AndAES_256
# Cipher.PBEWithHmacSHA384AndAES_128
# Cipher.PBEWithHmacSHA384AndAES_256
# Cipher.PBEWithHmacSHA512AndAES_128
# Cipher.PBEWithHmacSHA512AndAES_256
# 
# Conscrypt:
# Alg.Alias.Cipher.PBEWithHmacSHA1AndAES_128 : AES_128/CBC/PKCS5PADDING
# Alg.Alias.Cipher.PBEWithHmacSHA1AndAES_256 : AES_256/CBC/PKCS5PADDING
# Alg.Alias.Cipher.PBEWithHmacSHA224AndAES_128 : AES_128/CBC/PKCS5PADDING
# Alg.Alias.Cipher.PBEWithHmacSHA224AndAES_256 : AES_256/CBC/PKCS5PADDING
# Alg.Alias.Cipher.PBEWithHmacSHA256AndAES_128 : AES_128/CBC/PKCS5PADDING
# Alg.Alias.Cipher.PBEWithHmacSHA256AndAES_256 : AES_256/CBC/PKCS5PADDING
# Alg.Alias.Cipher.PBEWithHmacSHA384AndAES_128 : AES_128/CBC/PKCS5PADDING
# Alg.Alias.Cipher.PBEWithHmacSHA384AndAES_256 : AES_256/CBC/PKCS5PADDING
# Alg.Alias.Cipher.PBEWithHmacSHA512AndAES_128 : AES_128/CBC/PKCS5PADDING
# Alg.Alias.Cipher.PBEWithHmacSHA512AndAES_256 : AES_256/CBC/PKCS5PADDING

def Pbes2Impl(
    md: str,
    cipher_name: str,
    key_size_in_bytes: int):
  if cipher_name == "AES-CBC":
    cipher = AesCbcPkcs5
    cname = f"Aes_{8 * key_size_in_bytes}"
  else:
    raise ValueError("cipher_name not supported:" + cipher_name)
  compact_md = md
  if compact_md.startswith("SHA-"):
    compact_md = "SHA" + compact_md[4:]
  compact_md = compact_md[0].upper() + compact_md[1:].lower()
  name = f"PbeWithHmac{compact_md}And{cname}"
  return Pbes2WithIv(md, cipher, key_size_in_bytes, name=name)


