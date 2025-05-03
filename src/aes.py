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

import typing
import util

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

class AES:
  r'''A simple class that encrypts and decrypts single blocks with
     AES. This class is mainly used to make test vector generation
     as independent from underlying libraries as possible.
     This class works with bytes.

     >>> aes = AES(b'0123456789abcdef')
     >>> aes.encrypt_block(b'0123456789abcdef')
     b'rr~\x88\x1e\xdc\xfd\x01\x00\xa7\x18hy\t\xb5e'
     >>> aes.decrypt_block(b'rr~\x88\x1e\xdc\xfd\x01\x00\xa7\x18hy\t\xb5e')
     b'0123456789abcdef'
  '''

  key_sizes_in_bytes = (16, 24, 32)
  block_size_in_bytes = 16

  @util.type_check
  def __init__(self, key: bytes):
    if len(key) not in self.key_sizes_in_bytes:
      raise ValueError("invalid key size")
    self.E = Cipher(algorithms.AES(key), modes.ECB(), default_backend())

  @util.type_check
  def encrypt_block(self, b: bytes) -> bytes:
    if len(b) != 16:
      raise ValueError("invalid block size")
    encryptor = self.E.encryptor()
    return encryptor.update(b) + encryptor.finalize()

  @util.type_check
  def decrypt_block(self, b: bytes) -> bytes:
    if len(b) != 16:
      raise ValueError("invalid block size")
    decryptor = self.E.decryptor()
    return decryptor.update(b) + decryptor.finalize()

if __name__ == "__main__":
  import doctest
  doctest.testmod()

