# Copyright 2017 Google Inc. All Rights Reserved.
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
# ==============================================================================
"""AES encryption and decryption for one data block."""

import aes_block


class Aes(object):
  """AES encryption and decryption for one data block."""

  def __init__(self, key):
    if len(key) not in (16, 24, 32):
      raise ValueError('invalid key length')
    self.key = map(ord, key)
    n = len(key) + 28
    self.enc_key = [0] * n
    self.dec_key = [0] * n
    aes_block.expand_key(self.key, self.enc_key, self.dec_key)

  def encrypt_block(self, plaintext):
    """Encrypts one block of plaintext.

    Args:
      plaintext: bytes array (aka characters).

    Returns:
      AES encryption of the plaintext.

    Raises:
      ValueError: If the plaintext is not a full block.
    """
    if len(plaintext) != self.BLOCK_SIZE:
      raise ValueError('plaintext is not full block of %d bytes',
                       self.BLOCK_SIZE)
    ciphertext = [0] * len(plaintext)
    aes_block.encrypt_block(self.enc_key, map(ord, plaintext), ciphertext)
    return ''.join(map(chr, ciphertext))

  def decrypt_block(self, ciphertext):
    """Decrypts one block of ciphertext.

    Args:
      ciphertext: bytes array (aka characters).

    Returns:
      AES decryption of the plaintext.

    Raises:
      ValueError: If the ciphertext is not a full block.
    """
    if len(ciphertext) != self.BLOCK_SIZE:
      raise ValueError('ciphertext is not full block of %d bytes',
                       self.BLOCK_SIZE)
    plaintext = [0] * len(ciphertext)
    aes_block.decrypt_block(self.dec_key, map(ord, ciphertext), plaintext)
    return ''.join(map(chr, plaintext))

  BLOCK_SIZE = 16
