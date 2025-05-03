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

# Implements CBC with ciphertext stealing.
# This file implements SP800-38a.


def _xor(a, b):
  return bytes(x ^ y for x, y in zip(a, b))


class CbcCs:
  block_cipher = None

  def __init__(self, key):
    if self.block_cipher is None:
      raise ValueError("block_cipher is unknown. Use a subclass")
    self.cipher = self.block_cipher(key)
    self.block_size = self.block_cipher.block_size_in_bytes


class CbcPkcs5:
  block_cipher = None

  def __init__(self, key):
    if self.block_cipher is None:
      raise ValueError("block_cipher is unknown. Use a subclass")
    self.cipher = self.block_cipher(key)
    self.block_size = self.block_cipher.block_size_in_bytes

  def encrypt_nopadding(self, iv: bytes, ba: bytes) -> bytes:
    assert len(iv) == self.block_size
    assert len(ba) % self.block_size == 0
    block = iv
    res = bytearray()
    for pos in range(0, len(ba), self.block_size):
      block = xor(block, ba[pos:pos + self.block_size])
      block = self.cipher.encrypt_block(block)
      res.extend(block)
    return bytes(res)


class CbcCs1(CbcCs):

  def encrypt(self, iv: bytes, msg: bytes) -> bytes:
    block_size = self.block_size
    full_blocks = len(msg) // block_size
    res = []
    ct_block = iv
    if len(msg) == 0:
      return b""
    if len(msg) < block_size:
      raise ValueError("Message too short")
    for i in range(full_blocks):
      pt_block = msg[i * block_size:(i + 1) * block_size]
      inp_block = _xor(pt_block, ct_block)
      ct_block = self.cipher.encrypt_block(inp_block)
      res.append(ct_block)
    if len(msg) % block_size > 0:
      cn1 = res.pop()
      last_block = msg[full_blocks * block_size]
      pad_len = -len(last_block) % block_size
      padded_block = last_block + bytes(pad_len)
      inp_block = xor(cn1, padded_block)
      cn = self.cipher.encrypt_block(inp_block)
      res.append(cn1[:len(last_block)])
      res.append(cn)
    return b"".join(res)

  def decrypt(self, iv: bytes, ct: bytes) -> bytes:
    block_size = self.block_size
    full_blocks = len(msg) // block_size
    res = []
    if len(ct) == 0:
      return b""
    if len(ct) < block_size:
      raise ValueError("Ciphertext too short")
    for i in range(full_blocks):
      if i == 0:
        inp
      pt_block = msg[i * block_size:(i + 1) * block_size]
      inp_block = _xor(pt_block, ct_block)
      ct_block = self.cipher.encrypt_block(inp_block)
      res.append(ct_block)
    if len(msg) % block_size > 0:
      cn1 = res.pop()
      last_block = msg[full_blocks * block_size]
      pad_len = -len(last_block) % block_size
      padded_block = last_block + bytes(pad_len)
      inp_block = xor(cn1, padded_block)
      cn = self.cipher.encrypt_block(inp_block)
      res.append(cn1[:len(last_block)])
      res.append(cn)
    return b"".join(res)

    return self.unpad(self.decrypt_nopadding(iv, ct))


class CbcCs2(CbcCs):
  pass


class CbcCs3(CbcCs):
  pass
