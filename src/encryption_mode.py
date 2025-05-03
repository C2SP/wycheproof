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

def xor(a, b):
  return bytes(x ^ y for x, y in zip(a, b))


class Ecb:
  """Implements the ECB encryption mode.

  This is an abstract base class. Subclasses can be defined as shown in the
  following example:

  class AesEcbPkcs5:
    block_cipher = aes.Aes
    padding_scheme = padding.Pkcs5Padding
  """

  block_cipher = None  # a subclass of block_cipher
  padding_scheme = None  # a subclass of padding
  iv_size = None

  def __init__(self, key: bytes):
    if self.block_cipher is None:
      raise ValueError("block_cipher is unknown. Use a subclass")
    if self.padding_scheme is None:
      raise ValueError("padding_scheme is unknown. Use a subclass")
    self.cipher = self.block_cipher(key)
    self.block_size = self.block_cipher.block_size_in_bytes
    self.padding = self.padding_scheme(self.block_cipher)

  def encrypt_nopadding(self, ba: bytes) -> bytes:
    if len(ba) % self.block_size != 0:
      raise ValueError("Invalid message size")
    res = bytearray()
    for pos in range(0, len(ba), self.block_size):
      block = ba[pos:pos + self.block_size]
      block = self.cipher.encrypt_block(block)
      res.extend(block)
    return bytes(res)

  def decrypt_nopadding(self, ct: bytes) -> bytes:
    if len(ct) % self.block_size != 0:
      raise ValueError("Invalid ciphertext size")
    res = bytearray()
    for pos in range(0, len(ct), self.block_size):
      ctblock = ct[pos:pos + self.block_size]
      msgblock = self.cipher.decrypt_block(ctblock)
      res.extend(msgblock)
    return bytes(res)

  def encrypt(self, msg: bytes) -> bytes:
    return self.encrypt_nopadding(self.padding.pad(msg))

  def decrypt(self, ct: bytes) -> bytes:
    return self.padding.unpad(self.decrypt_nopadding(ct))


class Cbc:
  """Define the CBC encryption mode.

  This is an abstract base class. Subclasses can be defined as shown in the
  following example:

  class AesCbcPkcs(Cbc):
    block_cipher = aes.Aes
    padding_scheme = padding.Pkcs5Padding
  """
  block_cipher = None  # a subclass of block_cipher
  padding_scheme = None  # a subclass of padding

  def __init__(self, key):
    if self.block_cipher is None:
      raise ValueError("block_cipher is unknown. Use a subclass")
    if self.padding_scheme is None:
      raise ValueError("padding_scheme is unknown. Use a subclass")
    self.cipher = self.block_cipher(key)
    self.block_size = self.block_cipher.block_size_in_bytes
    self.iv_size = self.block_size
    self.padding = self.padding_scheme(self.block_cipher)

  def encrypt_nopadding(self, iv: bytes, ba: bytes) -> bytes:
    if len(iv) != self.iv_size:
      raise ValueError("Invalid IV size")
    if len(ba) % self.block_size != 0:
      raise ValueError("Invalid message size")
    block = iv
    res = bytearray()
    for pos in range(0, len(ba), self.block_size):
      block = xor(block, ba[pos:pos + self.block_size])
      block = self.cipher.encrypt_block(block)
      res.extend(block)
    return bytes(res)

  def decrypt_nopadding(self, iv: bytes, ct: bytes) -> bytes:
    if len(iv) != self.iv_size:
      raise ValueError("Invalid IV size")
    if len(ct) % self.block_size != 0:
      raise ValueError("Invalid ciphertext size")
    block = iv
    res = bytearray()
    for pos in range(0, len(ct), self.block_size):
      ctblock = ct[pos:pos + self.block_size]
      msgblock = xor(block, self.cipher.decrypt_block(ctblock))
      res.extend(msgblock)
      block = ctblock
    return bytes(res)

  def encrypt(self, iv: bytes, msg: bytes) -> bytes:
    return self.encrypt_nopadding(iv, self.padding.pad(msg))

  def decrypt(self, iv: bytes, ct: bytes) -> bytes:
    return self.padding.unpad(self.decrypt_nopadding(iv, ct))


class Cfb:
  block_cipher = None  # a subclass of block_cipher
  feedback_size_in_bits = None  # The size of the feedback

  def __init__(self, key: bytes):
    if self.block_cipher is None:
      raise ValueError("block_cipher is unknown. Use a subclass")
    self.block_size = self.block_cipher.block_size_in_bytes
    self.iv_size = self.block_size
    if self.feedback_size_in_bits is None:
      raise ValueError("feedback_size_in_bits is not specified")
    if self.feedback_size_in_bits % 8 != 0:
      raise ValueError("feedback not implemented for size not divisible by 8")
    self.feedback_size = self.feedback_size_in_bits // 8
    if self.feedback_size < 1 or self.feedback_size > self.block_size:
      raise ValueError("Invalid feedback size")
    self.cipher = self.block_cipher(key)

  def encrypt(self, iv: bytes, pt: bytes) -> bytes:
    if len(iv) != self.iv_size:
      raise ValueError("Invalid IV size")
    res = bytearray()
    for j in range(0, len(pt), self.feedback_size):
      iv = self.cipher.encrypt_block(iv)
      pt_block = pt[j:j + self.feedback_size]
      ct_block = xor(pt_block, iv[:len(pt_block)])
      res.extend(ct_block)
      iv = iv[len(ct_block):] + ct_block
    return bytes(res)

  def decrypt(self, iv: bytes, ct: bytes) -> bytes:
    if len(iv) != self.iv_size:
      raise ValueError("Invalid IV size")
    res = bytearray()
    for j in range(0, len(ct), self.feedback_size):
      iv = self.cipher.encrypt_block(iv)
      ct_block = ct[j:j + self.feedback_size]
      pt_block = xor(ct_block, iv[:len(ct_block)])
      res.extend(pt_block)
      iv = iv[len(ct_block):] + ct_block
    return bytes(res)


class Ctr:
  """Define the CTR encryption mode.

  This is an abstract base class. Subclasses can be defined as shown in the
  following example:

  class AesCtr(Ctr):
    block_cipher = aes.Aes
  """
  block_cipher = None  # a subclass of block_cipher

  def __init__(self, key):
    if self.block_cipher is None:
      raise ValueError("block_cipher is unknown. Use a subclass")
    self.cipher = self.block_cipher(key)
    self.block_size = self.block_cipher.block_size_in_bytes
    # This implementation assumes that the IV has the same length as
    # a message block. I.e. the caller would have to append 0's if the
    # IV is shorter than a block.
    self.iv_size = self.block_size

  def encrypt(self, iv: bytes, ba: bytes) -> bytes:
    if len(iv) != self.iv_size:
      raise ValueError("Invalid IV size")
    ctr = int.from_bytes(iv, "big")
    mod = 256**self.block_size
    res = bytearray()
    for pos in range(0, len(ba), self.block_size):
      inp = ctr.to_bytes(self.block_size, "big")
      stream = self.cipher.encrypt_block(inp)
      ctr = (ctr + 1) % mod
      res.extend(xor(stream, ba[pos:pos + self.block_size]))
    return bytes(res)

  decrypt = encrypt


class Ofb:
  """Define the CBC encryption mode.

  This is an abstract base class. Subclasses can be defined as shown in the
  following example:

  class AesOfb(Ofb):
    block_cipher = aes.Aes
  """
  block_cipher = None  # a subclass of block_cipher

  def __init__(self, key):
    if self.block_cipher is None:
      raise ValueError("block_cipher is unknown. Use a subclass")
    self.cipher = self.block_cipher(key)
    self.block_size = self.block_cipher.block_size_in_bytes
    self.iv_size = self.block_size

  def encrypt(self, iv: bytes, ba: bytes) -> bytes:
    if len(iv) != self.iv_size:
      raise ValueError("Invalid IV size")
    res = bytearray()
    stream = iv
    for pos in range(0, len(ba), self.block_size):
      stream = self.cipher.encrypt_block(stream)
      res.extend(xor(stream, ba[pos:pos + self.block_size]))
    return bytes(res)

  decrypt = encrypt
