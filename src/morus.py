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

# Implements Morus640 and Morus1280

# Type hints
# The state of the cipher. These are 5 integers with size_m bits.
State = tuple[int, int, int, int, int]


class Morus:
  const_0 = bytes.fromhex("000101020305080d1522375990e97962")
  const_1 = bytes.fromhex("db3d18556dc22ff12011314273b528dd")

  def rotl(self, s: int, bits: int) -> int:
    """Rotates the bits of an integer to the left.

    Args:
      s: the integer to rotate. This is an integer with self.size_m bits.
      bits: the number of bits to rotate s.

    Returns:
      the rotated integer
    """
    a, b = divmod(s << bits, 2**self.size_m)
    return a + b

  def rotl_xxx_yy(self, s: int, bits: int) -> int:
    """Divides s into 4 integers and rotates them individially.

    Args:
      s: an integer of size_m bits.
      bits: the number of bits to rotate each of the 4 subintegers.

    Returns:
      the rotated integers
    """
    n = self.size_m // 4
    res = 0
    for i in range(4):
      x = (s >> (i * n)) % 2**n
      a, b = divmod(x << bits, 2**n)
      res += (a + b) << (i * n)
    return res

  def state_update(self, state: State, m: int) -> State:
    s0, s1, s2, s3, s4 = state
    s0 = self.rotl_xxx_yy(s0 ^ (s1 & s2) ^ s3, self.b[0])
    s3 = self.rotl(s3, self.w[0])
    s1 = self.rotl_xxx_yy(s1 ^ (s2 & s3) ^ s4 ^ m, self.b[1])
    s4 = self.rotl(s4, self.w[1])
    s2 = self.rotl_xxx_yy(s2 ^ (s3 & s4) ^ s0 ^ m, self.b[2])
    s0 = self.rotl(s0, self.w[2])
    s3 = self.rotl_xxx_yy(s3 ^ (s4 & s0) ^ s1 ^ m, self.b[3])
    s1 = self.rotl(s1, self.w[3])
    s4 = self.rotl_xxx_yy(s4 ^ (s0 & s1) ^ s2 ^ m, self.b[4])
    s2 = self.rotl(s2, self.w[4])
    return s0, s1, s2, s3, s4

  def encrypt(self, iv: bytes, aad: bytes, pt: bytes) -> tuple[bytes, bytes]:
    """Encrypts a plaintext.

    Args:
      iv: a 16 byte initialization vector
      aad: additional data to authenticate
      pt: the plaintext to encrypt

    Returns:
      a tuple containing the ciphertext and tag
    """
    state = self.initialize(iv)
    state = self.process_aad(state, aad)
    ct, state = self.raw_encrypt(state, pt)
    tag = self.finalize(state, len(aad) * 8, len(pt) * 8)
    return ct, tag.to_bytes(16, "little")

  def decrypt(self, iv: bytes, aad: bytes, ct: bytes, tag: bytes) -> bytes:
    """Decrypts a plaintext.

    Args:
      iv: a 16 byte initialization vector
      aad: additional data to authenticate
      ct: the ciphertext
      tag: the tag

    Returns:
      the plaintext if the decryption was successful.
    """
    state = self.initialize(iv)
    state = self.process_aad(state, aad)
    pt, state = self.raw_decrypt(state, ct)
    tag2 = self.finalize(state, len(aad) * 8, len(ct) * 8)
    tag2 = tag2.to_bytes(16, "little")
    if tag != tag2:
      raise ValueError("tag mismatch")
    return pt


class Morus640(Morus):
  tagsize = 16
  size_m = 128
  b = [5, 31, 7, 22, 13]
  w = [32, 64, 96, 64, 32]
  key_sizes_in_bytes = (16,)

  def __init__(self, key: bytes):
    if len(key) not in self.key_sizes_in_bytes:
      raise ValueError("invalid key size")
    self.key = int.from_bytes(key, "little")

  def initialize(self, iv: bytes) -> State:
    if len(iv) != 16:
      raise ValueError("invalid IV size")
    state = (int.from_bytes(iv, "little"), self.key, 2**128 - 1,
             int.from_bytes(self.const_0,
                            "little"), int.from_bytes(self.const_1, "little"))
    for _ in range(16):
      state = self.state_update(state, 0)
    s0, s1, s2, s3, s4 = state
    return s0, s1 ^ self.key, s2, s3, s4

  def process_aad(self, state: State, aad: bytes) -> State:
    """Processes the additional data.

    Args:
      state: the state before the processing
      aad: the additional data

    Returns:
      the state after processing the additional data
    """
    aad += bytes(-len(aad) % 16)
    for i in range(len(aad) // 16):
      block = aad[16 * i:16 * (i + 1)]
      b = int.from_bytes(block, "little")
      state = self.state_update(state, b)
    return state

  def output_mask(self, state: State) -> int:
    """Computes the value that is used to encrypt a block of plaintext.

    Args:
      state: the state

    Returns:
      the value that is xored with a block of plaintext.
    """
    s0, s1, s2, s3, s4 = state
    return s0 ^ self.rotl(s1, 96) ^ (s2 & s3)

  def raw_encrypt(self, state: State, pt: bytes) -> tuple[bytes, State]:
    """Encrypt the plaintext without computing the tag.

    Args:
      state: the state before encrypting
      pt: the plaintext
    Returns: a tuple containing the ciphertext and the state after the
      encryption.
    """
    ct_blocks = []
    for i in range((len(pt) + 15) // 16):
      pt_block = pt[16 * i:16 * (i + 1)]
      p = int.from_bytes(pt_block, "little")
      c = p ^ self.output_mask(state)
      state = self.state_update(state, p)
      if len(pt_block) < 16:
        c %= 1 << (len(pt_block) * 8)
      ct_blocks.append(c.to_bytes(len(pt_block), "little"))
    return b"".join(ct_blocks), state

  def raw_decrypt(self, state: State, ct: bytes) -> tuple[bytes, State]:
    """Decrypts plaintext without verifying the tag.

    Args:
      state: the state before decryption
      ct: the ciphertext

    Returns:
      a tuple containing the plaintext and the state after decryption
    """
    pt_blocks = []
    for i in range((len(ct) + 15) // 16):
      ct_block = ct[16 * i:16 * (i + 1)]
      c = int.from_bytes(ct_block, "little")
      p = c ^ self.output_mask(state)
      if len(ct_block) < 16:
        p %= 1 << (len(ct_block) * 8)
      state = self.state_update(state, p)
      pt_blocks.append(p.to_bytes(len(ct_block), "little"))
    return b"".join(pt_blocks), state

  def finalize(self, state: State, aad_len: int, msg_len: int) -> int:
    """Finalizes an encryption or decryption.

    Args:
      state: the state of the cipher after encryption or decryption
      aad_len: the length of the aad in bits
      msg_len: the length of the message in bits

    Returns:
      the tag
    """
    tmp = aad_len + (msg_len << 64)
    state = state[:4] + (state[0] ^ state[4],)
    for _ in range(10):
      state = self.state_update(state, tmp)
    return self.output_mask(state)


class Morus1280(Morus):
  tagsize = 16
  key_sizes_in_bytes = (16, 32)
  size_m = 256
  b = [13, 46, 38, 7, 4]
  w = [64, 128, 192, 128, 64]

  def __init__(self, key: bytes):
    if len(key) not in self.key_sizes_in_bytes:
      raise ValueError("invalid key size")
    if len(key) == 16:
      key = key * 2
    self.key = int.from_bytes(key, "little")

  def initialize(self, iv: bytes) -> State:
    if len(iv) != 16:
      raise ValueError("invalid iv size")
    state = (int.from_bytes(iv, "little"), self.key, 2**256 - 1, 0,
             int.from_bytes(self.const_0 + self.const_1, "little"))
    for _ in range(16):
      state = self.state_update(state, 0)
    s0, s1, s2, s3, s4 = state
    return s0, s1 ^ self.key, s2, s3, s4

  def process_aad(self, state: State, aad: bytes) -> State:
    """Processes the additional data.

    Args:
      state: the state before the processing
      aad: the additional data

    Returns:
      the state after processing the additional data
    """
    aad += bytes(-len(aad) % 32)
    for i in range(len(aad) // 32):
      block = aad[32 * i:32 * (i + 1)]
      b = int.from_bytes(block, "little")
      state = self.state_update(state, b)
    return state

  def output_mask(self, state: State) -> int:
    """Computes the value that is used to encrypt a block of plaintext.

    Args:
      state: the state

    Returns:
      the value that is xored with a block of plaintext.
    """
    s0, s1, s2, s3, s4 = state
    return s0 ^ self.rotl(s1, 192) ^ (s2 & s3)

  def raw_encrypt(self, state, pt: bytes) -> tuple[bytes, State]:
    """Encrypt the plaintext without computing the tag.

    Args:
      state: the state before encrypting
      pt: the plaintext
    Returns: a tuple containing the ciphertext and the state after the
      encryption.
    """
    ct_blocks = []
    for i in range((len(pt) + 31) // 32):
      pt_block = pt[32 * i:32 * (i + 1)]
      p = int.from_bytes(pt_block, "little")
      c = p ^ self.output_mask(state)
      state = self.state_update(state, p)
      if len(pt_block) < 32:
        c %= 1 << (len(pt_block) * 8)
      ct_blocks.append(c.to_bytes(len(pt_block), "little"))
    return b"".join(ct_blocks), state

  def raw_decrypt(self, state: State, ct: bytes) -> tuple[bytes, State]:
    """Decrypts plaintext without verifying the tag.

    Args:
      state: the state before decryption
      ct: the ciphertext

    Returns:
      a tuple containing the plaintext and the state after decryption
    """
    pt_blocks = []
    for i in range((len(ct) + 31) // 32):
      ct_block = ct[32 * i:32 * (i + 1)]
      c = int.from_bytes(ct_block, "little")
      p = c ^ self.output_mask(state)
      if len(ct_block) < 32:
        p %= 1 << (len(ct_block) * 8)
      state = self.state_update(state, p)
      pt_blocks.append(p.to_bytes(len(ct_block), "little"))
    return b"".join(pt_blocks), state

  def finalize(self, state: State, aad_len: int, msg_len: int) -> int:
    """Finalizes an encryption or decryption.

    Args:
      state: the state of the cipher after encryption or decryption
      aad_len: the length of the aad in bits
      msg_len: the length of the message in bits

    Returns:
      the tag
    """
    tmp = aad_len + (msg_len << 64)
    state = state[:4] + (state[0] ^ state[4],)
    for _ in range(10):
      state = self.state_update(state, tmp)
    return self.output_mask(state) % 2**128

