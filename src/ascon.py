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

# Implements ASCON.
# http://ascon.iaik.tugraz.at/

import struct

# ===== Type hints =====

# The ASCON state is a list of 5 integers
State = list[int]


def bytes_to_int(ba: bytes) -> int:
  return int.from_bytes(ba, "big")


def bytes_to_state(ba: bytes) -> State:
  return list(struct.unpack(">5Q", ba))


def int_to_bytes(val: int, nbytes: int) -> bytes:
  return val.to_bytes(nbytes, 'big')


def rot64(val: int, r: int) -> int:
  res = (val >> r) | (val << (64 - r))
  return res & 0xffffffffffffffff

# === Ascon permutation ===

ROUND_CONSTANTS = [0xf0 - i * 0xf for i in range(12)]


def permute(s: State, rounds: int = 1) -> None:
  """
    Ascon permutation
    Args:
      S: the state, this state is updated
      rounds: the number of rounds
    """
  assert(rounds <= 12)
  for rconst in ROUND_CONSTANTS[-rounds:]:
    s[2] ^= rconst
    # substitution layer
    s[0] ^= s[4]
    s[4] ^= s[3]
    s[2] ^= s[1]
    w = s + s[:2]
    for i in range(5):
      s[i] ^= ~w[i + 1] & w[i + 2]
    s[1] ^= s[0]
    s[0] ^= s[4]
    s[3] ^= s[2]
    s[2] ^= 0xffffffffffffffff
    # linear diffusion layer
    s[0] ^= rot64(s[0], 19) ^ rot64(s[0], 28)
    s[1] ^= rot64(s[1], 61) ^ rot64(s[1], 39)
    s[2] ^= rot64(s[2], 1) ^ rot64(s[2], 6)
    s[3] ^= rot64(s[3], 10) ^ rot64(s[3], 17)
    s[4] ^= rot64(s[4], 7) ^ rot64(s[4], 41)

# ===== Base class for ASCON AEAD =====
class AsconAead:
  # This is an abstract base class that is not fully specified.
  # The subclasses must specify the following values.
  key_len = None
  iv_len = None
  a = None
  b = None
  rate = None
  # The tag size is the same for all ASCON variants
  tagsize = 16

  def __init__(self, key: bytes):
    if self.key_len is None:
      raise ValueError("Can't instantiate base class")
    if len(key) != self.key_len:
      raise ValueError("Invalid key length")
    self.key = key

  def initialize(self, iv: bytes) -> State:
    """
    Initializes the state
    Args:
      iv: the initialization vector
    Returns:
      the initialized ASCON state
    """
    key = self.key
    desc = bytes([len(key) * 8, self.rate * 8, self.a, self.b])
    state0 = desc + bytes((20 - len(key))) + key + iv
    state = bytes_to_state(state0)
    permute(state, self.a)
    state2 = bytes_to_state(bytes(40 - len(key)) + key)
    return [s ^ t for s, t in zip(state, state2)]

  def pad(self, b: bytes) -> bytes:
    pad_len = -(len(b) + 1) % self.rate
    return b + b'\x80' + bytes(pad_len)

  def process_aad(self, state: State, aad: bytes) -> None:
    """
    Processing additional data
    Args:
      state: Ascon state, this state is updated
      aad: the additional data
    """
    rate = self.rate
    if len(aad) > 0:
      padded = self.pad(aad)
      for i in range(0, len(padded), rate):
        state[0] ^= bytes_to_int(padded[i:i + 8])
        if rate == 16:
          state[1] ^= bytes_to_int(padded[i + 8:i + 16])
        permute(state, self.b)
    state[4] ^= 1

  def process_plaintext(self, state: State, plaintext: bytes) -> bytes:
    """Ascon plaintext processing

    Args:
      state: the state, this state is updated
      plaintext: the plaintext

    Returns:
      the ciphertext
    """
    rate = self.rate
    padded = self.pad(plaintext)

    # first t-1 blocks
    ciphertext = bytearray()
    if rate == 8:
      for i in range(0, len(padded) - rate, rate):
        state[0] ^= bytes_to_int(padded[i:i + 8])
        ciphertext += int_to_bytes(state[0], 8)
        permute(state, self.b)
      state[0] ^= bytes_to_int(padded[-8:])
      last_block = int_to_bytes(state[0], 8)
      ciphertext += last_block[:len(plaintext) % rate]
    elif rate == 16:
      for i in range(0, len(padded) - rate, rate):
        state[0] ^= bytes_to_int(padded[i:i + 8])
        state[1] ^= bytes_to_int(padded[i + 8:i + 16])
        ciphertext += int_to_bytes(state[0], 8) + int_to_bytes(state[1], 8)
        permute(state, self.b)
      state[0] ^= bytes_to_int(padded[-16:-8])
      state[1] ^= bytes_to_int(padded[-8:])
      last_block = int_to_bytes(state[0], 8) + int_to_bytes(state[1], 8)
      ciphertext += last_block[:len(plaintext) % rate]
    else:
      raise ValueError("unknown rate")
    return bytes(ciphertext)


  def process_ciphertext(self, state: State, ciphertext: bytes) -> bytes:
    """ Processes ciphertext.

    Args:
      state: the state of Ascon, this state is updated
      ciphertext: the ciphertext

    Returns:
      the plaintext
    """
    rate = self.rate
    if rate not in (8, 16):
      raise ValueError("Unsupported rate")
    last_block_size = len(ciphertext) % rate
    padded = ciphertext + bytes(rate - last_block_size)

    # first t-1 blocks
    plaintext = bytearray()
    last_block_bits = last_block_size % 8 * 8  # bits in last integer
    padding = 1 << (63 - last_block_bits)
    mask = 2 * padding - 1
    if rate == 8:
      for i in range(0, len(padded) - rate, rate):
        c0 = bytes_to_int(padded[i:i + 8])
        plaintext += int_to_bytes(state[0] ^ c0, 8)
        state[0] = c0
        permute(state, self.b)
      c0 = bytes_to_int(padded[-8:])
      last_block = int_to_bytes(c0 ^ state[0], 8)
      state[0] = c0 ^ padding ^ (state[0] & mask)
      plaintext += last_block[:last_block_size]
    elif rate == 16:
      for i in range(0, len(padded) - rate, rate):
        c0 = bytes_to_int(padded[i:i + 8])
        c1 = bytes_to_int(padded[i + 8:i + 16])
        plaintext += int_to_bytes(state[0] ^ c0, 8)
        plaintext += int_to_bytes(state[1] ^ c1, 8)
        state[0] = c0
        state[1] = c1
        permute(state, self.b)
      c0 = bytes_to_int(padded[-16:-8])
      c1 = bytes_to_int(padded[-8:])
      last_block = int_to_bytes(state[0] ^ c0, 8) + int_to_bytes(
          state[1] ^ c1, 8)
      if last_block_size < 8:
        state[0] = c0 ^ padding ^ (state[0] & mask)
      else:
        state[0] = c0
        state[1] = c1 ^ padding ^ (state[1] & mask)
      plaintext += last_block[:last_block_size]
    else:
      raise ValueError("unknown rate")
    return bytes(plaintext)


  def encrypt(self, iv: bytes, aad: bytes, pt: bytes) -> tuple[bytes, bytes]:
    """Ascon encryption.

    Args:
      iv: the initialization vector
      aad: additional authenticated data
      pt: the plaintext
    Returns:
      the ciphertext and the tag
    """
    state = self.initialize(iv)
    self.process_aad(state, aad)
    ciphertext = self.process_plaintext(state, pt)
    tag = self.finalize(state)
    return ciphertext, tag

  def decrypt(self, iv: bytes, aad: bytes, ct: bytes, tag: bytes) -> bytes:
    """Ascon decryption.

    Args:
      iv: the initialization vector
      aad: additional authenticated data
      ct: the ciphertext
      tag: the tag

    Returns:
      the decrypted plaintext
    Raises:
      ValueError: if the tag is invalid
    """
    state = self.initialize(iv)
    self.process_aad(state, aad)
    plaintext = self.process_ciphertext(state, ct)
    expected_tag = self.finalize(state)
    if tag == expected_tag:
      return plaintext
    else:
      raise ValueError("Invalid tag")

  def finalize(self, state: State) -> bytes:
    """The finalization of Ascon
    Args:
      state : the state of Ascon, this state is updated
    Returns:
      the tag
    """
    key = self.key
    assert(len(key) in (16, 20))
    assert self.rate in (8, 16)
    offset = self.rate // 8
    state[offset + 0] ^= bytes_to_int(key[0:8])
    state[offset + 1] ^= bytes_to_int(key[8:16])
    state[offset + 2] ^= bytes_to_int(key[16:])

    permute(state, self.a)

    state[3] ^= bytes_to_int(key[-16:-8])
    state[4] ^= bytes_to_int(key[-8:])
    tag = int_to_bytes(state[3], 8) + int_to_bytes(state[4], 8)
    return tag

class Ascon128(AsconAead):
  key_len = 16
  iv_len = 16
  # rounds
  a = 12
  b = 6
  rate = 8


class Ascon128a(AsconAead):
  key_len = 16
  iv_len = 16
  a = 12
  b = 8
  rate = 16


class Ascon80pq(AsconAead):
  # The reference code also allows key length = 16.
  # Is this an error?
  key_len = 20
  iv_len = 16
  a = 12
  b = 6
  rate = 8

# ===== Hash functions =====
def ascon_hash_base(msg: bytes,
                    a: int,
                    b: int,
                    tagspec: int,
                    output_size: int = 32) -> bytes:
  """Base function for all ASCON hashes.

  Args:
    msg: the message to hash
    a: the number of rounds a
    b: the number of rounds b
    tagspec: specifies the type of the hash
    output_size: the size of the output.

  Returns:
    the hash
  """

  rate = 8
  state0 = bytes([0, rate * 8, a, a - b]) + int_to_bytes(tagspec, 4) + bytes(32)
  state = bytes_to_state(state0)
  permute(state, a)

  # processes the input
  padded = msg + b"\x80" + bytes(-(len(msg) + 1) % rate)

  for i in range(0, len(padded) - rate, rate):
    state[0] ^= bytes_to_int(padded[i:i + 8])
    permute(state, b)
  state[0] ^= bytes_to_int(padded[-8:])

  permute(state, a)
  # computes the output
  res = bytearray()
  while len(res) < output_size:
    res += int_to_bytes(state[0], 8)
    permute(state, b)
  return bytes(res[:output_size])


def ascon_hash(msg: bytes) -> bytes:
  return ascon_hash_base(msg, a=12, b=12, tagspec=256, output_size=32)


def ascon_hasha(msg: bytes) -> bytes:
  return ascon_hash_base(msg, a=12, b=8, tagspec=256, output_size=32)


def ascon_xof(msg: bytes, output_size: int = 32) -> bytes:
  return ascon_hash_base(msg, a=12, b=12, tagspec=0, output_size=output_size)


def ascon_xofa(msg: bytes, output_size: int = 32) -> bytes:
  return ascon_hash_base(msg, a=12, b=8, tagspec=0, output_size=output_size)
