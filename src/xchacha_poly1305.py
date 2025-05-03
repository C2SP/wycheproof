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

import poly1305
import chacha
import util
import struct

def h_chacha20(key: bytes, nonce: bytes)-> bytes:
    """
    Implements the HChaCha20 function from Section 2.2 of
    https://datatracker.ietf.org/doc/draft-arciszewski-xchacha
    """
    assert len(key) == 32
    assert len(nonce) == 16
    state = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]
    state += chacha.bytes2int32(key)
    state += chacha.bytes2int32(nonce)
    working_state = state[:]
    for i in range(10):
      chacha.inner_block(working_state)
    L = working_state
    L2 = L[0:4] + L[12:16]
    return struct.pack("<8L", *L2)


class Xchacha20Poly1305:
  """Implements XChaCha20Poly1305 in AEAD mode.

  The difference between XChaCha20 and XChaCha20 used in the
  AEAD mode is that the former starts with a block ctr = 0,
  while the later uses block ctr 0 to derive the poly key and
  starts encrypting with the block ctr 1.

  Reference:
  https://tools.ietf.org/html/draft-irtf-cfrg-xchacha-01
  """
  tagsize = 16

  @util.type_check
  def __init__(self, key: bytes):
    self.key = key

  def key_derivation(self, nonce: bytes) -> tuple[bytes, bytes]:
    """Derives the corresponding ChaCha20_poly1305 key and the nonce."""
    assert len(nonce) == 24
    key = h_chacha20(self.key, nonce[:16])
    iv = bytes(4) + nonce[16:]
    return key, iv

  def tag(self, key: bytes, nonce: bytes, aad: bytes, ct: bytes)-> bytes:
    poly_key = chacha.chacha20_block(key, nonce, 0)[:32]
    poly_inp = aad + bytes(-len(aad) % 16)
    poly_inp += ct + bytes(-len(ct) % 16)
    poly_inp += poly1305.int_to_bytes(len(aad), 8)
    poly_inp += poly1305.int_to_bytes(len(ct), 8)
    return poly1305.poly1305(poly_key, poly_inp)

  @util.type_check
  def encrypt(self, nonce: bytes, aad: bytes, msg: bytes) -> tuple[bytes, bytes]:
    key, iv = self.key_derivation(nonce)
    ct = chacha.chacha20_encrypt(key, 1, iv, msg)
    return ct, self.tag(key, iv, aad, ct)

  @util.type_check
  def decrypt(self, nonce: bytes, aad: bytes, ct: bytes, tag: bytes)-> bytes:
    key, iv = self.key_derivation(nonce)
    t = self.tag(key, iv, aad, ct)
    if t != tag:
      raise ValueError("tag mismatch")
    return chacha.chacha20_decrypt(key, 1, iv, ct)

  def poly_key(self, nonce: bytes):
    key, iv = self.key_derivation(nonce)
    return chacha.chacha20_block(key, iv, 0)[:32]


