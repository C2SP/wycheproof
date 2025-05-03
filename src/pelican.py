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

import aes_util

# Implement Pelican 2.0.
# Described in in the paper
# "The Pelican MAC 2.0"
# by Joan Daemen and Vincent Rijmen,
# eprint.iacr.org/2005/088.pdf
#
# Goals and state:
# ================
# The main goal is to evaluate the security of the construction,
# since some claims came up in a comparison. The state is unclear:
# The paper leaves a few implementation details open.
# Pelican can not use the AESNI pipeline of Intel processors and
# hence is not optimal for such CPUs.
#
# Other papers:
# =============
# "Area optimized architectures & implementations of 
#  the Pelican Mac function", Sklavos and Efstathiou,
#  ICTTA 06.
# (Confirms some of the choices made below).
#
# eprint.iacr.com/2009/005.pdf
# Describes an attack that requires 2^85 chosen messages.
#  
# Other implementations:
# ======================
# The only implementation that I found is
# github.com/jedisc1/pelican-mac
# This implementation adds round keys in places where the paper
# does not use round keys, (and which would destroy the security
# claims made in the paper).

def _xor(a: bytes, b:bytes) -> bytes:
  return bytes(x^y for x, y in zip(a, b))

class Pelican:
  def __init__(self, key: bytes, tag_size_in_bytes: int = 16):
    self.cipher = aes_util.Aes(key)
    if not 1 <= tag_size_in_bytes <= 16:
      raise ValueError("Invalid tag size")
    self.tag_size = tag_size_in_bytes

  def mac(self, msg: bytes):
    padsize = 16 - len(msg) % 16
    padded = msg + bytes([0x80]) + bytes(padsize - 1)
    iv = bytes.fromhex("00000000010100010100010001010100")
    state = self.cipher.encrypt_block(iv)
    for i in range(0, len(padded), 16):
      if i > 0:
        for j in range(4):
          state= aes_util.aes_enc(state, bytes(16))
      state = _xor(padded[i:i+16], state)
    state = self.cipher.encrypt_block(state)
    return state[:self.tag_size]

# Self generated test vectors.
# There is absolutely no guarantee that they are correct.
TV = [
  { 'key': '00000000000000000000000000000000',
    'msg': '',
    'tag': 'b2bd0a8bcb8a8b65030fbdb25bf1db3a'},
  { 'key': '000102030405060708090a0b0c0d0e0f',
    'msg': '00112233445566778899aabbccddee',
    'tag': '574d8897b15db25478091f3a93ac6f36'},
  { 'key': '000102030405060708090a0b0c0d0e0f'
           '101113131415161718191a1b1c1d1e1f',
    'msg': '00112233445566778899aabbccddeeff'
           '12871468123618461283618236148123',
    'tag': '83184dabe2548c10741401e9317c002b'},
]
  
def test():
  errors = 0
  for tv in TV:
    p = Pelican(bytes.fromhex(tv['key']))
    mac = p.mac(bytes.fromhex(tv['msg']))
    if mac.hex() != tv['tag']:
      print(tv)
      print(mac.hex())
      errors += 1
  assert errors != 1

if __name__ == "__main__":
  test()
