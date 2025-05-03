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
import itertools

Block = bytes
State = list[Block]


def _xor(a: bytes, b:bytes) -> bytes:
  assert len(a) == len(b)
  return bytes(x ^ y for x, y in zip(a, b))

def _and(a: bytes, b:bytes) -> bytes:
  assert len(a) == len(b)
  return bytes(x & y for x, y in zip(a, b))

class Aegis128:
  const_0 = bytes.fromhex("000101020305080d1522375990e97962")
  const_1 = bytes.fromhex("db3d18556dc22ff12011314273b528dd")

  def __init__(self, key: bytes, tagsize :int = None):
    if len(key) != 16:
      raise ValueError("Invalid key length")
    self.key = key
    if tagsize not in [None, 16]:
      raise ValueError("Tag size not supported")
    self.tagsize = 16

  def state_update(self, state: State, m: Block) -> State:
    state = [
        aes_util.aes_enc(state[i - 1], state[i]) for i in range(len(state))
    ]
    state[0] = _xor(state[0], m)
    return state

  def initialize(self, iv: Block) -> State:
    k_iv = _xor(self.key, iv)
    state = [
        k_iv, self.const_1, self.const_0,
        _xor(self.key, self.const_0),
        _xor(self.key, self.const_1)
    ]
    for _ in range(5):
      state = self.state_update(state, self.key)
      state = self.state_update(state, k_iv)
    return state

  def update_aad(self, state: State, aad: bytes) -> State:
    for i in range(0, len(aad), 16):
      adi = aad[i:i+16]
      if len(adi) < 16:
        adi += bytes(16 - len(adi))
      state = self.state_update(state, adi)
    return state

  def finalize(self, state: State, ad_bits: int, msg_bits: int) -> Block:
    t = ad_bits.to_bytes(8, "little") + msg_bits.to_bytes(8, "little")
    tmp = _xor(state[3], t)
    for _ in range(7):
      state = self.state_update(state, tmp)
    tag = state[0]
    for r in state[1:5]:
      tag = _xor(tag, r)
    return tag

  def output_mask(self, state: State) -> Block:
    tmp = _and(state[2], state[3])
    tmp = _xor(state[1], tmp)
    return _xor(state[4], tmp)

  def raw_encrypt(self, state: State, msg: bytes) -> tuple[State, bytes]:
    ct_blocks = []
    for i in range(0, len(msg), 16):
      blk = msg[i:i+16]
      mask = self.output_mask(state)
      if len(blk) < 16:
        mask = mask[:len(blk)]
        p = blk + bytes(16 - len(blk))
      else:
        p = blk
      ct_blocks.append(_xor(mask, blk))
      state = self.state_update(state, p)
    return state, b"".join(ct_blocks)

  def raw_decrypt(self, state: State, ct: bytes) -> tuple[State, bytes]:
    pt_blocks = []
    for i in range(0, len(ct), 16):
      blk = ct[i:i+16]
      mask = self.output_mask(state)
      p = _xor(mask[:len(blk)], blk)
      pt_blocks.append(p)
      if len(p) < 16:
        p += bytes(16 - len(blk))
      state = self.state_update(state, p)
    return state, b"".join(pt_blocks)

  def encrypt(self, iv: Block, ad: bytes, msg: bytes) -> tuple[bytes, bytes]:
    state = self.initialize(iv)
    state = self.update_aad(state, ad)
    state, ct = self.raw_encrypt(state, msg)
    tag = self.finalize(state, len(ad) * 8, len(msg) * 8)
    return ct, tag

  def print_state(self, msg: str, state: State) -> None:
    print(msg)
    for i,s in enumerate(state):
      print("state%d  " % i, s.hex())
    print("mask", self.output_mask(state).hex())

  def encrypt_debug(self, iv: Block, ad: bytes,
                    msg: bytes) -> tuple[bytes, bytes]:
    state = self.initialize(iv)
    state = self.update_aad(state, ad)
    self.print_state("after update_aad", state)
    blk_nr = 0
    for i in range(0, len(msg), 16):
      blk = msg[i:i+16]
      blk += bytes(16 - len(blk))
      state = self.state_update(state, blk)
      self.print_state("after block %d" % blk_nr, state)
      blk_nr += 1

  def decrypt(self, iv: bytes, ad: bytes, ct: bytes, tag: bytes) -> bytes:
    state = self.initialize(iv)
    state = self.update_aad(state, ad)
    state, pt = self.raw_decrypt(state, ct)
    tag2 = self.finalize(state, len(ad) * 8, len(ct) * 8)
    if tag2 != tag:
      raise Exception('Invalid tag')
    return pt

  # ====== stuff for test vector generation and analysis.
  def message_between_states(self, before: State, after: State) -> bytes:
    """Returns message that leads from the state before to after.

    I.e. if
    msg = message_between_states(before, after)
    then
    raw_encrypt(before, message)[0] == after
    """
    blocks = 5  # number of blocks in a state
    state = [[None] * blocks for _ in range(blocks + 1)]
    state[0] = before
    state[blocks] = after
    # compute the states that do not depend on the messages.
    for i in range(1, blocks):
      for j in range(i, blocks):
        state[i][j] = aes_util.aes_enc(state[i - 1][j - 1], state[i - 1][j])
    # complete the states backwards from after
    for i in range(blocks - 1, 0, -1):
      for j in range(i - 1, -1, -1):
        state[i][j] = aes_util.inverse_aes_enc(state[i + 1][j + 1],
                                               state[i][j + 1])
    # compute the messages
    msg_blocks = [None] * blocks
    for i in range(blocks):
      t = aes_util.aes_enc(state[i][blocks - 1], state[i][0])
      msg_blocks[i] = _xor(t, state[i + 1][0])
    return b"".join(msg_blocks)


class Aegis128L:
  const_0 = bytes.fromhex("000101020305080d1522375990e97962")
  const_1 = bytes.fromhex("db3d18556dc22ff12011314273b528dd")

  def __init__(self, key: bytes, tagsize:int = 16):
    if len(key) != 16:
      raise ValueError("Invalid key length")
    self.key = key
    if tagsize not in [None, 16]:
      raise ValueError("Tag size not supported")

    self.tagsize = 16

  def state_update(self, state: State, ma: bytes, mb: bytes) -> State:
    state = [
        aes_util.aes_enc(state[i - 1], state[i]) for i in range(len(state))
    ]
    state[0] = _xor(state[0], ma)
    state[4] = _xor(state[4], mb)
    return state

  def initialize(self, iv: Block) -> State:
    k_iv = _xor(self.key, iv)
    state = [
        k_iv, self.const_1, self.const_0, self.const_1, k_iv,
        _xor(self.key, self.const_0),
        _xor(self.key, self.const_1),
        _xor(self.key, self.const_0)
    ]
    for _ in range(10):
      state = self.state_update(state, iv, self.key)
    return state

  def update_aad(self, state: State, aad: bytes) -> State:
    for i in range(0, len(aad), 32):
      adi = aad[i:i+32]
      if len(adi) < 32:
        adi += bytes(32 - len(adi))
      state = self.state_update(state, adi[:16], adi[16:])
    return state

  def finalize(self, state: State, ad_bits: int, msg_bits: int) -> bytes:
    t = ad_bits.to_bytes(8, "little") + msg_bits.to_bytes(8, "little")
    tmp = _xor(state[2], t)
    for _ in range(7):
      state = self.state_update(state, tmp, tmp)
    # https://eprint.iacr.org/2013/695.pdf computes the tag as sum over state[0] .. state[7]
    # http://competitions.cr.yp.to/round1/aegisv1.pdf computes the tag as sum over state[0] .. state[6]
    tag = state[0]
    for r in state[1:7]:
      tag = _xor(tag, r)
    return tag

  def output_mask(self, state: State) -> bytes:
    tmp = _and(state[2], state[3])
    tmp = _xor(state[1], tmp)
    tmp = _xor(state[6], tmp)
    tmp2 = _and(state[6], state[7])
    tmp2 = _xor(state[5], tmp2)
    tmp2 = _xor(state[2], tmp2)
    return tmp + tmp2

  def raw_encrypt(self, state: State, msg: bytes) -> tuple[State, bytes]:
    ct_blocks = []
    for i in range(0, len(msg), 32):
      blk = msg[i:i+32]
      mask = self.output_mask(state)
      if len(blk) < 32:
        mask = mask[:len(blk)]
        p = blk + bytes(32 - len(blk))
      else:
        p = blk
      ct_blocks.append(_xor(mask, blk))
      state = self.state_update(state, p[:16], p[16:])
    return state, b"".join(ct_blocks)

  def raw_decrypt(self, state: State, ct: bytes) -> tuple[State, bytes]:
    pt_blocks = []
    for i in range(0, len(ct), 32):
      blk = ct[i:i+32]
      mask = self.output_mask(state)
      p = _xor(mask[:len(blk)], blk)
      pt_blocks.append(p)
      if len(p) < 32:
        p += bytes(32 - len(blk))
      state = self.state_update(state, p[:16], p[16:])
    return state, b"".join(pt_blocks)

  def encrypt(self, iv: bytes, ad: bytes, msg: bytes) -> tuple[bytes, bytes]:
    state = self.initialize(iv)
    state = self.update_aad(state, ad)
    state, ct = self.raw_encrypt(state, msg)
    tag = self.finalize(state, len(ad) * 8, len(msg) * 8)
    return ct, tag

  def decrypt(self, iv: bytes, ad: bytes, ct: bytes, tag: bytes) -> bytes:
    state = self.initialize(iv)
    state = self.update_aad(state, ad)
    state, pt = self.raw_decrypt(state, ct)
    tag2 = self.finalize(state, len(ad) * 8, len(ct) * 8)
    if tag2 != tag:
      raise Exception('Invalid tag')
    return pt

  # ====== stuff for test vector generation.
  def message_between_states(self, before: State, after: State) -> bytes:
    """Returns message that leads from the state before to after.

    I.e. if
    msg = message_between_states(before, after)
    then
    raw_encrypt(before, msg)[0] == after
    """
    blocks = 8  # number of blocks in a state
    rounds = blocks // 2  # number of rounds between before and after
    state = [[None] * blocks for _ in range(rounds + 1)]
    state[0] = before
    state[rounds] = after
    # compute the states that do not depend on the messages.
    for i in range(1, rounds):
      for j in itertools.chain(range(i, rounds), range(i + rounds, blocks)):
        state[i][j] = aes_util.aes_enc(state[i - 1][j - 1], state[i - 1][j])
    # complete the states backwards from after
    for i in range(rounds - 1, 0, -1):
      for j in itertools.chain(range(i - 1, -1, -1),
                               range(i + rounds -1, rounds - 1, -1)):
        state[i][j] = aes_util.inverse_aes_enc(state[i + 1][j + 1],
                                               state[i][j + 1])
    # compute the messages
    msg_blocks = [None] * blocks
    for i in range(rounds):
      t0 = aes_util.aes_enc(state[i][blocks - 1], state[i][0])
      t1 = aes_util.aes_enc(state[i][rounds - 1], state[i][rounds])
      msg_blocks[2 * i] = _xor(t0, state[i + 1][0])
      msg_blocks[2 * i + 1] = _xor(t1, state[i + 1][rounds])
    res = b"".join(msg_blocks)
    assert self.raw_encrypt(before, res)[0] == after
    return res

class Aegis256:
  const_0 = bytes.fromhex("000101020305080d1522375990e97962")
  const_1 = bytes.fromhex("db3d18556dc22ff12011314273b528dd")

  def __init__(self, key: bytes, tagsize: int = None):
    if len(key) != 32:
      raise ValueError("Invalid key length")
    self.key = key
    if tagsize not in [None, 16]:
      raise ValueError("Tag size not supported")
    self.tagsize = 16

  def state_update(self, state: State, m: bytes) -> State:
    state = [
        aes_util.aes_enc(state[i - 1], state[i]) for i in range(len(state))
    ]
    state[0] = _xor(state[0], m)
    return state

  def initialize(self, iv: bytes) -> State:
    if len(iv) != 32:
      raise ValueError("Invalid IV length")
    k_0 = self.key[:16]
    k_1 = self.key[16:]
    iv_0 = iv[:16]
    iv_1 = iv[16:]
    state = [
        _xor(k_0, iv_0),
        _xor(k_1, iv_1), self.const_1, self.const_0,
        _xor(k_0, self.const_0),
        _xor(k_1, self.const_1)
    ]
    m4 = [k_0, k_1, _xor(k_0, iv_0), _xor(k_1, iv_1)]
    for _ in range(4):
      for m in m4:
        state = self.state_update(state, m)
    return state

  def update_aad(self, state: State, aad: bytes) -> State:
    for i in range(0, len(aad), 16):
      adi = aad[i:i+16]
      if len(adi) < 16:
        adi += bytes(16 - len(adi))
      state = self.state_update(state, adi)
    return state

  def finalize(self, state: State, ad_bits: int, msg_bits: int) -> bytes:
    t = ad_bits.to_bytes(8, 'little') + msg_bits.to_bytes(8, 'little')
    tmp = _xor(state[3], t)
    for _ in range(7):
      state = self.state_update(state, tmp)
    tag = state[0]
    for r in state[1:6]:
      tag = _xor(tag, r)
    return tag

  def output_mask(self, state: State) -> bytes:
    tmp = _and(state[2], state[3])
    tmp = _xor(state[1], tmp)
    tmp = _xor(state[4], tmp)
    return _xor(state[5], tmp)

  def raw_encrypt(self, state: State, msg: bytes) -> tuple[State, bytes]:
    ct_blocks = []
    for i in range(0, len(msg), 16):
      blk = msg[i:i+16]
      mask = self.output_mask(state)
      if len(blk) < 16:
        mask = mask[:len(blk)]
        p = blk + bytes(16 - len(blk))
      else:
        p = blk
      ct_blocks.append(_xor(mask, blk))
      state = self.state_update(state, p)
    return state, b"".join(ct_blocks)

  def raw_decrypt(self, state, ct: bytes) -> tuple[State, bytes]:
    pt_blocks = []
    for i in range(0, len(ct), 16):
      blk = ct[i:i+16]
      mask = self.output_mask(state)
      p = _xor(mask[:len(blk)], blk)
      pt_blocks.append(p)
      if len(p) < 16:
        p += bytes(16 - len(blk))
      state = self.state_update(state, p)
    return state, b"".join(pt_blocks)

  def encrypt(self, iv: bytes, ad: bytes, msg: bytes) -> tuple[bytes, bytes]:
    state = self.initialize(iv)
    state = self.update_aad(state, ad)
    state, ct = self.raw_encrypt(state, msg)
    tag = self.finalize(state, len(ad) * 8, len(msg) * 8)
    return ct, tag

  def decrypt(self, iv: bytes, ad: bytes, ct: bytes, tag: bytes) -> bytes:
    state = self.initialize(iv)
    state = self.update_aad(state, ad)
    state, pt = self.raw_decrypt(state, ct)
    tag2 = self.finalize(state, len(ad) * 8, len(ct) * 8)
    if tag2 != tag:
      raise Exception('Invalid tag')
    return pt

  # ====== stuff for test vector generation.
  def message_between_states(self, before: State, after: State) -> bytes:
    """Returns message that leads from the state before to after.

    I.e. if
    msg = message_between_states(before, after)
    then
    raw_encrypt(before, message)[0] == after
    """
    blocks = 6  # number of blocks in a state
    state = [[None] * blocks for _ in range(blocks + 1)]
    state[0] = before
    state[blocks] = after
    # compute the states that do not depend on the messages.
    for i in range(1, blocks):
      for j in range(i, blocks):
        state[i][j] = aes_util.aes_enc(state[i - 1][j - 1], state[i - 1][j])
    # complete the states backwards from after
    for i in range(blocks - 1, 0, -1):
      for j in range(i - 1, -1, -1):
        state[i][j] = aes_util.inverse_aes_enc(state[i + 1][j + 1],
                                               state[i][j + 1])
    # compute the messages
    msg_blocks = [None] * blocks
    for i in range(blocks):
      t = aes_util.aes_enc(state[i][blocks - 1], state[i][0])
      msg_blocks[i] = _xor(t, state[i + 1][0])
    return b"".join(msg_blocks)
