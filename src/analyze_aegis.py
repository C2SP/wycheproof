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

import aegis
import aes_util
import collections
import os
import time
from typing import Optional, List, Tuple

"""Implements the paper
"Under Pressure: Security of Caesar Candidates beyond their Guarantees"
by Serge Vaudenay and Damian Vizár
https://infoscience.epfl.ch/record/264823/files/2017-1147.pdf
with some minor improvements.
"""

# ===== Type hints =====
# a 16 byte block
Block = bytes

# a list of blocks, where None indicates an unknown block
Blocks = List[Optional[Block]]

# ====== utils =====
def split_blocks(m: bytes, pad: bool = False):
  if pad:
    m += bytes(-len(m) % 16)
  elif len(m) % 16 != 0:
    raise ValueError("Expecting a multiple of the block size")
  return [m[i : i + 16] for i in range(0, len(m), 16)]

# ====== ORACLES =====
# This part of the code simulates broken implementations of AEGIS.
class ChosenPlaintextOracle:
  """This is an oracle for a chosen plaintext attack under nonce reuse.

     The tests below show that the internal state of AEGIS can be recovered
     with a small number of calls.
  """

  def __init__(self, cipher):
    self.cipher = cipher
    self.queries = {}

  def num_queries(self):
    return len(self.queries)

  def get_ct(self, iv:bytes, aad:bytes, pt:bytes):
    if (iv, aad, pt) not in self.queries:
      self.queries[iv, aad, pt] = self.cipher.encrypt(iv, aad, pt)[0]
    return self.queries[iv, aad, pt]


class AsciiDecodeOracle:
  """An oracle that return ascii decode errors.

  This oracle simulates a faulty implementation of AEGIS, which does the
  following:
    - partial ciphertext is decrypted.
    - the partially decrypted plaintext is then passed into an ASCII
      decoder, which throws an exception when the bytes cannot be decoded.
    - the exception (which includes the position and the faulty byte) is
      accessible to the attacker.
  The experiments done below show that the information returned by this
  oracle is enough to leak the state of the cipher with less than 200
  chosen messages.

  An extrapolation of the experiments with this oracle is that correct
  implementations must not perform any checks on partially decrypted
  plaintext before the tag has been verified. Observable information
  from such checks (e.g. exceptions) can be used to attack AEGIS."""
  def __init__(self, cipher):
    self.cipher = cipher
    # A cache for queries made by the attacker.
    # Sometimes the code below repeats a query.
    # Such repeated calls are unnecessary and hence not counted.
    self.queries = {}

  def num_queries(self):
    """Returns the number of call made to this oracle."""
    return len(self.queries)

  def _get_partial_pt(self, iv: bytes, aad: bytes, ct: bytes) -> bytes:
    """Decryption of partial ciphertext.

    The assumption of this oracle is that the attacker does not get access to
    the partially decrypted plaintext. The assumption of the oracle is that
    the result of the partial decryption is then passed into an ASCII-decoder
    and only exceptions of this decoder are observable.

    Args:
      iv: the iv of the ciphertext to decrypt. The assumption is that the
        same IV can be used multiple times.
      aad: the aad.
      ct: partial ciphertext (i.e. without a tag)
    Returns:
      partial unauthenticated plaintext
    """
    if (iv, aad, ct) not in self.queries:
      S = self.cipher.initialize(iv)
      S = self.cipher.update_aad(S, aad)
      S, pt = self.cipher.raw_decrypt(S, ct)
      self.queries[iv, aad, ct] = pt
    return self.queries[iv, aad, ct]

  def cca(self, iv: bytes, aad: bytes, ct: bytes) -> Optional[Tuple[int, int]]:
    """Performs a chosen ciphertext attack using bytes.decode().

    This method assumes that partially decrypted plaintext pt is
    passed into bytes.decode(pt, "ascii") and that the attacker
    can learn potential exceptions.

    Returns:
      If the partially decrypted plaintext contains a byte that
      is not an ASCII character (i.e. a value >= 128) then the
      offending byte value and its position in the plaintext is
      returned. This is information gained from the UnicodeDecodeError.
      If no error occured then None is returned.
    """
    partial_pt = self._get_partial_pt(iv, aad, ct)
    try:
      partial_pt.decode("ascii")
    except UnicodeDecodeError as ex:
      # The UnicodeDecodeError thrown by python contains the full actual
      # plaintext. An implementation that made such an exception accessible to
      # a potential attacker would leak a lot of information to the attacker,
      # hence allowing an easy attack (i.e. much too easy for this experiment).
      #
      # The purpose of this implementation however is a proof of concept that
      # smaller pieces of information are sufficient. In this case this is the
      # error message alone, which leaks the first offending byte and its
      # position.
      msg = str(ex)
      parts = msg.split(" ")
      val = int(parts[5], 16)
      pos = int(parts[8][:-1])
      return val, pos

# Other oracles that might be exploitable:
# - Invalid character. E.g. assuming that 0-characters are not valid.
# - Decrypt then pipe into unzip 
#
# 

# ===== ATTACKS =====
# This part of the code implements the attacks.

# Computes a lookup table that finds potential byte values x,y
# given 
#   diff_in = x^y
#   diff_out = sbox[x]^sbox[y]
sbox_diff = collections.defaultdict(list)
for diff_in in range(256):
  for x in range(256):
    diff_out = aes_util.sbox0[x] ^ aes_util.sbox0[x ^ diff_in]
    sbox_diff[diff_in, diff_out].append(x)

def solve_aes_enc_diff(diff_in: Block, diff_out: Block):
  '''Finds inputs for aes_enc, given an input and output difference.

     Solves aes_enc(x, rk) xor aes_enc(x xor diff_in, rk) == diff_out
     where rk is an arbitrary round key.
     The output is a list of values for each of the bytes.
  '''

  # The order of shift_rows and sbox can be switched.
  # I.e., AESENC(s) can be computed as
  #   s = sbox(s)
  #   s = shift_rows(s)
  #   s = b"".join(mix_columns(s[i:i + 4]) for i in range(0, 16, 4))
  #   return _xor(s, round_key)

  # (1) diff_out does not depend on round_key. Hence round_key is not even
  #     a parameter of this function.
  #
  # (2) mix_columns is linear:
  #     mix_columns(x xor diff) = mix_columns(x) xor mix_columns(diff).
  #     Hence it is possible to find the difference before the mix_columns
  #     step.
  diff_before_mix = b''.join(aes_util.inverse_mix_columns(diff_out[i:i+4])
                             for i in range(0, len(diff_out), 4))

  # (3) shift_rows just reorders the bytes
  diff_after_sbox = aes_util.inverse_shift_rows(diff_before_mix)

  # (4) Just lookup the result for each byte
  res = [sbox_diff[inp, out] for inp, out in zip(diff_in, diff_after_sbox)]
  return res

def solve_aes_enc_diffs(diff_in: List[bytes],
                        diff_out: List[bytes],
                        max_solutions = 2**20):
  """Tries to find a 128-bit state S given a number of differentials.

  The known equations for the state S are:
    aes_enc(S, rk) ^ aes_enc(S ^ diff_in[i], rk) == diff_out[i]

  Args:
    diff_in: the input differences
    diff_out: the output differences
    max_solutions: the maximal number of solutions allowed.

  Returns:
    A list of values S that solve the known equations or None
    if no solution exists.

  Throws:
    ValueError: if there are more than max_solutions solutions.
      This can for exmaple happen if there are too many 0's in the
      differences. The typical reaction to such exceptions is to
      collect more differentials from additional chosen message or
      chosen ciphertext attacks.
  """
  sols = [set(x) for x in solve_aes_enc_diff(diff_in[0], diff_out[0])]
  for i in range(1, len(diff_in)):
    soli = solve_aes_enc_diff(diff_in[i], diff_out[i])
    sols = [x & set(y) for x, y in zip(sols, soli)]
  cnt = 1
  for s in sols:
    cnt *= len(s)
  if cnt > max_solutions:
    raise ValueError("Too many solutions:", cnt)
  elif cnt:
    L = [b'']
    for s in sols:
      L = [x + bytes([y]) for x in L for y in sorted(s)]
    return L
  else:
    return []

def xor(a: bytes, b: bytes) -> bytes:
  assert len(a) == len(b)
  return bytes(x ^ y for x, y in zip(a, b))

def _and(a: bytes, b: bytes) -> bytes:
  assert len(a) == len(b)
  return bytes(x & y for x, y in zip(a, b))


class Solver:
  """Base class for a solver that determines the states of a cipher.

  A solver has a list of states of cipher, where some of the registers
  are known and other registers are unknown (i.e. have value None).
  The solver tries to find the missing states.
  """
  def solve_state(state, masks: Blocks, pt_blocks: Blocks, i, j):
    return NotImplemented

  def solve(self, pt: bytes, ct: bytes):
    state_output = split_blocks(xor(pt, ct))
    pt_blocks = split_blocks(pt)
    return self.solve_blocks(state_output, pt_blocks)

  def solve_partial(self, pt: bytes, ct: bytes, skip_blocks: int):
    state_output = split_blocks(xor(pt, ct))
    for i in range(skip_blocks):
      state_output[i] = None
    pt_blocks = split_blocks(pt)
    return self.solve_blocks(state_output, pt_blocks)

  def solve_blocks(self, masks: Blocks, pt_blocks: Blocks):
    state = self.state
    done = False
    if self.log:
      print("----- Solve -----")
      for i, s in enumerate(state):
        for j, r in enumerate(s):
          if r is not None:
            print("Known state[%d][%d]:%s" % (i, j, r.hex()))
    while not done:
      done = True
      for i in range(len(state)):
        for j in range(len(state[i])):
          if state[i][j] is None:
            res = self.solve_state(masks, pt_blocks, i, j)
            if res is not None:
              done = False
              if self.log:
                print(res, state[i][j].hex())

class Aegis128Solver(Solver):
  def __init__(self, state, log:bool=False):
    self.state = state
    self.log = log

  def solve_state(self, output_masks: Blocks, pt_blocks: Blocks, i:int, j:int):
    """Tries to find state[i][j].
    
    Args:
      output_masks: the results of the function output_mask or None if unknown
      pt_blocks: the values passed into update (or None if unknown)
      i: index of the state to solve
      j: index of the state to
    """
    state = self.state
    if state[i][j] is not None:
      return None
    k = (j + 1) % 5
    if (i + 1 < len(state) and state[i][k] and state[i + 1][k]):
      s = state[i][k]
      if k == 0: 
        if pt_blocks[i]:
          s = xor(s, pt_blocks[i])
        else:
          s = None
      if s:
        state[i][j] = aes_util.inverse_aes_enc(state[i+1][k], s)
        return "A: Computed state[%d][%d] with inverse_aes_enc" % (i, j)
    if j == 1 and state[i][2] and state[i][3] and state[i][4] and output_masks[i]:
      t = _and(state[i][2], state[i][3])
      state[i][j] = xor(output_masks[i], xor(t, state[i][4]))
      return "B: Computed state[%d][%d] from output diff %d" % (i, j, i)
    if j == 4 and state[i][1] and state[i][2] and state[i][3] and output_masks[i]:
      t = _and(state[i][2], state[i][3])
      state[i][j] = xor(output_masks[i], xor(t, state[i][1]))
      return "C: Computed state[%d][%d] from output diff %d" % (i, j, i)
    return None

class Aegis128LSolver(Solver):
  def __init__(self, state, log:bool=False):
    self.state = state
    self.log = log

  def solve_state(self, masks: Blocks, pt_blocks: Blocks, i:int, j:int):
    """Tries to find state[i][j].

    Returns:
      A description of the rule that was used to find state[i][j] or
      None if the state is already known or could not be derived.
    """
    state = self.state
    if state[i][j] is not None:
      return None
    k = (j + 1) % 8
    if (i+1 < len(state) and state[i][k] and state[i+1][k]):
      s0 = state[i][k]
      s = None
      if k == 0:
        if pt_blocks[2 * i]:
          s = xor(s0, pt_blocks[2 * i])
      elif k == 4:
        if pt_blocks[2 * i + 1]:
          s = xor(s0, pt_blocks[2 * i + 1])
      else:
        s = s0
      if s:
        state[i][j] = aes_util.inverse_aes_enc(state[i+1][k], s)
        return "A: Computed state[%d][%d] with inverse_aes_enc" % (i, j)
    if j == 1 and state[i][2] and state[i][3] and state[i][6] and masks[2 * i]:
      t = _and(state[i][2], state[i][3])
      state[i][j] = xor(masks[2 * i], xor(t, state[i][6]))
      return "B: Computed state[%d][%d] from output diff %d" % (i, j, 2 * i)
    if j == 6 and state[i][1] and state[i][2] and state[i][3] and masks[2 * i]:
      t = _and(state[i][2], state[i][3])
      state[i][j] = xor(masks[2 * i], xor(t, state[i][1]))
      return "C: Computed state[%d][%d] from output diff %d" % (i, j, 2 * i)
    if j == 2 and state[i][5] and state[i][6] and state[i][7] and masks[2 * i + 1]:
      t = _and(state[i][6], state[i][7])
      state[i][j] = xor(masks[2 * i + 1], xor(t, state[i][5]))
      return "D: Computed state[%d][%d] from output diff %d" % (i, j, 2 * i + 1)
    if j == 5 and state[i][2] and state[i][6] and state[i][7] and masks[2 * i + 1]:
      t = _and(state[i][6], state[i][7])
      state[i][j] = xor(masks[2 * i + 1], xor(t, state[i][2]))
      return "E: Computed state[%d][%d] from output diff %d" % (i, j, 2 * i + 1)
    return None

class Aegis256Solver(Solver):
  def __init__(self, state, log:bool=False):
    self.state = state
    self.log = log

  def solve_state(self, masks: Blocks, pt_blocks: Blocks, i:int, j:int):
    """Tries to find state[i][j]."""
    state = self.state
    if state[i][j] is not None:
      return None
    k = (j + 1) % 6
    if (i + 1 < len(state) and state[i][k] and state[i+1][k]):
      s = state[i][k]
      if k == 0:
        if pt_blocks[i]:
          s = xor(s, pt_blocks[i])
        else:
          s = None
      if s:
        state[i][j] = aes_util.inverse_aes_enc(state[i+1][k], s)
        return "A: Computed state[%d][%d] with inverse_aes_enc" % (i, j)
    if j == 1 and state[i][2] and state[i][3] and state[i][4] and state[i][5]:
      t = _and(state[i][2], state[i][3])
      state[i][j] = xor(masks[i], xor(t, xor(state[i][5], state[i][4])))
      return "B: Computed state[%d][%d] from output diff %d" % (i, j, i)
    if j == 4 and state[i][1] and state[i][2] and state[i][3] and state[i][5]:
      t = _and(state[i][2], state[i][3])
      state[i][j] = xor(masks[i], xor(t, xor(state[i][1], state[i][5])))
      return "C: Computed state[%d][%d] from output diff %d" % (i, j, i)
    if j == 5 and state[i][1] and state[i][2] and state[i][3] and state[i][4]:
      t = _and(state[i][2], state[i][3])
      state[i][j] = xor(masks[i], xor(t, xor(state[i][1], state[i][4])))
      return "C: Computed state[%d][%d] from output diff %d" % (i, j, i)
    return None


class CmaAegis128:
  """This class simulates a chosen message attack against AEGIS128.

  The attack assumes that it is possible to get multiple chosen
  messages encrypted with the same IV. The goal of the implementation
  is to estimate the number of messges needed to recover the state
  of AEGIS128. Recovering the state of AEGIS128 allows to encrypt
  and decrypt plaintexts and ciphertext with the same IV.

  The current implementation is typically able to recover the
  state of AEGIS128 with 9 chosen message. 
  """

  def __init__(self,
               iv: bytes,
               oracle: ChosenPlaintextOracle = None):
    self.oracle = oracle
    self.iv = iv
    assert iv is not None
    self.aad = b''
    self.msg_len = 6 * 16

  def query(self, i: int, k: int) -> Tuple[bytes, bytes]:
    """Performs a chosen plaintext query.

    The chosen plaintext differs in the i-th block.
    Each byte of the i-th block is xored with k.
    Args:
      i: the block number of the plaintext that is modified
      k: the k-th modification

    Returns:
      The chosen message and the corresponding ciphertext.
    """
    prefix = bytes(i * 16)
    postfix = bytes((5 - i) * 16)
    block_k = bytes([k] * 16)
    pt = prefix + block_k + postfix
    return pt, self.oracle.get_ct(self.iv, self.aad, pt)

  def find_block(self, i: int) -> bytes:
    """Uses a chosen message attack on block i.

    Modifying the i-th message block with a differential
    delta has the following effects:
    The differential of state[i+1][0] is delta.
    The differential of state[i+2][1] is the same
    as the differential of the (i+2)nd ciphertext block.
    Given two differentials of state[i+1][0] and 
    state[i+2][i] it is possible to solve for state[i+1][0].
 
    Args:
      i: the message block that is modified

    Returns:
      the state[i+1][0]
    """
    pt, ct = self.query(i, 0)
    diff_in = []
    diff_out = []
    k = 1
    while True:
      pt_k, ct_k = self.query(i, k)
      diff_ct = xor(ct, ct_k)
      diff_blk = diff_ct[(i+2) * 16 : (i+3) * 16]
      block_k =  bytes([k] * 16)
      diff_in.append(block_k)
      diff_out.append(diff_ct[(i+2) * 16 : (i+3) * 16])
      try:
        L = solve_aes_enc_diffs(diff_in, diff_out, 1)
      except ValueError:
        k += 1
        if k == 256:
          raise ValueError("Can't solve this")
        continue
      if len(L) == 0:
        raise ValueError("cannot solve this")
      assert len(L) == 1
      return L[0]

  def find_state_cma(self, log: bool = False):
    states = [[None] * 5 for _ in range(5)]
    for i in range(4):
      b = self.find_block(i)
      states[i+1][0] = b
    updates = None
    pt, ct = self.query(0, 0)
    s = Aegis128Solver(states)
    s.solve(pt, ct)
    return s.state[1]

class CcaAegis128:
  """This class simulates a chosen ciphertext attack against AEGIS128.
  """

  def __init__(self,
               iv: bytes,
               ascii_decode_oracle: AsciiDecodeOracle = None):
    self.ascii_decode_oracle = ascii_decode_oracle
    self.iv = iv
    assert iv is not None
    self.aad = b''
    self.msg_len = 6 * 16

  def find_pt_block_cca(self, ct: bytes, i:int) -> bytes:
    """Uses a chosen ciphertext attack to find the i-th block
    of plaintext corresponding to a given ciphertext.

    Args:
      ct: the ciphertext
      i: the number of the block
    Returns:
      the i-th plaintext block
    """
    res = [None] * 16
    ct_bytes = bytearray(ct)
    j = 0
    while j < 16:
      pos = 16 * i + j
      ex = self.ascii_decode_oracle.cca(self.iv, self.aad, bytes(ct_bytes))
      if ex is None:
        ct_bytes[pos] ^= 0x80
        continue
      val, pose = ex
      if pose < pos:
        print(val, pose, pos, i, j)
        raise ValueError("unexpected")
      if pose == pos:
        res[j] = val ^ ct_bytes[pos] ^ ct[pos]
        ct_bytes[pos] ^= 0x80
        j += 1
      else:
        ct_bytes[pos] ^= 0x80
    return bytes(res)

  def find_block_cca(self, ct: bytes, i: int) -> bytes:
    """Uses a chosen message attack on block i.

    Modifying the i-th message block with a differential
    delta has the following effects:
    The differential of state[i+1][0] is delta.
    The differential of state[i+2][1] is the same
    as the differential of the (i+2)nd ciphertext block.
    Given two differentials of state[i+1][0] and 
    state[i+2][i] it is possible to solve for state[i+1][0].
 
    Args:
      ct: the ciphertext
      i: the message block that is modified

    Returns:
      the state[i+1][0]
    """
    diff_in = []
    diff_out = []
    k = 1
    pt_0 = self.find_pt_block_cca(ct, i + 2)
    while True:
      ct_k = bytearray(ct)
      for j in range(i*16, (i+1)*16):
        ct_k[j] ^= k
      ct_k = bytes(ct_k)
      pt_k = self.find_pt_block_cca(ct_k, i + 2)
      block_k = bytes([k] * 16)
      diff_pt = xor(pt_0, pt_k)
      diff_in.append(block_k)
      diff_out.append(diff_pt)
      try:
        L = solve_aes_enc_diffs(diff_in, diff_out, 1)
      except ValueError:
        k += 1
        if k == 256:
          raise ValueError("Can't solve this")
        continue
      if len(L) == 0:
        raise ValueError("cannot solve this")
      assert len(L) == 1
      return L[0]

  def find_state_cca(self, pt: bytes, ct:bytes, log=False):
    states = [[None] * 5 for _ in range(5)]
    for i in range(4):
      blk = self.find_block_cca(ct, i)
      if log:
        print('find_block_cca', i, blk.hex())
      states[i + 1][0] = blk
    output_masks = split_blocks(xor(ct, pt))
    if log:
      for i, s in enumerate(output_masks):
        print("mask", i, s.hex())
    updates = None
    s = Aegis128Solver(states, log=log)
    s.solve(pt, ct)
    return s.state[1]

  def try_cca(self, pt: Optional[bytes], 
                    ct: bytes, log: bool = False):
    if pt is None:
      pt = b''
      for i in range(len(ct)//16):
        pt += self.find_pt_block_cca(ct, i)

    S = self.find_state_cca(pt, ct, log=log)
    if log:
      for i,x in enumerate(S):
        print(i, x.hex())
    return S


class CmaAegis128L:

  def __init__(self, iv:bytes, oracle: ChosenPlaintextOracle):
    self.iv = iv
    self.aad = b''
    self.oracle = oracle
    self.msg_len = 6 * 32

  def query(self, i, k):
    prefix = bytes(i * 32)
    postfix = bytes((5 - i) * 32)
    block_k = bytes([k] * 16)
    pt = prefix + block_k + block_k + postfix
    ct = self.oracle.get_ct(self.iv, self.aad, pt)
    return pt, ct

  def find_block(self, i: int):
    pt, ct = self.query(i, 0)
    diff_in_l = []
    diff_out_l = []
    diff_in_r = []
    diff_out_r = []
    k = 1
    while True:
      pt_k, ct_k = self.query(i, k)
      diff_ct = xor(ct, ct_k)
      diff_blk = diff_ct[(i+2)*32 : (i+3)*32]
      block_k =  bytes([k] * 16)
      diff_in_l.append(block_k)
      diff_in_r.append(block_k)
      diff_out_l.append(diff_blk[:16])
      diff_out_r.append(diff_blk[16:])
      try:
        Ll = solve_aes_enc_diffs(diff_in_l, diff_out_l, 1)
        Lr = solve_aes_enc_diffs(diff_in_r, diff_out_r, 1)
      except ValueError:
        k += 1
        if k == 256:
          raise ValueError("Can't solve this")
        continue
      if len(Ll) == 0 or len(Lr) == 0:
        raise ValueError("cannot solve this")
      assert len(Ll) == 1 and len(Lr) == 1
      return Ll[0], Lr[0]

  def find_state_cma(self, log: bool = False):
    s = [[None] * 8 for _ in range(4)]
    for i in range(3):
      l,r = self.find_block(i)
      s[i+1][0] = l
      s[i+1][4] = r
    pt, ct = self.query(0, 0)
    s = Aegis128LSolver(s, log)
    s.solve(pt, ct)
    assert None not in s.state[1]
    return s.state[1]

  def find_state_cma_partial(self, log: bool = False):
    """Simulates an attack that partially recovers the state
       while updating the AAD. Recovering this state allows to
       forge messages with different AADs."""
    required_blocks = 4
    s = [[None] * 8 for _ in range(required_blocks + 1)]
    for i in range(required_blocks):
      l,r = self.find_block(i)
      s[i+1][0] = l
      s[i+1][4] = r
    pt, ct = self.query(0, 0)
    s = Aegis128LSolver(s, log)
    s.solve_partial(pt, ct, 4)
    assert None not in s.state[1]
    return s.state[1]


class CmaAegis256:
  def __init__(self, iv:bytes, oracle: ChosenPlaintextOracle):
    self.iv = iv
    self.aad = b''
    self.oracle = oracle
    self.msg_len = 6 * 16

  def query(self, i, k):
    prefix = bytes(i * 16)
    postfix = bytes((6 - i) * 16)
    block_k = bytes([k] * 16)
    pt = prefix + block_k + postfix
    ct = self.oracle.get_ct(self.iv, self.aad, pt)
    return pt, ct

  def find_block(self, i: int):
    pt, ct = self.query(i, 0)
    diff_in = []
    diff_out = []
    k = 1
    while True:
      pt_k, ct_k = self.query(i, k)
      diff_ct = xor(ct, ct_k)
      diff_blk = diff_ct[(i+2) * 16 : (i+3) * 16]
      block_k =  bytes([k] * 16)
      diff_in.append(block_k)
      diff_out.append(diff_ct[(i+2) * 16 : (i+3) * 16])
      try:
        L = solve_aes_enc_diffs(diff_in, diff_out, 1)
      except ValueError:
        k += 1
        if k == 256:
          raise ValueError("Can't solve this")
        continue
      if len(L) == 0:
        raise ValueError("cannot solve this")
      assert len(L) == 1
      return L[0]

  def find_state_cma(self, log: bool = False):
    states = [[None] * 6 for _ in range(6)]
    for i in range(5):
      b = self.find_block(i)
      states[i+1][0] = b
    pt, ct = self.query(0, 0)
    s = Aegis256Solver(states, log)
    s.solve(pt, ct)
    return s.state[1]

# ===== TESTS =====
# This part of the code tests the attacks.

def test_cma_aegis128(log: bool = False):
  print("Testing chosen plaintext attack against AEGIS128")
  start = time.time()
  key = bytes(range(16))
  iv = bytes(range(16, 32))
  cipher = aegis.Aegis128(key)
  oracle = ChosenPlaintextOracle(cipher)
  cma = CmaAegis128(iv=iv, oracle=oracle)
  S = cma.find_state_cma(log)
  print('%d queries used' % cma.oracle.num_queries())

  S2 = cipher.initialize(iv)
  S2 = cipher.state_update(S2, bytes(16))
  assert S == S2
  print('done', time.time()-start)


def get_random_pt(msg_len: int) -> bytes:
  """Returns a random ASCII plaintext."""
  return bytes([x % 128 for x in os.urandom(msg_len)])

def test_cca_aegis128(log: bool = False):
  print("Testing chosen ciphertext attack against AEGIS128")
  start = time.time()
  key = bytes(range(16))
  iv = bytes(range(16, 32))
  cipher = aegis.Aegis128(key)
  oracle = AsciiDecodeOracle(cipher)
  cca = CcaAegis128(iv=iv, ascii_decode_oracle=oracle)
  pt = get_random_pt(cca.msg_len)
  if log:
    cipher.encrypt_debug(iv, b"", pt)
  ct, tag = cipher.encrypt(iv, b"", pt)
  S = cca.try_cca(None, ct)
  num = oracle.num_queries()
  print("%d chosen ciphertexts used" % num)
  S2 = cipher.initialize(iv)
  S2 = cipher.state_update(S2, pt[:16])
  assert S == S2
  print('done', time.time()-start)


def test_cma_aegis128L(log: bool = False):
  print("Testing chosen plaintext attack against AEGIS128L")
  start = time.time()
  key = bytes(range(16))
  iv = bytes(range(16, 32))
  cipher = aegis.Aegis128L(key)
  oracle = ChosenPlaintextOracle(cipher)
  cma = CmaAegis128L(iv=iv, oracle=oracle)
  S = cma.find_state_cma(log)
  if log:
    for s in S:
      print(s.hex())
  print("%d queries used" % oracle.num_queries())

  cipher = aegis.Aegis128L(key)
  S2 = cipher.initialize(iv)
  S2 = cipher.state_update(S2, bytes(16), bytes(16))
  assert S == S2
  print('done', time.time()-start)

def test_cma_aegis128L_partial(log: bool = False):
  print("Testing chosen plaintext attack against AEGIS128L (partial)")
  start = time.time()
  key = bytes(range(16))
  iv = bytes(range(16, 32))
  cipher = aegis.Aegis128L(key)
  oracle = ChosenPlaintextOracle(cipher)
  cma = CmaAegis128L(iv=iv, oracle=oracle)
  S = cma.find_state_cma_partial(log)
  if log:
    for s in S:
      print(s.hex())
  print("%d queries used" % oracle.num_queries())

  cipher = aegis.Aegis128L(key)
  S2 = cipher.initialize(iv)
  S2 = cipher.state_update(S2, bytes(16), bytes(16))
  assert S == S2
  print('done', time.time()-start)

def test_cma_aegis256(log: bool = False):
  print("Testing chosen plaintext attack against AEGIS256")
  start = time.time()
  key = bytes(range(32))
  iv = bytes(range(16, 48))
  cipher = aegis.Aegis256(key)
  oracle = ChosenPlaintextOracle(cipher)
  cma = CmaAegis256(iv=iv, oracle=oracle)
  S = cma.find_state_cma(log)
  if log:
    for s in S:
      print(s.hex())
  print("%d queries used" % oracle.num_queries())

  S2 = cipher.initialize(iv)
  S2 = cipher.state_update(S2, bytes(16))
  assert S == S2
  print('done', time.time()-start)

if __name__ == "__main__":
  log = False
  test_cma_aegis128L(log)
  test_cma_aegis128L_partial(True)
  test_cma_aegis128(log)
  test_cma_aegis256(log)
  test_cca_aegis128(log)
