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

# Generates ECDSA signatures with biased k.
# Such a signature generation is insecure, since the private key can be
# derived from the signatures.
# Hence the code here must only be used for tests.

import ec_key
import ecdsa
import java_random
import os
import util
import prand
from enum import Enum
from typing import Optional

class BiasedEcdsaSigner(ecdsa.EcdsaSigner):
  @util.type_check
  def __init__(self,
               priv: ec_key.EcPrivateKey,
               verify_signatures: bool = True,
               *,
               min_k: int = None,
               max_k: int = None,
               mul_k: int = None,
               mask: int = None):
    super().__init__(priv, verify_signatures)
    self.min_k = min_k or 1
    self.max_k = max_k or self.priv.group.n
    self.mul_k = mul_k or 1
    self.mask = mask
    assert self.min_k < self.max_k
    assert self.mul_k != 0

  def get_k(self, label: Optional[bytes]=None):
    """Returns a biased k in range(self.min_k self.max_k, self.step_k)"""
    if label is None:
      label = os.urandom(16)
    m = self.max_k - self.min_k
    rand = prand.randrange(0, m, str(self.priv.s).encode('ascii'), label)
    k = (rand + self.min_k) * self.mul_k % self.priv.group.n
    if self.mask is not None:
      k &= self.mask
    return k

# Describes some variants of the U2F weakness:
# ALL_BYTES: replicates the weakness
# MOST_SIGNIFICANT_WORD: only the most significant word contains the weakness
# LEAST_SIGNIFICANT_WORD: only the least significant word contains the weakness
class U2fMode(Enum):
  ALL_BYTES = 1
  MOST_SIGNIFICANT_WORD = 2
  LEAST_SIGNIFICANT_WORD = 3

class U2fEcdsaSigner(ecdsa.EcdsaSigner):
  @util.type_check
  def __init__(self,
               priv: ec_key.EcPrivateKey,
               verify_signatures: bool = True,
               *,
               repeated_bytes: int = 4,
               mode: U2fMode = U2fMode.ALL_BYTES):
    super().__init__(priv, verify_signatures)
    self.repeated_bytes = repeated_bytes
    self.mode = mode

  def get_k(self, label: Optional[bytes]=None):
    n = self.priv.group.n
    bits = n.bit_length()
    if self.mode == U2fMode.ALL_BYTES:
      chunks = 1 + (bits - 1) // (8 * self.repeated_bytes)
      k = 0
      for b in os.urandom(chunks):
        k <<= 8 * self.repeated_bytes
        k += b
      k *= sum(256 ** i for i in range(self.repeated_bytes))
      return k % 2**bits
    elif self.mode == U2fMode.MOST_SIGNIFICANT_WORD:
      rand_bits = bits - 8 * self.repeated_bytes
      rand = int.from_bytes(os.urandom((rand_bits + 7) // 8), 'big')
      rand %= 2 ** rand_bits
      byte = os.urandom(1)
      rep = sum(256 ** i for i in range(self.repeated_bytes)) * byte[0]
      return (rep << rand_bits) + rand
    elif self.mode == U2fMode.LEAST_SIGNIFICANT_WORD:
      rand_bits = bits - 8 * self.repeated_bytes
      rand = int.from_bytes(os.urandom((rand_bits + 7) // 8), 'big')
      rand %= 2 ** rand_bits
      byte = os.urandom(1)
      rep = sum(256 ** i for i in range(self.repeated_bytes)) * byte[0]
      return (rand << (8 * self.repeated_bytes)) + rep
    else:
      raise ValueError("Unknown mode:" + str(self.mode))

class LcgEcdsaSigner(ecdsa.EcdsaSigner):
  @util.type_check
  def __init__(self,
               priv: ec_key.EcPrivateKey,
               lcg,
               *,
               verify_signatures: bool = True,
               normalize: bool = False):
    super().__init__(priv, verify_signatures, normalize=normalize)
    self.lcg = lcg

  def get_k(self, label: Optional[bytes]=None):
    self.lcg.reseed()
    n = self.priv.group.n
    bits = n.bit_length()
    while True:
      k = self.lcg.next_bits(bits)
      if 0 < k < n:
        return k


class JavaUtilRandomEcdsaSigner(ecdsa.EcdsaSigner):
  @util.type_check
  def __init__(self,
               priv: ec_key.EcPrivateKey,
               verify_signatures: bool = True,
               normalize: bool = False):
    super().__init__(priv, verify_signatures, normalize=normalize)

  def get_k(self, label: Optional[bytes]=None):
    bits = self.priv.group.n.bit_length()
    seed = int.from_bytes(os.urandom(6), 'big')
    rand = java_random.JavaRandom(seed)
    while True:
      k = rand.nextBigInteger(bits)
      if 0 < k < self.priv.group.n:
        return k

class MwcEcdsaSigner(ecdsa.EcdsaSigner):
  @util.type_check
  def __init__(self,
               priv: ec_key.EcPrivateKey,
               verify_signatures: bool = True,
               *,
               a: int,
               b: int):
    super().__init__(priv, verify_signatures)
    self.a = a
    self.b = b
    self.mod = a*b - 1

  def get_k(self, label: Optional[bytes]=None):
    bits = self.priv.group.n.bit_length()
    seed = int.from_bytes(os.urandom((self.mod.bit_length() + 72) // 8), 'big')
    c, x = divmod(seed % self.mod, self.b)
    k = 1
    while k.bit_length() < bits + 1:
      c, x = divmod(self.a * x + c, self.b)
      k = k * self.b + x
    return k % 2**bits

class HiddenSubsetSumSigner(ecdsa.EcdsaSigner):
  @util.type_check
  def __init__(self,
               priv: ec_key.EcPrivateKey,
               verify_signatures: bool = True,
               *,
               set_size: int = 40,
               normalize: bool = False):
    super().__init__(priv, verify_signatures, normalize=normalize)
    n = priv.group.n
    self.set_size = set_size
    self.weights = []
    for _ in range(set_size):
      r = int.from_bytes(os.urandom((n.bit_length() + 72) // 8), 'big')
      self.weights.append(r % n)

  def get_k(self, label: Optional[bytes]=None):
    r = int.from_bytes(os.urandom((len(self.weights) + 7) // 8), 'big')
    k = 0
    for i, w in enumerate(self.weights):
      if (r >> i) & 1: k += w
    return k % self.priv.group.n
