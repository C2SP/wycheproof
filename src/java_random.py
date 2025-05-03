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

import os
import pseudoprimes
from typing import Optional, Tuple

# This file contains some experiments that have the goal
# to recognize EC public keys where the private key has been
# generated with java.util.Random.

A = 0x5DEECE66D
A_INVERSE = 246154705703781
C = 0xB
MASK = 0xffffffffffff

class JavaRandom:
  def __init__(self, seed: Optional[int] = None):
    if seed is None:
      seed = int.from_bytes(os.urandom(6), 'big')
    self.state = (seed ^ A) & MASK

  @classmethod
  def fromState(cls, state: int) -> 'JavaRandom':
    return JavaRandom(state ^ A)

  @classmethod
  def fromOutput(cls, s0: int, s1: int) -> Optional['JavaRandom']:
    """Returns a JavaRandom where s0 and s1 are the next two outputs.

    I.e. the following holds:
    s0 = ...
    s1 = ...
    rand = JavaRandom.fromOutput(s0, s1)
    if rand is not None:
      assert rand.next() == s0
      assert rand.next() == s1
    """
    # The state of the random number generator after returning x0 is
    # l0 + eps for some 0 <= eps < 2**16.
    l0 = (s0 << 16) & MASK
    # The state of the random number generator after returning x1 is
    # l1 + delta for some 0 <= delta < 2**16.
    l1 = (s1 << 16) & MASK;
    # We have l1 + delta = (l0 + eps)*A + C (mod 2**48).
    # This allows to find an upper bound w for eps * A mod 2**48
    # by assuming delta = 2**16-1.
    w = (l1 - l0 * A + 65535 - C) & MASK;
    # The reduction eps * multiplier mod 2**48 only cuts off at most 3 bits.
    # Hence a simple search is sufficient. The maximal number of loops is 6.
    for em in range(w, A << 16, 1 << 48):
      # If the high order bits of em are guessed correctly then
      # em == eps * A + 65535 - delta.
      eps = em // A
      state0 = l0 + eps
      state1 = JavaRandom._nextState(state0)
      if state1 & 0xffffffff0000 == l1:
        res = cls.fromState(state0)
        res.back()
        return res
    return None

  def copy(self) -> 'JavaRandom':
    return JavaRandom(self.state ^ A)

  def _nextState(state: int) -> int:
    return (state * A + C) & MASK

  def next(self) -> int:
    self.state = (self.state * A + C) & MASK
    return self.state >> 16

  def step(self, n:int) -> None:
    """Steps the pseudorandom number generator n times.

    This method has complexity O(log(n)).
    Args:
      n: the number of steps
    """
    a = A
    c = C
    cycle_length = 1 << 48
    n %= cycle_length
    while n:
      if n & 1:
        self.state = (self.state * a + c) & MASK
      c = (c * (a + 1)) & MASK
      a = (a * a) & MASK
      n >>= 1

  def back(self) -> None:
    """Steps the pseudorandom number generator one step back."""
    self.state = ((self.state - C) * A_INVERSE) & MASK

  def nextBytes(self, n: int) -> bytes:
    """Simulates the method nextBytes from JavaRandom.
    Args:
      n: the number of bytes returned.

    """
    values = (n + 3) // 4
    res = bytearray(4 * values)
    for j in range(values):
      res[4*j : 4*(j+1)] = self.next().to_bytes(4, byteorder = 'little', signed=False)
    if len(res) == n:
      return bytes(res)
    else:
      return bytes(res[:n])

  def nextBigInteger(self, numBits: int):
    """Computes the same result as new BigInteger(numBits, self)

    Args:
      numBits: the size of the BigInteger returned.
    Returns:
      a BigInteger 0 < b < 2**numBits. 
    """
    res = int.from_bytes(self.nextBytes((numBits + 7) // 8), byteorder='big', signed=False)
    return res & ((1 << numBits) - 1)

  def nextProbablePrime(self, numBits: int):
    """Returns a problable prime similar to largePrime in jdk8.

    The method does not guarantee that it is the same prime.
    The only guarantee is that the result is equal or larger than
    a value x, where x was generated with nextBigInteger.

    jdk has a separate implementation for primes smaller than 95 bits.
    No attempt has been made to simulate these.

    Args:
      numBits:
        the size of the probable prime.
    Returns:
      a (probable) prime 2**(numBits-1) <= p < 2**numBits.
    """
    if numBits < 3:
      raise ValueError("not implemented")
    while True:
      p = self.nextBigInteger(numBits)
      p |= 1 << (numBits - 1)
      while not pseudoprimes.is_probable_prime(p):
        p += 1
      if p.bit_length() == numBits:
        return p

