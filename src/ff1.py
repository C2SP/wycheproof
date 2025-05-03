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

import util

# Implements FF1 from NIST SP 800-38G.

# This version is meant for test vector generation.
# The code may intentionally omit important checks
# so that invalid test vectors can be generated.

from aes import AES
from typing import Optional, List

# --- Type hints ---
# Numeral strings are used for plaintext and ciphertexts.
NumeralString = List[int]


def xor(a: bytes, b: bytes) -> bytes:
  assert len(a) == len(b)
  return bytes(x ^ y for x, y in zip(a, b))


def to_bytes(s: int, size: int) -> bytes:
  return s.to_bytes(size, "big")


def to_int(s: bytes) -> int:
  return int.from_bytes(s, 'big')


class Ff1:
  """Implementing FF1 as described in NIST SP 800-38G.
  
  The implementation here does not try to optimize the code.
  There are several places where such optimizations are possible:
  - The implementation converts integers to numeral string back
    and forth. This conversion is not needed.
  - The round function is implemented twice.
  """
  block_cipher = None
  # The implementation assumes that the number of rounds is even.
  rounds = 10

  def __init__(self,
               key: bytes,
               radix: int,
               minlen: Optional[int] = None,
               maxlen: Optional[int] = None,
               check_inputs: bool = True):
    # Section 5.1
    if not (2 <= radix <= 2**16):
      raise ValueError("invalid radix")
    self.cipher = self.block_cipher(key)
    self.radix = radix
    self.check_inputs = check_inputs
    if minlen is None:
      self.minlen = 2
      while radix ** self.minlen < 100:
        self.minlen += 1
    else:
      if minlen < 2 or radix ** minlen < 100:
        raise ValueError("Invalid minlen")
      self.minlen = minlen
    self.maxlen = maxlen or 2 ** 32
    if self.minlen > self.maxlen:
      raise ValueError("minlen must not be larger than maxlen")

  def block_size(self) -> int:
    """Returns the block size of the underlying cipher.

    Returns:
      the block size in bytes
    """
    return self.cipher.block_size_in_bytes

  def num(self, a: NumeralString) -> int:
    """Converts a numeral string to an int.

    This is Algorithm 1, page 17.
    The conversion uses bigendian order. Hence if
    self.radix=10 then num([1,2,3]) == 123

    Args:
      a: a numeral string (e.g. [1, 2, 3])

    Returns:
      the numeral string converted to an integer.
    """
    x = 0
    for v in a:
      x = x * self.radix + v
    return x

  def num_str(self, x: int, n: int) -> NumeralString:
    """Converts an integer into a numeral string.

    This is Algorithm 3, page 17.
    The conversion uses bigendian order. Hence if
    self.radix=10, then num_str(123, 4) = [0, 1, 2, 3].

    Args:
      x: an integer to convert to a numeral string
      n: the length of the result

    Returns:
      the corresponding numeral string
    """
    res = [None] * n
    for i in range(n):
      x, rem = divmod(x, self.radix)
      res[n - 1 - i] = rem
    assert x == 0
    return res

  def prf(self, x: bytes)-> bytes:
    """The pseudorandom function.

    Described by Algorithm 6 on page 17.

    Args:
      x: the input to the pseudorandom function. The size of the input must be a
        multiple of the block size of the underlying cipher.

    Returns:
      a pseudorandom output.
    """
    block_size = self.block_size()
    assert len(x) % block_size == 0
    y = bytes(block_size)
    for i in range(0, len(x), block_size):
      y = self.cipher.encrypt_block(xor(y, x[i:i+block_size]))
    return y

  def get_sizes(self, n: int) -> tuple[int, int, int, int]:
    """Returns the values u, v, d and b for an input of size n.

    Args:
      n: the number of digits of the input
    """
    u = n // 2
    v = n - u
    b = ((self.radix ** v - 1).bit_length() + 7) // 8
    d = 4 * ((b + 3) // 4) + 4
    return (u, v, b, d)

  @classmethod
  def sizes_for_radix(cls, radix: int, n: int) -> tuple[int, int, int, int]:
    """Returns the values u, v, d and b for an input of size n and radix.

    This method is identical to get_sizes, with the exception that it is
    a class method and takes the radix as additional input.

    Args:
      radix: the radix n : the size of the input
    """
    u = n // 2
    v = n - u
    b = ((radix ** v - 1).bit_length() + 7) // 8
    d = 4 * ((b + 3) // 4) + 4
    return (u, v, b, d)

  def get_P(self, u: int, n: int, t: int) -> bytes:
    """Computes the value P.

    This is Step 5 of Algorithm 7.
    Args:
      u: the size of the left input half
      n: the size of the input
      t: the size of the tweak

    Returns:
      the value P
    """
    return (bytes([1, 2, 1]) + to_bytes(self.radix, 3)
        + bytes([self.rounds, u % 256]) + to_bytes(n, 4) + to_bytes(t, 4))

  def round_function(self, r: int, num_b: int, tweak: bytes, n: int) -> int:
    """Returns the value y for round r.
    
    Args:
      r: the round number
      num_b: the value num(B)
      tweak: the tweak
      n: the length of plaintext and ciphertex
    """
    u, v, b, d = self.get_sizes(n)
    t = len(tweak)
    P = self.get_P(u, n, t)
    padded_tweak = tweak + bytes((-t - b - 1) % self.block_size())
    Q = padded_tweak + bytes([r]) + to_bytes(num_b, b)
    R = self.prf(P + Q)
    S = R
    for j in range(1, 1 + (d - 1) // self.block_size()):
      block = xor(R, to_bytes(j, self.block_size()))
      S += self.cipher.encrypt_block(block)
    assert len(S) >= d
    return to_int(S[:d])

  def check_input(self, msg: NumeralString):
    if not self.check_inputs:
      return
    if not self.minlen <= len(msg) <= self.maxlen:
      raise ValueError("Invalid message size")
    if not all(0 <= b < self.radix for b in msg):
      raise ValueError("Invalid element in input")

  def encrypt(self, tweak: bytes, pt: NumeralString) -> NumeralString:
    """Encrypts a numeral string.

    Args:
      tweak: the tweak
      pt: the plaintext as a numeral string.

    Returns:
      the ciphertext as a numeral string
    """
    self.check_input(pt)
    n = len(pt)
    u = n // 2
    v = n - u
    num_a = self.num(pt[:u])
    num_b = self.num(pt[u:])
    for r in range(self.rounds):
      y = self.round_function(r, num_b, tweak, n)
      m = (u, v)[r % 2]
      num_a, num_b = num_b, (num_a + y) % self.radix ** m
    return self.num_str(num_a, u) + self.num_str(num_b, v)

  def decrypt(self, tweak: bytes, ct: NumeralString) -> NumeralString:
    """Decrypts a ciphertext.

    Args:
      tweak: the tweak
      ct: the ciphertext as a numeral string

    Returns:
      the plaintext
    """
    self.check_input(ct)
    n = len(ct)
    u = n // 2
    v = n - u
    num_a = self.num(ct[:u])
    num_b = self.num(ct[u:])
    for r in range(self.rounds - 1, -1, -1):
      y = self.round_function(r, num_a, tweak, n)
      m = (u, v)[r % 2]
      num_a, num_b = (num_b - y) % self.radix ** m, num_a
    return self.num_str(num_a, u) + self.num_str(num_b, v)

  # ===== Methods for test vector generation =====

  def states(
      self, tweak: bytes,
      pt: NumeralString) -> list[tuple[int, int, Optional[int], Optional[int]]]:
    """Returns a list of states for each round during the encryption.
    
    Args:
      tweak: the tweak
      pt: the plaintext
    Returns:
      a list where the i-th element contains the values
      (num_a, num_b, num_c, y) for round i during encryption.
      The size fo the result is self.rounds+1, where the last
      element is (num_a, num_b, None, None) and num_a, num_b is the
      ciphertext.
    """
    n = len(pt)
    u = n // 2
    v = n - u
    num_a = self.num(pt[:u])
    num_b = self.num(pt[u:])
    res = []
    for r in range(self.rounds):
      y = self.round_function(r, num_b, tweak, n)
      m = (u, v)[r % 2]
      num_c = (num_a + y) % self.radix ** m
      res.append((num_a, num_b, num_c, y))
      num_a, num_b = num_b, num_c
    res.append((num_a, num_b, None, None))
    return res

  @util.type_check
  def invert_round_function(self,
                            y: int,
                            n: int,
                            tweak_prefix: bytes,
                            random_block: bytes = None
                           ) -> tuple[int, int, bytes]:
    """Inverts a round function.
    
    Finds values (r, num_b, tweak), such that
    self.round_function(r, num_b, tweak, n) == y and tweak starts with
    tweak_prefix. r and num_b may be out of range.
    """
    block_size = self.block_size()
    if len(tweak_prefix) % block_size != 0:
      raise ValueError("tweak_prefix must be a multiple of the block size.")
    u, v, b, d = self.get_sizes(n)
    # Choose the length of the tweak such that there is no padding
    # I.e., -t - b - 1 % self.block_size() == 0
    t0 = (-b - 1) % block_size
    t = t0 + len(tweak_prefix)
    # Only d <= block_size is implemented here.
    if d > block_size:
      raise ValueError("Not implemented " + str(d))
    R = to_bytes(y, d)
    P = self.get_P(u, n, t)
    x = P + tweak_prefix
    c = bytes(block_size)
    for i in range(0, len(x), block_size):
      c = self.cipher.encrypt_block(xor(c, x[i:i+block_size]))

    if d < block_size:
      R += random_block[:block_size - d]
    Q = xor(c, self.cipher.decrypt_block(R))
    assert self.prf(x + Q) == R
    tweak = tweak_prefix + Q[:t0]
    r = Q[t0]
    num_b = to_int(Q[t0 + 1:])
    return r, num_b, tweak

  def pt_with_state(self,
                    tweak: bytes,
                    k: int,
                    A: NumeralString,
                    B: NumeralString) -> NumeralString:
    """Returns a plaintext such that (A, B) is the state after k rounds.
    
    This function is used to generate test vectors with edge cases
    for the internal state."""
    n = len(A + B)
    u = n // 2
    v = n - u
    if k % 2 == 0:
      assert len(A) == u
      assert len(B) == v
    else:
      assert len(A) == v
      assert len(B) == u
    num_a = self.num(A)
    num_b = self.num(B)
    for r in range(k - 1, -1, -1):
      y = self.round_function(r, num_a, tweak, n)
      m = (u, v)[r % 2]
      num_a, num_b = (num_b - y) % self.radix ** m, num_a
    return self.num_str(num_a, u) + self.num_str(num_b, v)

class AesFf1(Ff1):
  block_cipher = AES
  name = 'AES-FF1'

# FF1 with other block ciphers
# A Format-preserving encryption FF1, FF3-1
# Using Lightweight Block Ciphers LEA and, SPECK
# https://dl.acm.org/doi/pdf/10.1145/3341105.3373953
