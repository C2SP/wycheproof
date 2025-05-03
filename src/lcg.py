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

import math
import os
from typing import Optional

try:
  import gmpy
  def inv_mod(x, n):
    return gmpy.invert(x, n)
except Exception:
  def inv_mod(x, n):
    return pow(x, -1, n)

class HighOrderLcg:
  """Implements a linear congruence generator

  Args:
    coeffs: the coefficients of the recurrence relation.
    mod: the modulus
  """

  def __init__(self, coeffs: list[int], mod: int = 2**64):
    self.coeffs = coeffs
    self.mod = mod
    rand_size = mod.bit_length() // 8 + 8
    self.state = []
    for _ in coeffs:
      seed = int.from_bytes(os.urandom(rand_size), "big") % self.mod
      self.state.append(seed)

  def next(self) -> int:
    val = sum(x * y for x, y in zip(self.coeffs, self.state)) % self.mod
    self.state = self.state[1:] + [val]
    return val

### Copied from wycheproof/py3/lcg.py
### This version is newer.
class Lcg:
  """Constructs a linear congruential generator.

  Args:
    mod: the modulus
    a: the multiplier
    b: summand
    shift: bits truncated
    bits: number of bits returned
    mode:
       "little": least significant bits are generated first
       "big": most significant bits are generated first, truncated at the end
       "big2": most significant bits are generated first, truncated at the top
       None: unknown (this is used for LCGs where I only know the parameters,
             but don't have the actual implementation. For most of the tests
             it does not matter which byte order is used.)
  """
  def __init__(self,
               mod: int,
               a: int,
               b: int,
               shift: int = 0,
               bits: Optional[int] = None,
               mode: Optional[str] = None):
    self.a = a
    self.ainv = inv_mod(a, mod)
    self.b = b
    self.mod = mod
    self.shift = shift
    if bits is None:
      bits = (mod - 1).bit_length() - shift
    self.bits = bits
    if mode not in ["little", "big", "big2", None]:
      raise ValueError("Invalid mode:" + str(mode))
    self.mode = mode
    self.seed = None

  def copy(self):
    """Makes a copy of this LCG with the same seed."""
    res = Lcg(self.mod, self.a, self.b, self.shift, self.bits, self.mode)
    res.set_seed(self.seed)
    return res

  def reseed(self):
    """Randomly reseeds this LCG."""
    rand_bytes = os.urandom(self.mod.bit_length() // 8 + 8)
    self.seed = int.from_bytes(rand_bytes, "big") % self.mod

  def set_seed(self, seed: int):
    """Sets the seed of this LCG."""
    if seed is not None:
      seed %= self.mod
    self.seed = seed

  def next(self):
    """Returns the next output of this LCG."""
    if self.seed is None:
      self.reseed()
    self.seed = (self.a * self.seed + self.b) % self.mod
    return (self.seed >> self.shift) % 2 ** self.bits

  def back(self):
    """Steps this LCG back to the previous state."""
    self.seed = (self.seed - self.b) * self.ainv % self.mod

  def next_bits(self, bits: int) -> int:
    """Returns an integer in the range 0 .. 2**bits - 1.

    self.mode determines the order of the bits.

    Args:
      bits: the size of the result in bits
    """
    res = 0
    b = 0
    while b < bits:
      v = self.next()
      if self.mode == "little":
        res += v << b
      else:
        res = (res << self.bits) + v
      b += self.bits
    if self.mode == "big":
      res >>= (b - bits)
    else:
      res = res % 2**bits
    return res

  def get_next_n(self, n):
    """Returns the next n outputs of this LCG."""
    return [self.next() for _ in range(n)]

LCGS = {
    "NumericalRecipesLCG" : Lcg(mod=2**32, a=1664525, b=1013904223),
    "BorlandRand" : Lcg(mod=2**31, a=22695477, b=1, shift=16),
    "BorlandLrand" : Lcg(mod=2**31, a=22695477, b=1),
    "Glibc" : Lcg(mod=2 ** 31, a=1103515245, b=12345),
    "AnsiC" : Lcg(mod=2 ** 31, a=1103515245, b=12345, shift=16),
    "TurboPascal" : Lcg(mod=2 ** 32, a=134775813, b=1),
    "MicrosoftVisualC" : Lcg(mod=2 ** 31, a=214013, b=2531011, shift=16),
    "MicrosoftVisualBasic" : Lcg(mod=2 ** 24, a=1140671485, b=12820163),
    "RtlUniform" : Lcg(mod=2 ** 31 - 1, a=2147483629, b=2147483587, bits=31),
    "CarbonLib" : Lcg(mod=2 ** 31 - 1, a=16807, b=0, bits=3),
    "MMIX" : Lcg(mod=2 ** 64, a=6364136223846793005, b=1442695040888963407),
    "Newlib" : Lcg(mod=2 ** 64, a=6364136223846793005, b=1, shift=32),
    "VMS" : Lcg(mod=2 ** 32, a=69069, b=1),
    # java.util.random uses thes parameters too, but the byte order of the result is reversed.
    "Posix" : Lcg(mod=2 ** 48, a=25214903917, b=11, shift=16),
    "PosixRand48" : Lcg(mod=2 ** 48, a=25214903917, b=11, shift=0),
    "cc65" : Lcg(mod=2 ** 23, a=65793, b=4282663, shift=8),
    "cc65new" : Lcg(mod=2 ** 32, a=16843009, b=826366247, shift=16),
    "Randu" : Lcg(mod=2 ** 31, a=65539, b=0),
    # GmpX_Y is a LCG used by gmpy with an X bit state and Y bit output.
    # gmpy generally uses a LCG that is at least twice the size of the output.
    # E.g., calling gmpy.rand("init", 32) will select the parameters Gmpy64_32
    "Gmp32_16" : Lcg(mod=2**32, a=0x29CF535, b=1, shift=16, mode="little"),
    "Gmp34_17" : Lcg(mod=2**34, a=0xA3D73AD, b=1, shift=17, mode="little"),
    "Gmp36_18" : Lcg(mod=2**36, a=0x28F725C5, b=1, shift=18, mode="little"),
    "Gmp38_19" : Lcg(mod=2**38, a=0xA3DD5CDD, b=1, shift=19, mode="little"),
    "Gmp40_20" : Lcg(mod=2**40, a=0x28F5DA175, b=1, shift=20, mode="little"),
    "Gmp56_28" : Lcg(mod=2**56, a=0xAA7D735234C0DD, b=1, shift=28, mode="little"),
    "Gmp64_32" : Lcg(mod=2**64, a=0xBAECD515DAF0B49D, b=1, shift=32, mode="little"),
    "Gmp100_50" : Lcg(mod=2**100,
                       a=0x292787EBD3329AD7E7575E2FD,
                       b=1,
                       shift=50,
                       mode="little"),
    "Gmp128_64" : Lcg(mod=2**128,
                       a=0x48A74F367FA7B5C8ACBB36901308FA85,
                       b=1,
                       shift=64,
                       mode="little"),
    "Gmp156_78" : Lcg(mod=2**156,
                       a=0x78A7FDDDC43611B527C3F1D760F36E5D7FC7C45,
                       b=1,
                       shift=78,
                       mode="little"),
    "Gmp196_98" : Lcg(mod=2**196,
                       a=0x41BA2E104EE34C66B3520CE706A56498DE6D44721E5E24F5,
                       b=1,
                       shift=98,
                       mode="little"),
    "Gmp200_100" : Lcg(mod=2**200,
                        a=0x4E5A24C38B981EAFE84CD9D0BEC48E83911362C114F30072C5,
                        b=1,
                        shift=100,
                        mode="little"),
    "Gmp256_128" : Lcg(mod=2**256,
                        a=0xAF66BA932AAF58A071FD8F0742A99A0C76982D648509973DB802303128A14CB5,
                        b=1,
                        shift=128,
                        mode="little"),
}

def named_lcg(name: str):
  return LCGS[name].copy()

def defined_lcgs():
  for n, rng in LCGS.items():
    yield n, rng.copy()

def gmpy_rand_test():
  """This is a regression test against data generated with gmpy.rand."""
  seed = 12345
  for (name, val) in [
    ("Gmp32_16", 0xb117159d3731bf227143e620b1d91503abdc89c03f5354edec82fde5f36d02ec),
    ("Gmp40_20", 0xcd48071220ff32d2683a3590ed959bacfab11312865e20f7f0857ebd8af737a1),
    ("Gmp56_28", 0x6cb6d77bb787427e88901e8243ca5ba2e7376bece99fbfcdd2a4ab0d67b8e173),
    ("Gmp64_32", 0x73e00db9f80252f3fc5948da126c6c567d9f0ba1776f35fad0e0473b06af8aea),
    ("Gmp128_64", 0x82ad57ec080aa5634cf0e271f1a851f1613acb3dd5d1a2aa8c1adb11de6d1a11),
    ("Gmp200_100", 0xca264511020b3a814d41084c548bb28a08e7bc658f6d9b69a9fd0b921f3a33f5),
    ("Gmp256_128", 0x167c41e00e389491ca6595d26abb58fd50db22c561a8d118ec46351da4a5a302),
  ]:
    g = named_lcg(name)
    g.set_seed(seed)
    x = g.next_bits(256)
    assert x == val

if __name__ == "__main__":
  gmpy_rand_test()
