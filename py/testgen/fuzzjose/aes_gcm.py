# Copyright 2017 Google Inc. All Rights Reserved.
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
# ==============================================================================
# Run as:
#     sage -python aes_gcm.py
#
# Note(quannguyen): the current implementation is not complete, but it's enough
# for me to get started.
"""Implements Galois Counter Mode (GCM)."""

import aes
from sage.all_cmdline import *  # pylint: disable=wildcard-import
import util


class AesGcm(object):
  """Galois Counter Mode (GCM)."""

  def __init__(self, key):
    self.key = key
    self.aes = aes.Aes(self.key)
    # Authentication key
    self.h = self._bytes2gf(self.aes.encrypt_block(chr(0) * 16))

  def encrypt(self, iv, a, p):
    y0 = self.compute_y0(iv)
    cnt = self.incr(y0)
    c = self.crypt_ctr(cnt, p)
    t = self._xor_bytes(self.ghash(a, c), self.aes.encrypt_block(y0))
    return c, t

  def decrypt(self, iv, a, c, t):
    y0 = self.compute_y0(iv)
    cnt = self.incr(y0)
    computed_t = self._xor_bytes(self.ghash(a, c), self.aes.encrypt_block(y0))
    if computed_t != t:
      raise ValueError('invalid authentication tag')
    return self.crypt_ctr(cnt, c)

  def mult_h(self, x):
    res = self._bytes2gf(chr(0) * 16)
    for i in range(0, len(x), 16):
      res = (res + self._bytes2gf(x[i:i + 16])) * self.h
    return self._gf2bytes(res)

  def ghash(self, a, c):
    length = util.int2bytes(len(a) * 8, 8) + util.int2bytes(len(c) * 8, 8)
    a += chr(0) * ((16 - len(a) % 16) % 16)
    c += chr(0) * ((16 - len(c) % 16) % 16)
    return self.mult_h(a + c + length)

  def crypt_ctr(self, cnt, p):
    length = len(p)
    p += chr(0) * ((16 - length % 16) % 16)
    c = ''
    for i in range(0, len(p), 16):
      c += self._xor_bytes(self.aes.encrypt_block(cnt), p[i:i + 16])
      cnt = self.incr(cnt)
    return c[:length]

  def incr(self, cnt):
    """Increments the integer (the last 4 bytes of cnt) modulo 2^32."""
    return cnt[:12] + util.int2bytes((util.bytes2int(cnt[12:]) + 1) % 2**32, 4)

  def compute_y0(self, iv):
    if len(iv) == 12:
      return iv + (chr(0) * 3) + chr(1)
    return self.ghash('', iv)

  def _xor_bytes(self, xs, ys):
    return ''.join([chr(ord(x) ^ ord(y)) for x, y in zip(xs, ys)])

  def _invert_byte(self, b):
    """Transforms big-endian to little-endian and vice versa."""
    res = 0
    for i in range(8):
      res = res * 2 + (b >> i) % 2
    return res

  def _bytes2gf(self, bs):
    """Transforms little-endian bytes array to GF128 element."""
    # Converts little-endian bytes array to big-endian integer.
    res = 0
    for b in bs[::-1]:
      res = res * 256 + self._invert_byte(ord(b))

    return self.gf128.fetch_int(res)

  def _gf2bytes(self, element):
    """Transforms GF128 element to little-endian bytes array."""
    x = element.integer_representation()
    # Converts big-endian integer to little-endian bytes array.
    return ''.join(
        chr(self._invert_byte((x >> (i * 8)) % 256)) for i in range(16))

  # Note that Galois Field integer representation in Sagemath is big-endian
  # while GCM authentication tag computation uses little-endian representation.
  gf128 = GF(  # pylint: disable=undefined-variable
      Integer(2)**Integer(128),  # pylint: disable=undefined-variable
      'x',
      modulus=x**Integer(128) + x**Integer(7) +  # pylint: disable=undefined-variable
      x**Integer(2) + x + Integer(1))  # pylint: disable=undefined-variable
