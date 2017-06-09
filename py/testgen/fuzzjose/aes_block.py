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

# This Python implementation is derived from the Go crypto/aes/block.go,
# which carries the following notice.
#
# Copyright 2009 The Go Authors. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

# This Go implementation is derived in part from the reference
# ANSI C implementation, which carries the following notice:
#
#       rijndael-alg-fst.c
#
#       @version 3.0 (December 2000)
#
#       Optimised ANSI C code for the Rijndael cipher (now AES)
#
#       @author Vincent Rijmen <vincent.rijmen@esat.kuleuven.ac.be>
#       @author Antoon Bosselaers <antoon.bosselaers@esat.kuleuven.ac.be>
#       @author Paulo Barreto <paulo.barreto@terra.com.br>
#
#       This code is hereby placed in the public domain.
#
#       THIS SOFTWARE IS PROVIDED BY THE AUTHORS ''AS IS'' AND ANY EXPRESS
#       OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
#       WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
#       ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE
#       LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
#       CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
#       SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
#       BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
#       WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
#       OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
#       EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
# See FIPS 197 for specification, and see Daemen and Rijmen's Rijndael
# submission for implementation details.
#       http:#www.csrc.nist.gov/publications/fips/fips197/fips-197.pdf
#       http:#csrc.nist.gov/archive/aes/rijndael/Rijndael-ammended.pdf
"""AES encryption and decryption for one data block.

User should not use this module directly, instead use aes module.
"""

import aes_const


def _uint32(x):
  return x & 0xffffffff


def _uint8(x):
  return x & 0xff


def encrypt_block(xk, src, dst):
  """Encrypts one block from src into dst, using the expanded key xk."""

  s0 = _uint32(src[0] << 24) | _uint32(src[1] << 16) | _uint32(
      src[2] << 8) | _uint32(src[3])
  s1 = _uint32(src[4] << 24) | _uint32(src[5] << 16) | _uint32(
      src[6] << 8) | _uint32(src[7])
  s2 = _uint32(src[8] << 24) | _uint32(src[9] << 16) | _uint32(
      src[10] << 8) | _uint32(src[11])
  s3 = _uint32(src[12] << 24) | _uint32(src[13] << 16) | _uint32(
      src[14] << 8) | _uint32(src[15])

  # First round just XORs input with key.
  s0 ^= xk[0]
  s1 ^= xk[1]
  s2 ^= xk[2]
  s3 ^= xk[3]

  # Middle rounds shuffle using tables.
  # Number of rounds is set by length of expanded key.
  nr = len(xk) / 4 - 2  # -2: one above, one more below
  k = 4
  for _ in range(nr):
    t0 = xk[k + 0] ^ aes_const.te0[_uint8(s0 >> 24)] ^ aes_const.te1[_uint8(
        s1 >> 16)] ^ aes_const.te2[_uint8(s2 >> 8)] ^ aes_const.te3[_uint8(s3)]
    t1 = xk[k + 1] ^ aes_const.te0[_uint8(s1 >> 24)] ^ aes_const.te1[_uint8(
        s2 >> 16)] ^ aes_const.te2[_uint8(s3 >> 8)] ^ aes_const.te3[_uint8(s0)]
    t2 = xk[k + 2] ^ aes_const.te0[_uint8(s2 >> 24)] ^ aes_const.te1[_uint8(
        s3 >> 16)] ^ aes_const.te2[_uint8(s0 >> 8)] ^ aes_const.te3[_uint8(s1)]
    t3 = xk[k + 3] ^ aes_const.te0[_uint8(s3 >> 24)] ^ aes_const.te1[_uint8(
        s0 >> 16)] ^ aes_const.te2[_uint8(s1 >> 8)] ^ aes_const.te3[_uint8(s2)]
    k += 4
    s0, s1, s2, s3 = t0, t1, t2, t3

  # Last round uses s-box directly and XORs to produce output.
  s0 = _uint32(aes_const.sbox0[t0 >> 24] << 24) | _uint32(
      aes_const.sbox0[t1 >> 16 & 0xff] << 16) | _uint32(
          aes_const.sbox0[t2 >> 8 & 0xff] << 8) | _uint32(
              aes_const.sbox0[t3 & 0xff])
  s1 = _uint32(aes_const.sbox0[t1 >> 24] << 24) | _uint32(
      aes_const.sbox0[t2 >> 16 & 0xff] << 16) | _uint32(
          aes_const.sbox0[t3 >> 8 & 0xff] << 8) | _uint32(
              aes_const.sbox0[t0 & 0xff])
  s2 = _uint32(aes_const.sbox0[t2 >> 24] << 24) | _uint32(
      aes_const.sbox0[t3 >> 16 & 0xff] << 16) | _uint32(
          aes_const.sbox0[t0 >> 8 & 0xff] << 8) | _uint32(
              aes_const.sbox0[t1 & 0xff])
  s3 = _uint32(aes_const.sbox0[t3 >> 24] << 24) | _uint32(
      aes_const.sbox0[t0 >> 16 & 0xff] << 16) | _uint32(
          aes_const.sbox0[t1 >> 8 & 0xff] << 8) | _uint32(
              aes_const.sbox0[t2 & 0xff])

  s0 ^= xk[k + 0]
  s1 ^= xk[k + 1]
  s2 ^= xk[k + 2]
  s3 ^= xk[k + 3]

  dst[0], dst[1], dst[2], dst[3] = _uint8(s0 >> 24), _uint8(s0 >> 16), _uint8(
      s0 >> 8), _uint8(s0)
  dst[4], dst[5], dst[6], dst[7] = _uint8(s1 >> 24), _uint8(s1 >> 16), _uint8(
      s1 >> 8), _uint8(s1)
  dst[8], dst[9], dst[10], dst[11] = _uint8(s2 >> 24), _uint8(s2 >> 16), _uint8(
      s2 >> 8), _uint8(s2)
  dst[12], dst[13], dst[14], dst[15] = _uint8(s3 >> 24), _uint8(
      s3 >> 16), _uint8(s3 >> 8), _uint8(s3)


def decrypt_block(xk, src, dst):
  """Decrypts one block from src into dst, using the expanded key xk."""
  s0 = _uint32(src[0] << 24) | _uint32(src[1] << 16) | _uint32(
      src[2] << 8) | _uint32(src[3])
  s1 = _uint32(src[4] << 24) | _uint32(src[5] << 16) | _uint32(
      src[6] << 8) | _uint32(src[7])
  s2 = _uint32(src[8] << 24) | _uint32(src[9] << 16) | _uint32(
      src[10] << 8) | _uint32(src[11])
  s3 = _uint32(src[12] << 24) | _uint32(src[13] << 16) | _uint32(
      src[14] << 8) | _uint32(src[15])

  # First round just XORs input with key.
  s0 ^= xk[0]
  s1 ^= xk[1]
  s2 ^= xk[2]
  s3 ^= xk[3]

  # Midle rounds shuffle using tables.
  # Number of rounds is set by length of expanded key.
  nr = len(xk) / 4 - 2  # - 2: one above, one more below
  k = 4

  for _ in range(nr):
    t0 = xk[k + 0] ^ aes_const.td0[_uint8(s0 >> 24)] ^ aes_const.td1[_uint8(
        s3 >> 16)] ^ aes_const.td2[_uint8(s2 >> 8)] ^ aes_const.td3[_uint8(s1)]
    t1 = xk[k + 1] ^ aes_const.td0[_uint8(s1 >> 24)] ^ aes_const.td1[_uint8(
        s0 >> 16)] ^ aes_const.td2[_uint8(s3 >> 8)] ^ aes_const.td3[_uint8(s2)]
    t2 = xk[k + 2] ^ aes_const.td0[_uint8(s2 >> 24)] ^ aes_const.td1[_uint8(
        s1 >> 16)] ^ aes_const.td2[_uint8(s0 >> 8)] ^ aes_const.td3[_uint8(s3)]
    t3 = xk[k + 3] ^ aes_const.td0[_uint8(s3 >> 24)] ^ aes_const.td1[_uint8(
        s2 >> 16)] ^ aes_const.td2[_uint8(s1 >> 8)] ^ aes_const.td3[_uint8(s0)]
    k += 4
    s0, s1, s2, s3 = t0, t1, t2, t3

  # Last round uses s-box directly and XORs to produce output.
  s0 = _uint32(aes_const.sbox1[t0 >> 24] << 24) | _uint32(
      aes_const.sbox1[t3 >> 16 & 0xff] << 16) | _uint32(
          aes_const.sbox1[t2 >> 8 & 0xff] << 8) | _uint32(
              aes_const.sbox1[t1 & 0xff])
  s1 = _uint32(aes_const.sbox1[t1 >> 24] << 24) | _uint32(
      aes_const.sbox1[t0 >> 16 & 0xff] << 16) | _uint32(
          aes_const.sbox1[t3 >> 8 & 0xff] << 8) | _uint32(
              aes_const.sbox1[t2 & 0xff])
  s2 = _uint32(aes_const.sbox1[t2 >> 24] << 24) | _uint32(
      aes_const.sbox1[t1 >> 16 & 0xff] << 16) | _uint32(
          aes_const.sbox1[t0 >> 8 & 0xff] << 8) | _uint32(
              aes_const.sbox1[t3 & 0xff])
  s3 = _uint32(aes_const.sbox1[t3 >> 24] << 24) | _uint32(
      aes_const.sbox1[t2 >> 16 & 0xff] << 16) | _uint32(
          aes_const.sbox1[t1 >> 8 & 0xff] << 8) | _uint32(
              aes_const.sbox1[t0 & 0xff])

  s0 ^= xk[k + 0]
  s1 ^= xk[k + 1]
  s2 ^= xk[k + 2]
  s3 ^= xk[k + 3]

  dst[0], dst[1], dst[2], dst[3] = _uint8(s0 >> 24), _uint8(s0 >> 16), _uint8(
      s0 >> 8), _uint8(s0)
  dst[4], dst[5], dst[6], dst[7] = _uint8(s1 >> 24), _uint8(s1 >> 16), _uint8(
      s1 >> 8), _uint8(s1)
  dst[8], dst[9], dst[10], dst[11] = _uint8(s2 >> 24), _uint8(s2 >> 16), _uint8(
      s2 >> 8), _uint8(s2)
  dst[12], dst[13], dst[14], dst[15] = _uint8(s3 >> 24), _uint8(
      s3 >> 16), _uint8(s3 >> 8), _uint8(s3)


def subw(w):
  """Applies aes_const.sbox0 to each byte in w."""
  return _uint32(aes_const.sbox0[w >> 24] << 24) | _uint32(
      aes_const.sbox0[w >> 16 & 0xff] << 16) | _uint32(
          aes_const.sbox0[w >> 8 & 0xff] << 8) | _uint32(
              aes_const.sbox0[w & 0xff])


def rotw(w):
  """Rotates."""
  return _uint32(w << 8) | _uint32(w >> 24)


def expand_key(key, enc, dec):
  """Expands key according to FIPS-197, Figure 11."""

  # Encryption key setup
  nk = len(key) / 4
  for i in range(nk):
    enc[i] = _uint32(key[4 * i] << 24) | _uint32(
        key[4 * i + 1] << 16) | _uint32(key[4 * i + 2] << 8) | _uint32(
            key[4 * i + 3])
  for i in range(nk, len(enc)):
    t = _uint32(enc[i - 1])
    if i % nk == 0:
      t = subw(rotw(t)) ^ _uint32(aes_const.powx[i / nk - 1] << 24)
    elif nk > 6 and i % nk == 4:
      t = subw(t)
    enc[i] = enc[i - nk] ^ t

  # Derives decryption key from encryption key.
  # Reverses the 4-word round key sets from enc to produce dec.
  # All sets but the first and last get the MixColumn transform applied.
  if dec is None:
    return
  n = len(enc)
  for i in range(0, n, 4):
    ei = n - i - 4
    for j in range(4):
      x = enc[ei + j]
      if i > 0 and i + 4 < n:
        x = aes_const.td0[aes_const.sbox0[x >> 24]] ^ aes_const.td1[
            aes_const.sbox0[x >> 16 & 0xff]] ^ aes_const.td2[
                aes_const.sbox0[x >> 8 & 0xff]] ^ aes_const.td3[
                    aes_const.sbox0[x & 0xff]]
      dec[i + j] = x
