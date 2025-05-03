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

import binascii
import gf
import os
import struct
import crc
from crc import crc32c
import util
from typing import Optional

# ===== Type hints
xmm = util.Uint128
ymm = "ymm"

uint32 = util.Uint32
uint64 = util.Uint64
uint128 = util.Uint128

# ===== Intel intrinsics

def crc32c_update(crc_in: uint32, block: int, bits: int) -> int:
  """Computes (crc ^ block) * x ^ (-bits) % crc32c.poly over GF_2[x].

  This functions can be used to describe Intel's CRC instructions
  below.

  Args:
    crc_in: an unconditioned crc
    block: a block
    bits: the size of block in bits.
  """
  assert 0 <= block < 2**bits
  h = (crc32c.poly ^ 1) >> 1
  h2b = gf.bin_exp(h, bits, crc32c.poly)
  return gf.bin_mulmod(crc_in ^ block, h2b, crc32c.poly)

def _mm_crc32_u64(crc: uint32, block: uint64) -> uint32:
  return crc32c_update(crc, block, 64)

def _mm_crc32_u32(crc: uint32, block: uint32) -> uint32:
  return crc32c_update(crc, block, 32)

def _mm_crc32_u16(crc: uint32, block: int) -> uint32:
  return crc32c_update(crc, block, 16)

def _mm_crc32_u8(crc: int, block: int) -> int:
  return crc32c_update(crc, block, 8)

def _mm_clmulqdq(src1: xmm, src2: xmm, imm: int) -> int:
  assert imm in (0x00, 0x01, 0x10, 0x11)
  if imm & 1:
    inp1 = src1 >> 64
  else:
    inp1 = src1 % 2**64
  if imm & 0x10:
    inp2 = src2 >> 64
  else:
    inp2 = src2 % 2**64
  return gf.bin_mult(inp1, inp2)

def _mm_set_epi64x(e1: uint64, e0: uint64) -> xmm:
  return (e1 << 64) ^ e0

def _mm_extract_epi64(src: xmm, imm: int) -> uint64:
  assert imm in (0,1)
  return (src >> (64 * imm)) % 2**64

def crc32c_update_shortcuts(crc: uint32, block: int, bits: int) -> uint32:
  """This is simply a number of short cuts that are possible with
  some of the input sizes"""
  assert 0 <= block < 2**bits
  if bits <= 64:
    inp = ((block ^ crc) << (64 - bits)) % 2**64
    return _mm_crc32_u64(0, inp) ^ (crc >> bits)
  else:
    print('should not happen', bits)
    return crc32c_update(crc, block, bits)

def crc32c_extend_128x(crc_in: uint32, blocks: list[xmm]) -> uint32:
  if not blocks:
    return crc_in
  blocks = blocks[:]
  blocks[0] ^= _mm_set_epi64x(0, crc_in ^ 0xffffffff)
  res = blocks[-1]
  size = len(blocks)
  for i in range(size - 1):
    exp0 = (size - 1 - i) * 128
    exp1 = (size - 1 - i) * 128 - 64
    c0 = crc.crc32c.xTo(-exp0)
    c1 = crc.crc32c.xTo(-exp1)
    const = _mm_set_epi64x(c1, c0)
    res ^= _mm_clmulqdq(const, blocks[i], 0x00)
    res ^= _mm_clmulqdq(const, blocks[i], 0x11)
  hi = _mm_extract_epi64(res, 1)
  lo = _mm_extract_epi64(res, 0)
  crc_out = _mm_crc32_u64(0, lo)
  crc_out = _mm_crc32_u64(crc_out, hi)
  return crc_out ^ 0xffffffff



def pseudo_multiply(a: uint64, b: uint32) -> uint32:
  "computes a * b * x^-64 % crc32c_poly"
  p = gf.bin_mult(a, b)
  hi, lo = divmod(p, 2**64)
  return _mm_crc32_u64(0, lo) ^ hi

def uint64_reduce(a: uint64) -> uint32:
  """computes a % crc32_poly"""
  assert 0 <= a < 2**64
  x64 = 0xa9cdda0d
  m = _mm_clmulqdq(a, x64, 0x00)
  m_hi, m_lo = divmod(m, 2**64)
  return m_hi ^ _mm_crc32_u64(0, m_lo)

# ===== GF SIV related functions =====

def crc_m128i(a: xmm) -> uint32:
  """Computes/defines the CRC of an XMM register.
  Args:
    a: the 128 bit value to compute the CRC from
  Returns:
    a * x^(-128) % crc32c_poly
  """
  a_hi = a >> 64
  a_lo = a % 2**64
  c0 = _mm_crc32_u64(0, a_lo)
  return _mm_crc32_u64(c0, a_hi)

def crc_m256i(a: ymm):
  """Computes/defines the CRC of a YMM register.
  Args:
    a: the 256 bit value to compute the CRC from
  Returns:
    a * x^(-256) % crc32c_poly
  """
  res = 0
  for i in range(4):
    a, rem = divmod(a, 2**64)
    res = _mm_crc32_u64(res, rem)
  return res

def montgomery_reduce_ref(hi: xmm, lo: xmm, poly: xmm) -> xmm:
  """Return hi + lo * x^(-128) % poly"""
  h = (poly ^ 1) >> 1
  w = gf.bin_exp(h, 128, poly)
  p = hi ^ gf.bin_mulmod(lo, w, poly)
  return p

def montgomery_reduce(hi: xmm, lo: xmm, poly: xmm) -> xmm:
  """Returns hi + lo * x^(-128), crc_out"""
  inv = gf.bin_inverse(poly, 128)
  m = gf.bin_mult(lo, inv) % 2**128
  lo ^= gf.bin_mult(m, poly)
  a, b = divmod(lo, 2**128)
  assert b == 0
  hi ^= a
  return hi

def montgomery_reduce_crc(hi: xmm, lo: xmm, poly: xmm):
  """Performs a Montgomery reduction with a CRC.

  The function computes the reduced polynomial
  (hi + lo * x^(-128)) % poly and a CRC difference crc_diff caused by
  the reduction.

  crc_diff is defined as follows:
  in = hi * x^128 + lo
  crc_in =  in * x^(-256) % crc_poly
  out = (in + m * poly) * x^(-128), for a polynomial m with
  m = in * poly^(-1) % x^128
  crc_out = out * x^(-128) % crc_poly
  crc_diff = crc_in ^ crc_out

  I.e., crc_diff is computed as
  crc_diff = crc_in ^ crc_out
           = (in * x^(-256) + out * x^(-128)) % crc_poly
           = m * poly * x^(-256) % crc_poly

  Args:
    hi: the high order 128 bits of the polynomial to reduce
    lo: the low order 128 bits of the polynomial to reduce
    poly: the lower 128 bits of the modulus. I.e. in is reduced
      modulo x^128 + poly
  Returns: the reduced input and the crc difference (as explained above).
  """
  inv = gf.bin_inverse(poly, 128)
  # m is used both for the modular reduction and
  # the CRC computation. Hence it needs to be explained what happens
  # if the computation of m is incorrect:
  #
  # Assume there is an error in the computation of m and the result is
  # m + delta instead of m. Then the question is: for which delta does the
  # false crc and the false value for out match. I.e. which delta satisfy
  # crc_in ^ crc_out' == crc_diff'?
  #
  # Claim: Assume poly and crc_poly are relatively prime. Then
  #   crc_in ^ crc_out' == crc_diff' iff delta % crc_poly == 0.
  #
  # We have crc_diff' = (m + delta) * poly * x^(-256) % crc_poly
  # Hence, crc_diff' = crc_diff + delta * poly * x^(-256) % crc_poly
  #
  # The computation of crc_out' is as follows:
  # tmp = (in + (m + delta) * poly)
  # trunc = tmp % x^128
  # out' = (tmp - trunc) * x^(-128)
  #      = (in + m*poly + delta*poly - trunc) * x^(-128)
  #      = out + (delta * poly - trunc) * x^(-128)
  #
  # 0 == in + m * poly % x^128 implies
  # trunc = delta * poly % x^128
  # We need trunc % crc_poly == 0
  # This implies delta % crc_poly == 0
  m = gf.bin_mult(lo, inv) % 2**128
  lo ^= gf.bin_mult(m, poly)
  a, b = divmod(lo, 2**128)
  assert b == 0
  out = hi ^ a
  # What we want to compute is m * poly * x^(-256) % crc_poly.
  #   diff = gf.bin_mult(m, poly)
  #   crc_diff = crc_m256i(mp)
  # This is equivalent to
  #   crc_poly = crc_m128i(poly ^ 2**128) ^ 1
  #   crc_m = crc_m128i(m)
  #   crc_diff = gf.bin_mulmod(crc_poly, crc_m, crc32c.poly)
  c0 = 0x694859ae # poly * x^(-192) % crc_poly
  c1 = 0xd0ba5bcc # poly * x^(-128) % crc_poly
  c = c0 ^ (c1 << 64)
  tmp0 = _mm_clmulqdq(c, m, 0x00)
  tmp1 = _mm_clmulqdq(c, m, 0x11)
  tmp = tmp0 ^ tmp1  # 96-bit result
  # tmp is equal to m * poly *x^(-192) % crc32c.poly
  tmp_hi, tmp_lo = divmod(tmp, 2**64)
  crc_diff = tmp_hi ^ _mm_crc32_u64(0, tmp_lo)
  return out, crc_diff

def montgomery_reduce_crc_diff(hi: xmm, lo: xmm, poly: xmm, mdiff: xmm):
  """Performs a faulty Montgomery reduction with a CRC.

  Args:
    hi: the high order 128 bits of the polynomial to reduce
    lo: the low order 128 bits of the polynomial to reduce
    poly: the lower 128 bits of the modulus. I.e. in is reduced
      modulo x^128 + poly
    mdiff: difference added to the computation of m
  Returns: a Montgomery reduction with faulty computation of m.
  """
  inv = gf.bin_inverse(poly, 128)
  m = gf.bin_mult(lo, inv) % 2**128
  # This is the error
  m ^= mdiff
  lo ^= gf.bin_mult(m, poly)
  a, b = divmod(lo, 2**128)
  out = hi ^ a
  c0 = 0x694859ae # poly * x^(-192) % crc_poly
  c1 = 0xd0ba5bcc # poly * x^(-128) % crc_poly
  c = c0 ^ (c1 << 64)
  tmp0 = _mm_clmulqdq(c, m, 0x00)
  tmp1 = _mm_clmulqdq(c, m, 0x11)
  tmp = tmp0 ^ tmp1  # 96-bit result
  tmp_hi, tmp_lo = divmod(tmp, 2**64)
  crc_diff = tmp_hi ^ _mm_crc32_u64(0, tmp_lo)
  return out, crc_diff

# ===== GCM_CRC related functions

def gcm_stream(j0: bytes, blocks: int):
  """Returns the CTR stream input for the GCM mode.
  
  I.e. GCM encrypts a plaintext by XOR it with the encryption of the stream
  ctr + 1 || ctr + 2 || ctr + 3,
  where the increment is added to the last 4 bytes of the CTR using big endian
  byte ordering.
  
  Args:
    j0: the initial counter
    blocks: the number of blocks in the stream
  """
  assert len(j0) == 16
  prefix = j0[:12]
  c = int.from_bytes(j0[12:], 'big')
  return b''.join(prefix + ((c + j) % 2**32).to_bytes(4, 'big')
                  for j in range(1, blocks + 1))

def crc32c_gcm_stream_ref(j0: bytes, blocks: int):
  return crc32c(gcm_stream(j0, blocks))

def crc32c_gcm_ctr_ref(blocks: int):
  """Same as crc32c_gcm_ctr_ref.
  
  Used for testing.
  """
  assert blocks < 2**32 - 1
  null_iv = bytes([0] * 15 + [1])
  return crc32c(gcm_stream(null_iv, blocks))

def crc_mul(x: int, y:int) -> int:
  return gf.bin_mulmod(x, y, crc32c.poly)

def gen_tables(table_size: int = 33,
               block_size: int = 16):

  def crc_ctr(ctr: int):
    # Returns an uncoditioned CRC of a CTR value
    val = ctr.to_bytes(block_size, 'big')
    return crc32c.unconditioned(val)

  block_size_in_bits = 8 * block_size

  # Precomputation
  x_to_size = [crc32c.xTo(-block_size_in_bits * 2**i) for i in range(table_size)]
  x_to_32 = crc32c.xTo(32)
  x_to_size_32 = [crc_mul(x, x_to_32) for x in x_to_size]

  # mult_m[i] = sum(x^(-block_size*j) for j in range(2**i)) % poly
  # If b is a 16 byte block, then mult_m * CRC(b) % poly == CRC(b * 2**bit).
  # TODO: Check if mult_m[i] * (x^-block_size + 1) == x_to_size[i] + 1
  mult_m = [None] * table_size
  mult_m[0] = 1
  for i in range(1, table_size):
    mult_m[i] = crc_mul(mult_m[i-1], 1 ^ x_to_size[i-1])

  crc_block = [None] * table_size
  crc_block[0] = offset_block = crc32c.zero_bits(block_size_in_bits)
  for i in range(1, table_size):
    crc_bit = crc_ctr(2**(i - 1))
    crc_mstep = crc_mul(crc_bit, mult_m[i-1])
    crc_block[i] = crc_mul(crc_block[i-1], 1 ^ x_to_size[i-1]) ^ crc_mstep

  def format_array(a):
    line_size = 4
    lines = []
    for i in range(0, len(a), line_size):
      line = ', '.join(hex(x) for x in a[i:i+line_size])
      lines.append(line)
    return '[' + ',\n    '.join(lines) + ']'

  print(f"block_size={block_size}")
  print(f"offset_block={hex(offset_block)}")
  print(f"table_size={table_size}")
  print(f"mult_m={format_array(mult_m)}")
  print(f"crc_block={format_array(crc_block)}")
  print(f"x_to_size={format_array(x_to_size)}")
  print(f"x_to_size_32={format_array(x_to_size_32)}")

# Precomputation tables for 16 byte blocks
# block_size=128
# offset_block=0x42709aea
# table_size=33
MULT_M=[0x1, 0xf20c0dff, 0xd383c030, 0x41f11289,
    0x1e0f05d2, 0x25ec57ad, 0x1518b829, 0x59875355,
    0x4ef33b43, 0x4d4b4e30, 0x889c50bb, 0xd49116f9,
    0xab663602, 0x3c2e3963, 0x2c5d07d9, 0x887cc888,
    0x29d28bec, 0xf35f6762, 0xe6c473d0, 0x7db46ed6,
    0x406490c3, 0x7818fcf6, 0x859e67e0, 0x380419f2,
    0x95237359, 0x5d44f18d, 0xb6ed052, 0x2b65b389,
    0xd10a368e, 0xc85021ae, 0xb257ad6a, 0xfca42dae,
    0xf20c0dff]

CRC_BLOCK=[0x42709aea, 0x78fab5a9, 0xf5688b02, 0xf4ab7cdc,
    0x66681720, 0x9d057d57, 0x5638fd22, 0x6027b93e,
    0xa306b5ea, 0x242b666, 0x28ecfd6a, 0x95247057,
    0x9e267532, 0xbd1f0685, 0x6331800, 0x6c2493e1,
    0xf6543284, 0x57951030, 0x7de7cffa, 0x1bc62d28,
    0x4eb902af, 0x10fcf2fc, 0x7f96b80d, 0x121ea2b9,
    0x33c645d5, 0x91881e67, 0x3d8af95a, 0x2e348c99,
    0xb3f39b21, 0x4459b5d0, 0xcbf7dcba, 0xbc3a2524,
    0x6503f088]

X_TO_SIZE=[0xf20c0dfe, 0x3da6d0cb, 0x740eef02, 0x6992cea2,
    0xdcb17aa4, 0xbd6f81f8, 0xfe314258, 0xf7506984,
    0xc2a5b65e, 0xe040e0ac, 0xc7cacead, 0x4fcdcbf,
    0x6bafcc21, 0x140441c6, 0x68175a0a, 0xe1ff3667,
    0x8b7230ec, 0x56175f20, 0xb9a3dcd0, 0xdd2d789e,
    0x44036c4a, 0x4612657d, 0x584d5569, 0xe8cd33e2,
    0x82f63b78, 0x417b1dbc, 0x105ec76f, 0xf26b8303,
    0x13a29877, 0xdd45aab8, 0x493c7d27, 0xf20c0dfe,
    0x3da6d0cb]

X_TO_SIZE_32=[0x3171d430, 0xa2158b34, 0x75bba45b, 0x7417153f,
    0x1426a815, 0xe986c148, 0xcdc220dd, 0x1acaec54,
    0x6bae74c4, 0x508c2ac8, 0x7b66d223, 0xc0381349,
    0xf902f73d, 0xf760b4e7, 0x78409f1e, 0xa70b0dc6,
    0xb2e4d22a, 0xe69aa612, 0x7dd9f837, 0xfa0e4598,
    0xa0ffe38d, 0xd7752589, 0xb6e9e7e, 0x4fd04875,
    0x80000000, 0x40000000, 0x10000000, 0x1000000,
    0x10000, 0x1, 0xdd45aab8, 0x3171d430,
    0xa2158b34]

def crc32c_12byte_nonce_ref(nonce: bytes, blocks: int):
  """Reference implementation of crc32c_12byte_nonce"""
  if blocks > 2**32 - 2:
    raise ValueError("Too many blocks for GCM")
  stream = b''.join(nonce + i.to_bytes(4, 'big') for i in range(2, blocks + 2))
  return crc32c(stream)

def crc32c_12byte_nonce(nonce: bytes, blocks: int):
  """Computes the CRC of the counter stream of GCM.
  
  Args:
    nonce: this must be a 12 byte nonce. This function does not work
      with other nonces, since the function relies on the fact that the
      CTR values in this case start at a fixed point.
      Additionally, the timing of the function depends on the inputs.
      When the nonce is 12 bytes long then the inputs are public, hence timing
      and other side channels do not leak secret information. When the nonce
      is not 12 bytes then the CTR is the output of GHASH and must be kept
      secret.
    blocks: the number of 16-byte blocks of the counter stream.
      the function computes the CRC over a given number of full blocks.
  """
  def reduce32(x: int) -> int:
    """Given a 64 bit integer computes x * x^-32 % crc32c.poly"""
    hi, lo = divmod(x, 2**32)
    return hi ^ _mm_crc32_u32(0, lo)

  def reverse_bytes(x: int) -> int:
    val = x.to_bytes(4, 'big')
    return int.from_bytes(val, 'little')

  if len(nonce) != 12:
    raise ValueError("Only implemented for 12 byte nonces")
  if blocks > 2**32 - 2:
    raise ValueError("Too many blocks for GCM")

  crc_nonce_uncond = crc32c.unconditioned(nonce)
  const1 = 0xab887f19
  assert const1 == crc_mul(crc32c(bytes([0] * 31 + [1])),
                           crc32c.xTo(256))
  const2 = 0x38923956
  assert const2 == crc32c.xTo(256) ^ crc32c.xTo(128)
  # If res was initialized to 0 then this function would compute the
  # CRC of (nonce || 0000) || (nonce || 0001) || ... || (nonce || m - 1).
  # Since CTR stream for GCM starts with nonce || 0002, we basically have to
  # cancel the first two blocks. This can be done by the initialisation
  # res = CRC32C(nonce || 0000 || nonce || 0001) * x^256 % crc.poly.
  res = const1 ^ reduce32(gf.bin_mult(crc_nonce_uncond, const2))

  # I.e. an alternative computation of res is
  # crc_unused = crc32c(nonce + bytes(4) + nonce + bytes([0, 0, 0, 1]))
  # res_ref = gf.bin_mulmod(crc_unused, crc32c.xTo(256), crc32c.poly)
  # assert res == res_ref

  m = blocks + 2
  bits = m.bit_length()
  for bit in range(bits - 1, -1, -1):
    if m & (1 << bit):
      # TODO: Why can I use both m or m-1 here?
      # (m-1) >> (bit+1) << (bit + 1) is always a 32-bit integer.
      last = reverse_bytes(((m-1) >> (bit + 1)) << (bit + 1))
      res = gf.bin_mult(res, X_TO_SIZE_32[bit])
      res ^= gf.bin_mult(crc_nonce_uncond ^ last, MULT_M[bit])
      res = reduce32(res) ^ CRC_BLOCK[bit]
  return res

def crc_ctr_diff(block_cipher, nonce: bytes, msg_size: int):
  block_size = block_cipher.block_size_in_bytes
  if block_size != 16:
    raise ValueError("Not implemented")
  if len(nonce) != 12:
    raise ValueError("Not implemented")
  pad_len = -msg_size % block_size
  blocks = (msg_size + pad_len) // block_size
  b = []
  for i in range(blocks):
    inp = nonce + (i + 2).to_bytes(4, 'big')
    out = block_cipher.encrypt_block(inp)
    if i == blocks - 1:
      out = out[:block_size-pad_len] + bytes(pad_len)
    diff = bytes(x ^ y for x, y in zip(inp, out))
    b.append(diff)
  return crc32c(b''.join(b))

def crc_stream(block_cipher, j0: bytes, msg_size: int):
  block_size = block_cipher.block_size_in_bytes
  if block_size != 16:
    raise ValueError("Not implemented")
  if len(j0) != 16:
    raise ValueError("Expecting 16 byte j0")
  pad_len = -msg_size % block_size
  blocks = (msg_size + pad_len) // block_size
  b = []
  prefix = j0[:12]
  ctr = int.from_bytes(j0[12:], 'big')
  for i in range(blocks):
    inp = prefix + ((ctr + i + 1) % 2**32).to_bytes(4, 'big')
    out = block_cipher.encrypt_block(inp)
    if i == blocks - 1:
      out = out[:block_size-pad_len]
    b.append(out)
  return crc32c(b''.join(b))

class CrcStringSplitter:
  """A simple version for a string splitter.
  
  Example:
    css = CrcSplitter(some_bytes)
    while css:
      block, crc = css.split_off_prefix(16)
      print(block.hex(), crc)
  
  Args:
    msg: the bytes to split.
    crc_msg: the CRC of msg. This CRC is verified once every byte from msg
      has been split off.
  """
  def __init__(self,
               msg: bytes,
               crc_msg: Optional[uint32] = None):
    self.msg = memoryview(msg)
    if crc_msg is None:
      crc_msg = crc32c(msg)
    self.remainder = gf.bin_mulmod(crc_msg, crc32c.xTo(8 * len(msg)),
                                   crc32c.poly)

  def split_off_prefix(self, size: int) -> (bytes, uint32):
    prefix = bytes(self.msg[:size])
    self.msg = self.msg[size:]
    crc_prefix = crc32c(prefix)
    self.remainder = gf.bin_mulmod(self.remainder,
                                   crc32c.xTo(-8 * len(prefix)),
                                   crc32c.poly)
    self.remainder ^= crc_prefix
    return prefix, crc_prefix

  def split_off_8byte_prefix(self) -> (bytes, uint32):
    if len(self.msg) < 8:
      return self.split_off_prefix(len(self.msg))
    prefix = bytes(self.msg[:8])
    self.msg = self.msg[8:]
    crc_prefix = _mm_crc32_u64(0xffffffff, int.from_bytes(prefix, 'little'))
    crc_prefix ^= 0xffffffff
    self.remainder = _mm_crc32_u64(0, self.remainder)
    self.remainder ^= crc_prefix
    return prefix, crc_prefix

  def __bool__(self):
    if self.msg:
      return True
    elif self.remainder == 0:
      return False
    else:
      raise ValueError("Invalid CRC of empty message")

# ===== Experiments
def crc32c_checked_constants(step = 64, maxn = 1024, poly2 = 2**32 + 2**16 + 1):
  poly = crc32c.poly
  init = gf.bin_mult(0xffffffff, gf.bin_exp(2, 128, poly))
  init = gf.bin_mod(init, poly)
  init = gf.bin_chrem(init, poly, 0, poly2)
  print(hex(gf.bin_mod(init, poly)))
  print('init', hex(init))
  h = poly >> 1
  for i in range(step, maxn + 1, step):
    p = gf.bin_exp(h, i, poly)
    p2 = gf.bin_chrem(p, poly, 0, poly2)
    assert gf.bin_mod(p2, poly) == p
    assert gf.bin_mod(p2, poly2) == 0
    print("x^(-%d) = %s" % (i, hex(p2)))

if __name__ == "__main__":
  gen_tables()
