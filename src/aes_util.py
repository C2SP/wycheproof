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

"""AES encryption and decryption of a single block.

This is experimental code. It contains little of no
type checks or protection against side channel attacks or
other safety measures. The purpose of this code is for generating
test vectors only. The code exports internal functions.
This should allow to implement related ciphers such as AEGIS.
"""

import collections
import struct
import util

# Some definitions for type hinting.
uint32 = util.Uint32
uint8 = util.Uint8
class Block(metaclass=util.FixedLengthBytesMeta):
  size = 16

def _block_to_ints(b: Block) -> list[uint32]:
  """Converts a Block into 4 integers using bigendian order"""
  return struct.unpack(">IIII", b)

def _block_from_ints(v: list[uint32]) -> Block:
  """Converts 4 integers into a block using bigendian order"""
  return struct.pack(">IIII", *v)

def _xor(a: Block, b:Block) -> Block:
  return bytes(x^y for x, y in zip(a, b))

def _rot8(x: uint32) -> uint32:
  return (x >> 8) | ((x & 0xff) << 24)

_SHIFT_ROWS = tuple(5 * i % 16 for i in range(16))
def shift_rows(s: Block) -> Block:
  """The shift rows operation.
 
  Args:
    s: a block
  Returns:
    the block ater the permutation
  """
  return bytes(s[i] for i in _SHIFT_ROWS)

_INVERSE_SHIFT_ROWS = tuple(13 * i % 16 for i in range(16))
def inverse_shift_rows(s: Block) -> Block:
  """The inverse of the shift rows operation.
     I.e. x == inverse_shift_rows(shift_rows(x))
 
  Args:
    s: a block
  Returns:
    the block ater the permutation
  """
  return bytes(s[i] for i in _INVERSE_SHIFT_ROWS)

# ===== The field GF(8) uses in AES =====
# The finite field used for AES is GF(2)[x]/(_POLY(x))
_POLY = 1 << 8 | 1 << 4 | 1 << 3 | 1 << 1 | 1 << 0


def mod_poly(x: int) -> int:
  while x >= 256:
    r, x = divmod(x, 256)
    x ^= r ^ (r << 1) ^ (r << 3) ^ (r << 4)
  return x


def mul_poly(x: int, y: int) -> int:
  prod = 0
  for i in range(x.bit_length()):
    if x & (1 << i):
      prod ^= y << i
  return mod_poly(prod)


def inverse_poly(x: uint8) -> uint8:
  r = 1
  for i in range(7):
    r = mul_poly(r, x)
    r = mul_poly(r, r)
  assert r == x == 0 or mul_poly(r, x) == 1
  return r

# ===== Additional functions for the AES field. =====
def conjugate(x: uint8) -> uint8:
  """Computes the conjugate of x.

  This is a linear function."""
  for _ in range(4):
    x = mul_poly(x, x)
  return x

def norm(x: uint8) -> uint8:
  """The norm in the subfield of order 16.

  I.e. the same as x**17"""
  return mul_poly(x, conjugate(x))

def trace(x: uint8) -> uint8:
  return x ^ conjugate(x)


# ===== SBOX =====
def affine(x: uint8) -> uint8:
  """The affine function used for the Sbox"""
  w = x ^ (x << 1) ^ (x << 2) ^ (x << 3) ^ (x << 4)
  return (w % 256) ^ (w >> 8) ^ 0x63


def inverse_affine(x: uint8) -> uint8:
  """The inverse of affine"""
  w = (x << 1) ^ (x << 3) ^ (x << 6)
  return (w % 256) ^ (w >> 8) ^ 0x05


def sbox_ref(x: uint8) -> uint8:
  """The S-Box in AES as defined"""
  return affine(inverse_poly(x))


def inverse_sbox_ref(x: uint8) -> uint8:
  return inverse_poly(inverse_affine(x))

# FIPS-197 Figure 7. S-box substitution values in hexadecimal format.
sbox0 = bytes.fromhex(
    "637c777bf26b6fc53001672bfed7ab76"
    "ca82c97dfa5947f0add4a2af9ca472c0"
    "b7fd9326363ff7cc34a5e5f171d83115"
    "04c723c31896059a071280e2eb27b275"
    "09832c1a1b6e5aa0523bd6b329e32f84"
    "53d100ed20fcb15b6acbbe394a4c58cf"
    "d0efaafb434d338545f9027f503c9fa8"
    "51a3408f929d38f5bcb6da2110fff3d2"
    "cd0c13ec5f974417c4a77e3d645d1973"
    "60814fdc222a908846eeb814de5e0bdb"
    "e0323a0a4906245cc2d3ac629195e479"
    "e7c8376d8dd54ea96c56f4ea657aae08"
    "ba78252e1ca6b4c6e8dd741f4bbd8b8a"
    "703eb5664803f60e613557b986c11d9e"
    "e1f8981169d98e949b1e87e9ce5528df"
    "8ca1890dbfe6426841992d0fb054bb16")

# Inverse S-box.
sbox1 = bytes.maketrans(sbox0, bytes(range(256)))

def sbox(b:bytes)-> bytes:
  """Applies the S-box to all bytes in b."""
  return b.translate(sbox0)

def inverse_sbox(b:bytes)-> bytes:
  """Applies the inverse S-Box to all bytes in b."""
  return b.translate(sbox1)


_ROUND_CONST = bytes([mod_poly(1 << i) for i in range(16)])

# ===== MIX_COLUMNS =====
def mix_columns(b: bytes) -> bytes:
  """Applies the MixColumns step to 4 bytes."""
  if len(b) != 4:
    raise ValueError("expected 4 byte input")
  res = bytearray(4)
  for i in range(4):
    s = b[i]
    s2 = mod_poly(s << 1)
    s3 = s ^ s2
    res[i] ^= s2
    res[(i + 1) % 4] ^= s
    res[(i + 2) % 4] ^= s
    res[(i + 3) % 4] ^= s3
  return bytes(res)

def inverse_mix_columns(ba: bytes) -> bytes:
  """Applies the MixColumns step to 4 bytes."""
  if len(ba) != 4:
    raise ValueError("expected 4 byte input")
  res = bytearray(4)
  for i in range(4):
    s = ba[i]
    a = mul_poly(s, 14)
    b = mul_poly(s, 9)
    c = mul_poly(s, 13)
    d = mul_poly(s, 11)
    res[i] ^= a
    res[(i + 1) % 4] ^= b
    res[(i + 2) % 4] ^= c
    res[(i + 3) % 4] ^= d
  return bytes(res)

# ===== Generating lookup tables
# Lookup tables for fused SubBytes and MixColumns
# See https://en.wikipedia.org/wiki/Rijndael_MixColumns
te0 = [None] * 256
for i,s in enumerate(sbox0):
  t = mix_columns(bytes([s, 0, 0, 0]))
  te0[i] = struct.unpack(">I", t)[0]
te1 = [_rot8(x) for x in te0]
te2 = [_rot8(x) for x in te1]
te3 = [_rot8(x) for x in te2]

# Lookup tables for applying the inverse of SubBytes and
# MixColumns
td0 = [None] * 256
for i,s in enumerate(sbox1):
  t = inverse_mix_columns(bytes([s, 0, 0, 0]))
  td0[i] = struct.unpack(">I", t)[0]
td1 = [_rot8(x) for x in td0]
td2 = [_rot8(x) for x in td1]
td3 = [_rot8(x) for x in td2]

def print_table(tab, indent=4, elems_per_line=4):
  for i in range(0, len(tab), elems_per_line):
    print(' '*indent +
          ''.join('0x%08x, ' % x for x in tab[i:i+elems_per_line]))

# ===== Some of the AES-NI functions
def aes_enc_ref(s: Block, round_key: Block) -> Block:
  """Performs the AESENC operation.

  This is slow reference code.
  """
  s = shift_rows(s)
  s = sbox(s)
  s = b"".join(mix_columns(s[i:i + 4]) for i in range(0, 16, 4))
  return _xor(s, round_key)


def aes_enc(s: Block, round_key: Block) -> Block:
  """Performs the AESENC operation with tables."""
  t0 = (te0[s[0]] ^ te1[s[5]] ^ te2[s[10]] ^ te3[s[15]])
  t1 = (te0[s[4]] ^ te1[s[9]] ^ te2[s[14]] ^ te3[s[3]])
  t2 = (te0[s[8]] ^ te1[s[13]] ^ te2[s[2]] ^ te3[s[7]])
  t3 = (te0[s[12]] ^ te1[s[1]] ^ te2[s[6]] ^ te3[s[11]])
  s = _block_from_ints([t0, t1, t2, t3])
  return _xor(s, round_key)


def aes_dec_ref(s: Block, round_key: Block) -> Block:
  """Performs the AESDEC operation.

  This is slow reference code.
  """
  s = inverse_shift_rows(s)
  s = inverse_sbox(s)
  s = b"".join(inverse_mix_columns(s[i:i + 4]) for i in range(0, 16, 4))
  return _xor(s, round_key)


def aes_dec(s: Block, round_key: Block) -> Block:
  """Performs the AESENC operation with tables."""
  t0 = (td0[s[0]] ^ td1[s[13]] ^ td2[s[10]] ^ td3[s[7]])
  t1 = (td0[s[4]] ^ td1[s[1]] ^ td2[s[14]] ^ td3[s[11]])
  t2 = (td0[s[8]] ^ td1[s[5]] ^ td2[s[2]] ^ td3[s[15]])
  t3 = (td0[s[12]] ^ td1[s[9]] ^ td2[s[6]] ^ td3[s[3]])
  s = _block_from_ints([t0, t1, t2, t3])
  return _xor(s, round_key)


def aes_enc_last(s: Block, round_key: Block) -> Block:
  s = shift_rows(s)
  s = sbox(s)
  return _xor(s, round_key)


def aes_dec_last(s: Block, round_key: Block) -> Block:
  s = inverse_shift_rows(s)
  s = inverse_sbox(s)
  return _xor(s, round_key)

def aes_mc(s: Block) -> Block:
  """Applies the MixColumns step to a block"""
  return b"".join(mix_columns(s[i:i + 4]) for i in range(0, 16, 4))

def aes_imc_ref(s: Block) -> Block:
  """Applies the inverse MixColumns step to a block.

  This is a reference implementation."""
  return b"".join(inverse_mix_columns(s[i:i + 4]) for i in range(0, 16, 4))

def aes_imc(rk_enc: Block) -> Block:
  """Applies the inverse MixColumns step to a block.

  This is a typical implementation, using the tables."""
  rk_enc_sbox = sbox(rk_enc)
  tmp = [None] * 4
  for j in range(4):
    s = rk_enc_sbox[4 * j : 4 * j + 4]
    tmp[j] = td0[s[0]] ^ td1[s[1]] ^ td2[s[2]] ^ td3[s[3]]
  return _block_from_ints(tmp)
  
# ===== Key expansion
def subw(w: bytes) -> bytes:
  """Applies sbox0 to each byte in w."""
  return sbox(w)

def rotw(w: bytes) -> bytes:
  """Rotates."""
  return w[1:] + w[:1]

def expand_key(key: bytes) -> list[Block]:
  """Key expansion
   
  Args:
    key: the key

  Returns:
    the round keys for encryption and decryption
  """
  if len(key) not in (16, 24, 32):
    raise ValueError('invalid key length')

  n = len(key) + 28
  # Finds the round key for encryption.
  enc = [0] * n
  nk = len(key) // 4
  for i in range(nk):
    enc[i] = key[4 * i : 4 * i + 4]

  for i in range(nk, n):
    t = enc[i - 1]
    if i % nk == 0:
      t = subw(t)
      rconst = _ROUND_CONST[i // nk - 1]
      t = bytes([t[1] ^ rconst, t[2], t[3], t[0]])
    elif nk > 6 and i % nk == 4:
      t = subw(t)
    enc[i] = _xor(enc[i - nk], t)
  round_keys_enc = [b''.join(enc[i:i+4]) for i in range(0, n, 4)]

  # Finds the round keys for decryption from the encryption keys.
  rounds = len(round_keys_enc) - 1
  round_keys_dec = [None] * (rounds + 1)
  round_keys_dec[0] = round_keys_enc[-1]
  round_keys_dec[-1] = round_keys_enc[0]
  for r in range(1, rounds):
    round_keys_dec[r] = aes_imc(round_keys_enc[rounds - r])
  return round_keys_enc, round_keys_dec

def aes_keygen_assist(s: Block, rc: int):
  rc &= 0xff
  x1 = s[4:8]
  x3 = s[12:16]
  t0 = subw(x1)
  t1 = bytes([t0[1] ^ rc, t0[2], t0[3], t0[0]])
  t2 = subw(x3)
  t3 = bytes([t2[1] ^ rc, t2[2], t2[3], t2[0]])
  return t0 + t1 + t2 + t3

def expand_key_128_intel(key: Block):
  """Simulates Intel's key expansion.
  
  Described in the white paper "Intel Advanced Encryption
  Standard (AES)" by S. Gueron.
  
  There seems to be a typo in Fig.19 on page 20.
  I'm using Fig.24 from page 25.
  """
  rounds = 10
  round_keys = [key] + [None] * rounds
  for i in range(rounds):
    xmm1 = round_keys[i]
    xmm2 = aes_keygen_assist(xmm1, _ROUND_CONST[i])
    # pshufd xmm2, xmm2, 0xff
    xmm2 = xmm2[12:16] * 4
    xmm3 = xmm1
    for j in range(3):
      xmm3 = bytes(4) + xmm3[:12]
      xmm1 = _xor(xmm1, xmm3)
    xmm1 = _xor(xmm1, xmm2)
    round_keys[i + 1] = xmm1
  return round_keys

def inverse_aes_enc(s: Block, round_key: Block) -> Block:
  """Computes the inverse of the AESENC operation.

  AESENC and AESDEC are not inverses of each other.
  Sometimes, (e.g. for the analysis of AEGIS) it is helpful
  to compute the actual inverse of aes_enc.

  Args:
    s: a block of bytes
    round_key: a round key
  Returns:
    a block b such that aes_enc(b, round_key) == s
  """
  s = _xor(s, round_key)
  s = aes_imc(s)
  s = inverse_sbox(s)
  return inverse_shift_rows(s)


def inverse_aes_dec(s: Block, round_key: Block) -> Block:
  """Computes the inverse of the AESDEC operation.

  AESENC and AESDEC are not inverses of each other.
  Sometimes, it is helpful to compute the actual inverse of aes_dec.

  Args:
    s: a block of bytes
    round_key: a round key
  Returns:
    a block b such that aes_dec(b, round_key) == s

  """
  s = _xor(s, round_key)
  s = aes_mc(s)
  s = sbox(s)
  return shift_rows(s)

# ===== AES
class Aes(object):
  """AES encryption and decryption for one data block."""

  def __init__(self, key: bytes):
    assert isinstance(key, bytes)
    self.key = key
    round_keys = expand_key(self.key)
    self.round_keys_enc = round_keys[0]
    self.round_keys_dec = round_keys[1]
    self.rounds = len(self.round_keys_enc) - 1

  def encrypt_block(self, plaintext: Block) -> Block:
    """Encrypts one block of plaintext.

    Args:
      plaintext: a block of plaintext

    Returns:
      AES encryption of the plaintext block

    Raises:
      ValueError: If the plaintext is not a full block.
    """
    assert isinstance(plaintext, bytes)
    if len(plaintext) != 16:
      raise ValueError('invalid plaintext length. expected 16 bytes')
    rk = self.round_keys_enc
    s = _xor(plaintext, rk[0])
    for r in range(1, self.rounds):
      s = aes_enc(s, rk[r])
    return aes_enc_last(s, rk[-1])

  def decrypt_block(self, ciphertext: Block) -> Block:
    """Decrypts one block of ciphertext.

    Args:
      ciphertext: a ciphertext block

    Returns:
      AES decryption of the ciphertext block

    Raises:
      ValueError: If the ciphertext is not a full block.
    """
    assert isinstance(ciphertext, bytes)
    if len(ciphertext) != 16:
      raise ValueError('invalid plaintext length. expected 16 bytes')
    rk = self.round_keys_dec
    s = _xor(ciphertext, rk[0])
    for r in range(1, self.rounds):
      s = aes_dec(s, rk[r])
    return aes_dec_last(s, rk[-1])

  def print_keys(self):
    print("AES")
    print("key:", self.key.hex())
    print("round keys for encryption")
    for r in self.round_keys_enc:
      print(" ", r.hex())
    print("round keys for decryption")
    for r in self.round_keys_dec:
      print(" ", r.hex())



