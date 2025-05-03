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

import aes

# type hints:
Block = bytes  # a 128-bit block

class BitString:
  def __init__(self, bits: int, size: int):
    if bits.bit_length() > size:
      bits %= 2**size
    self.bits = bits
    self.size = size

  def __len__(self) -> int:
    return self.size

  @classmethod
  def from_int(cls, n: int, bits: int) -> "BitString":
    return cls(n, bits)

  @classmethod
  def from_bytes(cls, b: bytes) -> "BitString":
    bits = 0
    for v in b:
      bits = (bits << 8) + v
    return cls(bits, len(b) * 8)

  @classmethod
  def zeros(cls, bits: int) -> "BitString":
    return cls(0, bits)

  def __repr__(self) -> str:
    return "BitString(%s, %s)" %(bin(self.bits), self.size)

  def __add__(self, other:"BitString") -> "BitString":
    return BitString((self.bits << other.size) | other.bits,
                     self.size + other.size)
 
  def asBytes(self) -> bytes:
    if self.size % 8 != 0:
      raise ValueError("BitString not a multiple of 8")
    b = bytearray(self.size // 8)
    bits = self.bits
    for i in range(self.size // 8):
      bits, r = divmod(bits, 256)
      b[i] = r
    return bytes(b[::-1])

  def as_block(self) -> Block:
    assert self.size == 128
    return self.asBytes()

  def __getitem__(self, key) -> "BitString":
    """Returns a bit or a slice.
   
    RFC 7253 uses 1 based big-endian order. 
    This implementation uses 0 based big_endian order. 
    [0] is the most significant bit
    Slices don't support step and don't include
    the stop.
    >>> BitString(0b001011000, 9)[2,6]
    ... BitString(0b1011, 4)
    """ 
    if isinstance(key, int):
      pos = self.size - key - 1
      return (self.bits >> pos) & 1
    elif isinstance(key, slice):
      if key.step not in [1, None]:
        raise ValueError("step not supported")
      shift = (self.size - key.stop)
      size = (key.stop - key.start)
      return BitString(self.bits >> shift, size)
    raise ValueError("Unsupported key")

  def __xor__(self, other: "BitString") -> "BitString":
    if self.size != other.size:
      raise ValueError("BitString not of equal size")
    return BitString(self.bits ^ other.bits, self.size)
  

  __str__ = __repr__  

def _ntz(n:int) -> int:
  assert n > 0
  return (n & -n).bit_length() - 1

def _xor(a:bytes, b:bytes) -> bytes:
  if len(a) != len(b):
    raise ValueError("invalid length")
  return bytes(x ^ y for x, y in zip(a, b))

def _shift(a: bytes, n: int) -> int:
  num_bytes, num_bits = divmod(n, 8)
  if num_bytes:
    a = a[num_bytes:]
  if num_bits == 0:
    return a
  b = bytearray(len(a))
  for i in range(len(a)):
    b[i] = (a[i] << num_bits) & 0xff
  for i in range(len(a)-1):
    b[i] ^= a[i+1] >> (8 - num_bits)
  return bytes(b)
    
  
def _dbl(block: Block) -> Block:
  assert len(block) == 16
  res = bytearray([0])*16
  for i in range(16):
    res[i] = (block[i] << 1) & 0xff
  for i in range(15):
    res[i] ^= block[i+1] >> 7
  res[15] ^= (block[0] >> 7) * 0x87
  return bytes(res)


class AesOcb:
  def __init__(self, key: bytes, tagsize: int = 16):
    self.key = key
    if not (0 < tagsize <= 16):
      raise ValueError("Invalid tagsize")
    self.tagsize = tagsize
    self.cipher = aes.AES(key)
    self.L_star = self.cipher.encrypt_block(bytes(16))
    self.L_dollar = _dbl(self.L_star)
    self.L = [_dbl(self.L_dollar)]

  def print_state(self):
    print("key :", self.key.hex())
    print("L_* :", self.L_star.hex())
    print("L_$ :", self.L_dollar.hex())
    print("L_0 :", self.get_l(0).hex())
    print("L_1 :", self.get_l(1).hex())

  def get_l(self, i) -> bytes:
    while len(self.L) <= i:
      self.L.append(_dbl(self.L[-1]))
    return self.L[i]

  def pad_block(self, b: bytes) -> Block:
    assert len(b) < 16
    return b + bytes([0x80] + [0] * (15 - len(b)))

  def hash(self, aad: bytes) -> Block:
    summ = bytes(16)
    offset = bytes(16)
    aad_blocks = len(aad) // 16
    for i in range(aad_blocks):
      offset = _xor(offset, self.get_l(_ntz(i + 1)))
      a = aad[16 * i : 16 * (i + 1)]
      summ = _xor(summ, self.cipher.encrypt_block(_xor(a, offset)))
    a_star = aad[16 * aad_blocks:]
    if a_star:
      offset = _xor(offset, self.L_star)
      a = self.pad_block(a_star)
      summ = _xor(summ, self.cipher.encrypt_block(_xor(a, offset)))
    return summ
    
  def encrypt(self,
              nonce: bytes,
              aad: bytes,
              msg: bytes) -> tuple[bytes, bytes]:
    if len(nonce) > 15:
      raise ValueError("Invalid nonce")

    # num2str: bigendian representation
    #
    # Nonce = num2str(TAGLEN mod 128,7) || zeros(120-bitlen(N)) || 1 || N
    # bottom = str2num(Nonce[123..128])
    # Ktop = ENCIPHER(K, Nonce[1..122] || zeros(6))
    # Stretch = Ktop || (Ktop[1..64] xor Ktop[9..72])
    # Offset_0 = Stretch[1+bottom..128+bottom]
    # Checksum_0 = zeros(128)
    N = bytearray(16)
    N[0] = self.tagsize * 16 % 256
    N[-len(nonce):] = nonce
    N[-len(nonce)-1] ^= 1
    bottom = N[-1] & 0b111111
    N[-1] &= 0b11000000
    N = bytes(N)
    ktop = self.cipher.encrypt_block(N)
    stretch = ktop + _xor(ktop[0:8], ktop[1:9])
    offset = _shift(stretch, bottom)[:16]
    ck_sum = bytes(16)
    ct = []
    blocks = len(msg) // 16
    for i in range(blocks):
      offset = _xor(offset, self.get_l(_ntz(i + 1)))
      p = msg[16 * i : 16 * (i + 1)]
      ci = _xor(offset, self.cipher.encrypt_block(_xor(offset, p)))
      ct.append(ci)
      ck_sum = _xor(ck_sum, p)
    p_star = msg[16 * blocks:]
    if p_star:
      offset = _xor(offset, self.L_star)
      pad = self.cipher.encrypt_block(offset)
      c_star = _xor(p_star, pad[:len(p_star)])
      ck_sum = _xor(ck_sum, self.pad_block(p_star))
      ct.append(c_star)
    taginp = _xor(ck_sum, _xor(offset, self.L_dollar))
    h = self.hash(aad)
    t0 = self.cipher.encrypt_block(taginp)
    tag = _xor(h, t0)[:self.tagsize]
    return b"".join(ct), tag

  def decrypt(self,
              nonce: bytes,
              aad: bytes,
              ct: bytes,
              tag: bytes) -> tuple[bytes, bytes]:
    if len(nonce) > 15:
      raise ValueError("Invalid nonce")

    # num2str: bigendian representation
    #
    # Nonce = num2str(TAGLEN mod 128,7) || zeros(120-bitlen(N)) || 1 || N
    # bottom = str2num(Nonce[123..128])
    # Ktop = ENCIPHER(K, Nonce[1..122] || zeros(6))
    # Stretch = Ktop || (Ktop[1..64] xor Ktop[9..72])
    # Offset_0 = Stretch[1+bottom..128+bottom]
    # Checksum_0 = zeros(128)
    N = bytearray(16)
    N[0] = self.tagsize * 16 % 256
    N[-len(nonce):] = nonce
    N[-len(nonce)-1] ^= 1
    bottom = N[-1] & 0b111111
    N[-1] &= 0b11000000
    N = bytes(N)
    ktop = self.cipher.encrypt_block(N)
    stretch = ktop + _xor(ktop[0:8], ktop[1:9])
    offset = _shift(stretch, bottom)[:16]
    ck_sum = bytes(16)
    pt = []
    blocks = len(ct) // 16
    for i in range(blocks):
      offset = _xor(offset, self.get_l(_ntz(i + 1)))
      ci = ct[16 * i : 16 * (i + 1)]
      p = _xor(offset, self.cipher.decrypt_block(_xor(offset, ci)))
      pt.append(p)
      ck_sum = _xor(ck_sum, p)
    c_star = ct[16 * blocks:]
    if c_star:
      offset = _xor(offset, self.L_star)
      pad = self.cipher.encrypt_block(offset)
      p_star = _xor(c_star, pad[:len(c_star)])
      ck_sum = _xor(ck_sum, self.pad_block(p_star))
      pt.append(p_star)
    taginp = _xor(ck_sum, _xor(offset, self.L_dollar))
    h = self.hash(aad)
    t0 = self.cipher.encrypt_block(taginp)
    tag2 = _xor(h, t0)[:self.tagsize]
    if tag != tag2:
      raise ValueError("Invalid tag")
    return b"".join(pt)

