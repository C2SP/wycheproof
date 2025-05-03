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
import typing

# TODO: Generate test vectors.
# Edge cases are:
#  - empty strings
#  - short strings < 16
#  - long strings
#  - string that are multiples of 16 bytes
#  - modify the tag.
#  - modify the tag before tha last encryption.
#    (i.e. someone might try to parallelize the last encryption away.

def multiply_by_x(block: bytes) -> bytes:
  assert len(block) == 16
  assert isinstance(block, bytearray) or isinstance(block, bytes)
  res = bytearray(16)
  for i in range(16):
    res[i] = (block[i] << 1) & 0xff
  for i in range(15):
    res[i] ^= block[i+1] >> 7
  res[15] ^= (block[0] >> 7) * 0x87
  return bytes(res)

def divide_by_x(block: bytes) -> bytes:
  '''Inverse of multiply_by_x
  >>> b = bytes(range(16))
  >>> divide_by_x(multiply_by_x(b)) == b
  True
  >>> b = bytes([255]*16)
  >>> divide_by_x(multiply_by_x(b)) == b
  True
  '''
  assert len(block) == 16
  tmp = bytearray(block)
  carry = tmp[15] & 1
  tmp[15] ^= carry * 0x87
  res = bytearray([0])*16
  for i in range(16):
    res[i] = (tmp[i] >> 1)
  for i in range(15):
    res[i+1] ^= (tmp[i] << 7) & 0xff
  res[0] ^= carry << 7
  return bytes(res)

def _xor(a: bytes,b: bytes)-> bytes:
  assert len(a) == len(b)
  return bytes(x^y for x,y in zip(a,b))

class Pmac:
  '''
  References: 
  J. Black and P. Rogaway,
  "A Block-Cipher Mode of Operation for Parallelizable Message Authentication"
  Eurocrypt '02

  https://en.wikipedia.org/wiki/PMAC_(cryptography) 
  '''
  def __init__(self,
               key:typing.Optional[bytes]=None,
               cipher:typing.Optional[aes.AES]=None,
               macsize:int=16):
    assert macsize <= 16
    # Specify either by key or cipher
    assert (key is None) != (cipher is None)
    if cipher:
      assert isinstance(cipher, aes.AES)
      self.cipher = cipher
    else:
      self.cipher = aes.AES(key)
    self.macsize = macsize
    l = self.cipher.encrypt_block(bytes(16))
    self.l_div_x = divide_by_x(l)
    self.L = [l]

  def gamma(self, i: int)-> int:
    return i ^ (i >> 1)

  def gamma_L(self, i:int) -> bytes:
    g = self.gamma(i)
    while g.bit_length() > len(self.L):
      self.L.append(multiply_by_x(self.L[-1]))
    res = bytes(16)
    for i in range(g.bit_length()):
      if g & (1 << i):
        res = _xor(res, self.L[i])
    return res
 
  def padded(self, block:bytes)->bytes:
    assert len(block) <= 16
    if len(block) == 16:
      return _xor(block, self.l_div_x)
    else:
      return block + bytes([0x80]) + bytes(16 - 1 - len(block))

  def mac(self, data:bytes)-> bytes:
    blocks = max(1, (len(data) + 15) // 16)
    res = bytearray([0]*16)
    for i in range(blocks - 1):
      x = _xor(self.gamma_L(i + 1), data[i*16:(i+1)*16])
      y = self.cipher.encrypt_block(x)
      res = _xor(res, y)
    lastblock = data[(blocks-1)*16:]
    sigma = _xor(res, self.padded(lastblock))
    tag = self.cipher.encrypt_block(sigma)
    return tag[:self.macsize]

  def invert_mac(self, tag:bytes, tail:bytes=None)-> bytes:
    '''Returns a input of size len(tail)+16,
       such that result ends with tail and the PMAC
       of the result is tag'''
    assert len(tag) == self.macsize
    if tail is None:
      tail = bytes()
    sigma_wanted = self.cipher.decrypt_block(tag)
    tag0 = self.mac(bytes(16) + tail)
    sigma0 = self.cipher.decrypt_block(tag0)
    sigma_diff = _xor(sigma_wanted, sigma0)
    sigma_diff += bytes(16 - len(sigma_diff))
    if len(tail)==0:
      # the block to modify is the last block
      return sigma_diff
    else:
      # Find block B such that
      # _xor(cipher.encrypt_block(gamma_L(1)),
      #      cipher.encrypt_block(xor(B, gamma_L(1)) = sigma_diff
      A = _xor(sigma_diff, self.cipher.encrypt_block(self.gamma_L(1)))
      B = _xor(self.gamma_L(1), self.cipher.decrypt_block(A))
      return B + tail

# Test vectors from
# A Block-Cipher Mode of Operation for Parallelizable Message Authentication
# J. Black, P. Rogaway
# February 15, 2002
#
# Format: [comment, key_hex, msg_hex, tag]
KnownTestVectors = [
    ["PMAC-AES-128-0B",
     "000102030405060708090a0b0c0d0e0f",
     "",
     "4399572cd6ea5341b8d35876a7098af7"
    ],
    ["PMAC-AES-128-3B",
     "000102030405060708090a0b0c0d0e0f",
     "000102",
     "256ba5193c1b991b4df0c51f388a9e27",
    ],
    ["PMAC-AES-128-16B",
     "000102030405060708090a0b0c0d0e0f",
     "000102030405060708090a0b0c0d0e0f",
     "ebbd822fa458daf6dfdad7c27da76338"],
    ["PMAC-AES-128-20B",
     "000102030405060708090a0b0c0d0e0f",
     "000102030405060708090a0b0c0d0e0f10111213",
     "0412ca150bbf79058d8c75a58c993f55"],
    ["PMAC-AES-128-32B",
     "000102030405060708090a0b0c0d0e0f",
     "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
     "e97ac04e9e5e3399ce5355cd7407bc75"],
    ["PMAC-AES-128-34B",
     "000102030405060708090a0b0c0d0e0f",
     "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021",
     "5cba7d5eb24f7c86ccc54604e53d5512"],
    ["PMAC-AES-128-1000B",
     "000102030405060708090a0b0c0d0e0f",
     "00" * 1000,
     "c2c9fa1d9985f6f0d2aff915a0e8d910"],
    ["PMAC-AES-192-0B",
     "000102030405060708090a0b0c0d0e0f1011121314151617",
     "",
     "0d63b2b2c276de9306b2f37e36dabe49"],
    ["PMAC-AES-192-3B",
     "000102030405060708090a0b0c0d0e0f1011121314151617",
     "000102",
     "5b1cbc4340752742d8828a7aa2c3197d"],
    ["PMAC-AES-192-16B",
     "000102030405060708090a0b0c0d0e0f1011121314151617",
     "000102030405060708090a0b0c0d0e0f",
     "0787415737989bc1a2e124c991e400e1"],
    ["PMAC-AES-192-20B",
     "000102030405060708090a0b0c0d0e0f1011121314151617",
     "000102030405060708090a0b0c0d0e0f10111213",
     "156a7c21121cc773a731e05ab618c6bb"],
    ["PMAC-AES-192-32B",
     "000102030405060708090a0b0c0d0e0f1011121314151617",
     "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
     "654a145904dc97da9f68318b180970b9"],
    ["PMAC-AES-192-34B",
     "000102030405060708090a0b0c0d0e0f1011121314151617",
     "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021",
     "b5ff2016878e834438aa1ff624bfa09c"],
    ["PMAC-AES-192-1000B",
     "000102030405060708090a0b0c0d0e0f1011121314151617",
     "00" * 1000,
     "d3aec29036298bc11a2905f53773ff50"],
    ["PMAC-AES-256-0B",
     "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
     "",
     "e620f52fe75bbe87ab758c0624943d8b"],
    ["PMAC-AES-256-3B",
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
     "000102",
     "ffe124cc152cfb2bf1ef5409333c1c9a"],
    ["PMAC-AES-256-16B",
     "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
     "000102030405060708090a0b0c0d0e0f",
     "853fdbf3f91dcd36380d698a64770bab"],
    ["PMAC-AES-256-20B",
     "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
     "000102030405060708090a0b0c0d0e0f10111213",
     "7711395fbe9dec19861aeb96e052cd1b"],
    ["PMAC-AES-256-32B",
     "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
     "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
     "08fa25c28678c84d383130653e77f4c0"],
    ["PMAC-AES-256-34B",
     "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
     "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021",
     "edd8a05f4b66761f9eee4feb4ed0c3a1"],
    ["PMAC-AES-256-1000B",
     "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
     "00" * 1000,
     "69aa77f231eb0cdff960f5561d29a96e"],
  ]

# Special keys:
# key, E(0)
# c7497273539937f28cd8102b8304e12b 2ca997a20f240174d23af27c8718c780
# f37111ee5411608d59d496dfeb1c4e25 f510799364dccfc94a035becfbba5780
# 9c8aa3b3a6e8fe148d68ca311d287d8a 7c5ef4122068b64950c07533b6ac9a80
# 168baea5755853cef014a40e9b65d001 519e83856db1e7d65782c570197e7380
# ca570ce7aee85a447a570d45b85ceb9e 74051eb1c0a2cc84c70739db85988000
# 518e1757f066658c4cfa38661bc9a1fc c50dbc82515d521bfc1d5a97d0f58000
# 2fb2bd17e986fc1b9d842c13b03f038a b45c0ceb40c5d19dd700a4d6ba800000
# 284eb430be119f53ef659252eb667c2e 32523efc467188cc4c76b812f8800000

def test():
  for comment, key_hex, msg_hex, tag_hex in KnownTestVectors:
     m = Pmac(bytes.fromhex(key_hex))
     tag = m.mac(bytes.fromhex(msg_hex))
     assert tag.hex() == tag_hex, comment

def test2():
  '''The paper by
     Changhoon Lee, Jongsung Kim, Jaechul Sung, Seokhie Hong, Sangjin Lee. 
     "Forgery and Key Recovery Attacks on PMAC and Mitchell's TMAC Variant", 
     2006 shows that finding a collision where only the last block changes
     leaks the L*x^-1.
     Once L*x^-1 and hence L is known it is possible to modify other
     message blocks without changing the tag. 
  '''
  a = Pmac(bytes(range(16)))
  A = bytes(range(13))
  tag = a.mac(A)
  B = a.invert_mac(tag)
  print(a.l_div_x.hex())
  print(_xor(a.padded(A), B).hex())

def diff_test():
  '''Once a MAC collision of string of the same length is known
     it is possible to generate more collisions.'''
  a = Pmac(bytes(range(16)))
  A = bytes(32)
  tagA = a.mac(A)
  B = a.invert_mac(tagA, bytes([0x01] * 16))
  diff = bytes(range(16))
  A2 = A[:16] + _xor(diff, A[16:])
  B2 = B[:16] + _xor(diff, B[16:])
  print(A2.hex(), a.mac(A2).hex())
  print(B2.hex(), a.mac(B2).hex())
  
if __name__ == "__main__":
  test()
  test2()
  diff_test()

