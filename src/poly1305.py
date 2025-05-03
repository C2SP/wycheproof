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

# Implements Poly1305.
# This algorithm is typically used in AEADs such as
# ChaCha20-Poly1305.
#
# Poly1305 can be used as a MAC only, if properly randomized.
# This is rarely done. Probably the randomization is too cumbersome.
#
# The Ecrypt recommendation "D5.4 Algorithms, Key size and protocol report
# (2018) puts Poly1305 into the legacy category. I.e., Poly1305 should only
# be used for AEADs.

import typing
import util

p = 2**130 - 5
def le_bytes_to_int(s: bytes)-> int:
  return int.from_bytes(s, 'little')

def int_to_bytes(val: int, cnt: int = 16)-> bytes:
  '''Converts to little endian. Allows overflow.

  Args:
    val: the integer to converto to little endian.
    cnt: the number of bytes to use
  Returns:
    the integer converted to little endian
  '''
  res = bytearray(cnt)
  for i in range(cnt):
    val, rem = divmod(val, 256)
    res[i] = rem
  return bytes(res)

def get_rs(otkey: bytes)-> typing.Tuple[int, int]:
  '''Convert a poly1305 key to values r, s.

  Args:
    otkey: the onetime key. Must be 32 bytes long
  Returns:
    the integers r and s.
  '''
  if len(otkey) != 32:
    raise ValueError("Invalid key size")
  r = le_bytes_to_int(otkey[:16]) & 0x0ffffffc0ffffffc0ffffffc0fffffff
  s = le_bytes_to_int(otkey[16:])
  return r,s
   
# TODO: find keys where the limbs are maximal, rsp. sum(limbs) large
@util.type_check
def poly1305(otkey: bytes, message: bytes)-> bytes:
  '''Computes poly1305 of a message.

  Args:
    otkey: the onetime key. Must be 32 bytes long.
    message: the message to compute poly1305 for.
  Returns:
    the poly1305 result
  '''
  r, s = get_rs(otkey)
  acc = 0
  for b in range(0, len(message), 16):
    for i, c in enumerate(message[b:b+16] + b'\x01') :
      acc += c << (8 * i)
    acc = acc * r % p
  # No mod here.
  acc += s
  return int_to_bytes(acc)

def poly1305Hex(key: str, message: bytes):
  '''Computes poly1305 of a message in hex.

  Args:
    otkey: a 32 byte long key
    message: the message over which poly1305 is computed.
  Returns:
    the poly1305 result in hex.

  >>> key = "85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b"
  >>> msg = b"Cryptographic Forum Research Group"
  >>> poly1305Hex(key, msg)
  'a8061dc1305136c6c22b8baf0c0127a9'
  '''
  res = poly1305(bytes.fromhex(key), message)
  return res.hex()

# ----- Test vector generation: -----
@util.type_check
def append_blocks(otkey: bytes, prefix: bytes, intermediate_sum: int)-> bytes:
  '''Finds blocks so that the intermediate result of prefix+blocks is equal to
     intermediate_sum

  Args:
    otkey: the one time key for poly1305
    prefix: the prefix of the message searched.
    intermeadidate_sum: the intermediate sum of poly1305 after the computation
       over prefix + "the blocks found"
  Returns:
    prefix + additional blocks
  '''
  if len(prefix) % 16 != 0:
    raise ValueError("prefix must be a multiple of 16 bytes long")
  r = le_bytes_to_int(otkey[:16]) & 0x0ffffffc0ffffffc0ffffffc0fffffff
  rinv = pow(r, -1, p)
  target = intermediate_sum * rinv % p
  acc = 0
  for b in range(0, len(prefix), 16):
    for i,c in enumerate(prefix[b:b+16] + b'\x01') :
      acc += c << (8 * i)
    acc = acc * r % p
  delta = (target - acc - 2**128) % p
  if delta < 2**128:
    return prefix + int_to_bytes(delta)
  k = 2**128-1
  while True:
    acc2 = (acc + k + 2**128) * r % p
    delta = (target - acc2 - 2**128) % p
    if delta < 2**128:
      return prefix + int_to_bytes(k) + int_to_bytes(delta)
    k -= 1

@util.type_check
def modify_blocks(otkey: bytes,
                  message: bytes, 
                  idx1: int,
                  idx2: int,
                  poly: int) -> bytes:
  '''Modifies the blocks with index idx1 and idx2 in message such that 
     le_bytes_to_int(poly1305(otkey, message)) == poly'''
  blocks = (len(message) + 15) // 16
  if idx1 >= blocks - 1:
    raise ValueError("idx1 too large")
  if idx2 >= blocks - 1:
    raise ValueError("idx2 too large")
  if idx1 == idx2:
    raise ValueError("idx1 and idx2 must be distinct")
  r = le_bytes_to_int(otkey[:16]) & 0x0ffffffc0ffffffc0ffffffc0fffffff
  rinv = pow(r, -1, p)
  polym = le_bytes_to_int(poly1305(otkey, message))
  m1 = pow(r, blocks - idx1, p)
  m2inv = pow(rinv, blocks - idx2, p)
  b1 = le_bytes_to_int(message[idx1*16:(idx1+1)* 16])
  b2 = le_bytes_to_int(message[idx2*16:(idx2+1)* 16])
  delta = (poly - polym) % p
  d1 = 0
  while True:
    assert d1 <= b1
    d2 = (delta + (d1 * m1)) * m2inv % p
    c2 = (b2 + d2) % p
    if c2 < 2**128:
      ba = bytearray(message)
      ba[idx1*16:(idx1+1)* 16] = int_to_bytes(b1 - d1)
      ba[idx2*16:(idx2+1)* 16] = int_to_bytes(c2)
      m = bytes(ba)
      w = le_bytes_to_int(poly1305(otkey, m))
      if w == poly:
        return m
      raise AssertionError("Computation failed:"
        "d1 = %s, poly = %x, w = %x" % (d1, poly, w))
    d1 += 1
 
if __name__ == "__main__":
    import doctest
    doctest.testmod()

