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

# This is an experimental implementation of AES-VCM.
# The implementation is slow, it doesn't check for invalid input and hence
# must not be used for actual encryption.
#
# I'm using this implemementation for example to generate IVs so that
# the CTR has given values.
# References Ed Knapp has written a paper. Not sure if this has been
# published.
import aes
import vmac

def int2bytes(n:int, cnt:int) -> bytes:
  """Converts an integer into an array of bytes
     of size cnt using big-endian order."""
  res = bytearray(cnt)
  for i in range(cnt):
    res[cnt - 1 - i] = n % 256
    n //= 256
  return bytes(res)

def bytes2int(ba:bytes) -> int:
  """Converts an array of bytes into an integer
     using bigendian order"""
  res = 0
  for b in ba:
    res = 256 * res + b
  return res

def xor(A:bytes, B:bytes) -> bytes:
  return bytes(x^y for x,y in zip(A, B))

class AesVcm:
  name = "AES-VCM"
  def __init__(self, key:bytes, tagsize:int = 16, debug:bool=False):
    self.key = key
    # a block cipher for the key
    self.E = aes.AES(key)
    self.mac = vmac.Vmac(key, tagsize * 8)
    self.debug = debug

  def encrypt_block(self, block:bytes) -> bytes:
    assert len(block) == 16
    return self.E.encrypt_block(block)

  def get_ctr(self, iv:bytes):
    if len(iv) == 12:
      return bytes([1,0,0,0]) + iv
    else:
      raise ValueError("12 byte nonce expected")

  def inc_ctr(self, ctr:bytes, increment:int=1) -> bytes:
    assert len(ctr) == 16
    c = bytearray(ctr)
    for i in range(4):
      if c[i] < 255:
        c[i] += 1
        break
      c[i] == 0
    ctr = bytes(c)
    if self.debug:
      print("inc_ctr", ctr.hex())
    return ctr

  def gctr(self, ctr:bytes, b:bytes)->bytes:
    res = bytes()
    for i in range(0, len(b), 16):
      res += xor(self.E.encrypt_block(ctr), b[i:i+16])
      ctr = self.inc_ctr(ctr)
    return res

  def get_tag(self, A:bytes, C:bytes, nonce:bytes) -> bytes:
    L = int2bytes(len(A)*8, 8) + int2bytes(len(C)*8, 8)
    padA = bytes(-len(A) % 16)
    padC = bytes(-len(C) % 16)
    S = A + padA + C + padC + L
    tag = self.mac.mac(S, nonce)
    return tag


  def encrypt(self, nonce:bytes, A:bytes, P:bytes) -> bytes:
    ctr = self.get_ctr(nonce)
    C = self.gctr(ctr, P)
    tag = self.get_tag(A, C, nonce)
    return C, tag

  def decrypt(self, nonce:bytes, A:bytes, C:bytes, T:bytes) -> bytes:
    ctr = self.get_ctr(nonce)
    tag = self.get_tag(A, C, nonce)
    if T != tag:
      raise Exception("Invalid tag")
    return self.gctr(ctr, C)


