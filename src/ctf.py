#!/usr/bin/python3.9
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

from typing import Any
import hashlib
import hmac
import pickle
import random
import os
import time

# flag = open('flag.txt', 'rb').read().strip()
flag = bytes(range(32)) 

enc_oid = ('I am not sure, but I would guess something in between ' 
           '1.2.840.113549.2.7 and 1.2.840.113549.1.1.5 plus nonce')
sig_oid = ('I am not sure, but I would guess something in between '
           '1.2.840.113549.2.7 and 1.2.840.113549.1.1.5 plus nonce')
enc_algorithm = ('I am not sure, but I would guess something in between '
                 'hmacWithSHA1 and sha1WithRSAEncryption plus nonce')
sig_algorithm = ('I am not sure, but I would guess something in between '
                 'hmacWithSHA1 and sha1-with-rsa-signature plus nonce')

def bytes_to_long(b: bytes):
  return int.from_bytes(b, "big")

def long_to_bytes(n: int):
  size = (n.bit_length() + 7) // 8
  return n.to_bytes(size, "big")
  
def next_prime(x):
  while pow(3, x, x) != 3:
    x += 1
  return x

def invert(x, n):
  return pow(x, -1, n)

def pad(d: bytes, size: int) -> bytes:
  assert len(d) < size
  res = d + bytes([0x80]) + bytes(size - len(d)- 1)
  return res

def unpad(d: bytes, size: int):
  d = bytes(size - len(d)) + d
  i = len(d) - 1
  while d[i] == 0 and i > 0:
    i -= 1
  assert d[i] == 0x80
  res = d[:i]
  return res
 
class RSA:
  def __init__(self):
    self.e = 65537
    self.p = next_prime(random.getrandbits(2048) | 2**2047 | 2**2046)
    print(f"p={self.p}")
    self.q = next_prime(random.getrandbits(2048) | 2**2047 | 2**2046)
    print(f"q={self.q}")
    self.d = invert(self.e, (self.p-1)*(self.q-1))
    self.n = self.p*self.q
    self.bl = self.n.bit_length()//8
  
  def encrypt(self, msg: bytes, hmac_key: bytes) -> bytes:
    def _parse(msg: bytes) -> int:
      data = {
          'hmac_key': hmac_key,
          'oid': enc_oid,
          'nonce': hmac.digest(hmac_key, long_to_bytes(int(time.time())), hashlib.sha1),
          'algorithm_name': enc_algorithm,
          'message': msg,
          'digest_message': hmac.digest(hmac_key, msg, hashlib.sha1),
      }
      m = bytes_to_long(pad(pickle.dumps(data), self.bl))
      if not m < self.n:
        raise ValueError('Can\'t encrypt. Message is too long.')
      return m
  
    return long_to_bytes(pow(_parse(msg), self.e, self.n))
  def decrypt(self, enc: bytes) -> bytes:
    def _unparse(m: int) -> dict[str, Any]:
      data = pickle.loads(unpad(long_to_bytes(m), self.bl))
      return data
    m = pow(bytes_to_long(enc), self.d, self.n)
    data = _unparse(m)
    digest_message = hmac.digest(data['hmac_key'],
                                 data['message'],
                                 hashlib.sha1)
    if digest_message != data['digest_message']:
      raise ValueError('Can\'t decrypt. Integrity check failed.')
    return data['message']
  def sign(self, msg: bytes, hmac_key: bytes) -> bytes:
    def _parse(msg: bytes) -> int:
      data = {
        'hmac_key': hmac_key,
        'oid': sig_oid,
        'nonce': hmac.digest(hmac_key, long_to_bytes(int(time.time())), hashlib.sha1),
        'algorithm_name': sig_algorithm,
        'digest_message': hmac.digest(hmac_key, msg, hashlib.sha1),
      }
      m = bytes_to_long(pad(pickle.dumps(data), self.bl))  
      if not m < self.n:
        raise ValueError('Can\'t sign. Message is too long.')
      return m
    def _crt(m: list[int], a: list[int]) -> int:
      acc = 0
      prod = 1
      for v in m:
        prod *= v
      for n_i, a_i in zip(m, a):
        p = prod // n_i
        acc += a_i * invert(p, n_i) * p
      return acc % prod
    p1 = _parse(msg)
    sp = pow(p1, self.d, self.p)
    p2 = _parse(msg)
    sq = pow(p2, self.d, self.q)
    s = _crt([self.p, self.q], [sp, sq])
    return long_to_bytes(s), p1, p2
  def verify(self, msg: bytes, sig: bytes):
    def _unparse(m: int) -> dict[str, Any]:
      data = pickle.loads(unpad(long_to_bytes(m), self.bl))
      return data
    try:
      m = pow(bytes_to_long(sig), self.e, self.n)
      data = _unparse(m)
      digest_message = hmac.digest(data['hmac_key'], msg, hashlib.sha1)
      return digest_message == data['digest_message']
    except:
      return False
# Testing protocol...
def main():
  rsa = RSA()
  for i in range(1000):
    hmac_key = os.urandom(16)
    enc = rsa.encrypt(flag, hmac_key)
    dec = rsa.decrypt(enc)
    sig, p1, p2 = rsa.sign(flag, hmac_key)
    if dec == flag and rsa.verify(flag, sig):
      print("Test %d OK! :)" % i)
    else:
      print("Something went wrong :(\n\n")
      print("Debug info:")
      print('e =', hex(rsa.e))
      print('n =', hex(rsa.n))
      print('enc = 0x' + enc.hex())
      print('sig = 0x' + sig.hex())
      print('p1 =', hex(p1))
      print('p2 =', hex(p2))
      print('diff', hex(p1 ^ p2))
      break
      
if __name__ == "__main__":
  main()
