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

import rsa_key
import os
from time import time

def gen_msg(blen: int, msg_len: int):
  assert msg_len + 10 < blen
  t = bytearray(os.urandom(blen))
  t[0] = 0
  t[1] = 2
  for j in range(2, blen - msg_len):
    while t[j] == 0:
      t[j] = os.urandom(1)[0]
  t[blen-msg_len - 1] = 0
  return bytes(t)
  
def pkcs_conf(m: int, blen: int):
  assert blen > 10
  ba = m.to_bytes(blen, "big")
  if ba[:2] != bytes([0,2]):
    return False
  if 0 in ba[2:10]:
    return False
  if 0 in ba[10:]:
    return True
  return False
  
def gen_key(
    key_size: int = 2048,
    e: int = 65537,
    seed: bytes = b"128x;j234oi123lkjlsd23uxcyh"):
  if key_size % 8 != 0:
    raise ValueError("key size not supported")
  prime_size = key_size // 2
  p = rsa_key.new_prime(prime_size, e, seed=seed + b"p")
  q = rsa_key.new_prime(prime_size, e, seed=seed + b"q")
  key = rsa_key.RsaPrivateKey(p*q, e, primes=sorted([p, q]))
  key.fill_crt()
  return key
  

def limits(n, size, lsbs):
  """
  If m is a pkcs#1 encoded message and last size bits are lsbs of m
  then a <= m * 2^(-size) % n < b
  for the result a, b)
  """
  a = 2<<(n.bit_length() - 16 - size)
  b = 3<<(n.bit_length() - 16 - size)
  t = pow(2, -size, n) * lsbs % n
  return t + a , t + b

def test_step1(key, cnt=100000):
  start = time()
  n = key.n
  key_size = n.bit_length()
  blen = key_size // 8
  low = 2*2**(key_size - 16)
  high = 3*2**(key_size - 16)
  assert key_size % 8 == 0
  val = 0
  cnt0 = cnt * 20
  for i in range(cnt0):
    m = int.from_bytes(os.urandom(blen + 8), "big") % n
    if pkcs_conf(m, blen):
      val += 1
  print("based prob:", val / cnt0, f"{cnt0} / {val}={cnt0/val}") 
    
  for w in [16, 32, 64, 128, 256]:
    val = 0
    inv_w = pow(w, -1, n)
    mult = inv_w * (w+1) % n
    for i in range(cnt):
      msg = gen_msg(blen, 16)
      m = int.from_bytes(msg, "big")
      m2 = m * mult % n
      if pkcs_conf(m2, blen):
        val += 1
    print(w, val / cnt, cnt / val)
  print(f"time: {time()-start}")


def intersect(a: int, b: int, c: int, d: int) -> bool:
  """Determines if [a,b) and [c,d) intersect.
     The function assumes that intervals can wrap around some
     bound > max(a,b,c,d). x
     I.e., if a > b then [a, b) denotes the values x with
     x >= a or x < b.
     The interval [a, a) is the empty interval.
  """
  if a == b or c == d:
    return False  
  return (a > b) + (b > c) + (c > d) + (d > a) != 1
       
def find_k(a: int, b: int, n: int, size: int, max_k=10**7):
  low = 2 << (size - 16)
  high = 3 << (size - 16)
  for k in range(1, max_k, 2):
    ka = a * k % n
    kb = b * k % n
    if ka > kb:
      continue
    if ka < high and kb > low:
      yield k
    
def test_limits(key):
  n = key.n
  key_size = n.bit_length()
  blen = key_size // 8
  msg = gen_msg(blen, 16)
  m = int.from_bytes(msg, "big")
  for i in range(10):
    m2 = m * pow(2, -i, n) % n
    a, b = limits(n, i, m % 2**i)
    if (a <= m2 < b):
      print(i)
      print(hex(a))
      print(hex(m2))
      print(hex(b))

if __name__ == "__main__":
  key_size = 512
  key = gen_key(key_size)
  print(key)
  test_limits(key)
  test_step1(key)


