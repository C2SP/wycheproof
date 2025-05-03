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
import os
import pem

def make_key(e, p, q):
  n = p * q
  dp = pow(e, -1, p - 1)
  dq = pow(e, -1, q - 1)
  d = pow(e, -1, (p - 1) * (q - 1))
  qinvp = pow(q, -1, p)
  return [0, n, e, d, p, q, dp, dq, qinvp]


def next_prime(n: int):
  n |= 1
  while pow(3, n, n) != 3:
    n += 2
  return n


def get_p(c: bytes):
  bits = 8 * len(c)
  p = 0
  for x in c:
    p = 256 * p + x
  p |= 2**bits
  p |= 2**(bits - 1)
  return next_prime(p)


def get_weak_p(bits: int, pattern: bytes):
  assert bits % 8 == 0
  res = b''
  while 8 * len(res) < bits:
    res += pattern
  return get_p(res[:bits // 8])


def gen_key(pw: bytes, key_size=16, psize=128, shift=24, e=65537, c=2048):
  id_aes128_ECB = pem.get_oid('2.16.840.1.101.3.4.1.1')
  hmac_md = "SHA-256"
  while True:
    salt = os.urandom(8)
    key = pem.get_key(pw, salt, c, key_size, hmac_md)
    block = bytes.fromhex('fbeb617be71a91efa2b3e6be9627bef9')
    cipher = aes.AES(key)
    dec = cipher.decrypt_block(block)
    pattern = os.urandom(16)
    p = get_weak_p(1024, pattern)
    q = get_p(os.urandom(shift) + dec + os.urandom(psize - 16 - shift))
    if p % e == 1:
      continue
    if q % e == 1:
      continue
    rsa = make_key(e, p, q)
    enc = pem.pem_pkcs8_encrypt(rsa, pw, salt, c, id_aes128_ECB,
                                hmac_md = hmac_md)
    return enc


def key_gen():
  pw = os.urandom(16)
  print(pw.hex())
  for i in range(2, 32):
    print(i)
    print(gen_key(pw, shift=i))


if __name__ == '__main__':
  key_gen()
