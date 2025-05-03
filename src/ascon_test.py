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

import ascon
import ascon_ktv


def test_aead(cipher_class,
              test_vectors: list):
  print(f"===== testing {cipher_class.__name__} ===")
  for tc in test_vectors:
    key = bytes.fromhex(tc['key'])
    iv = bytes.fromhex(tc['iv'])
    aad = bytes.fromhex(tc['aad'])
    msg = bytes.fromhex(tc['msg'])
    ct = bytes.fromhex(tc['ct'])
    tag = bytes.fromhex(tc['tag'])
    cipher = cipher_class(key)
    ciphertext, tag2 = cipher.encrypt(iv, aad, msg)
    decrypted = cipher.decrypt(iv, aad, ciphertext, tag2)
    if ciphertext != ct or tag != tag2:
      print('failed test')
      for n, v in tc.items():
        print(n, v)
      print(f'      "ct"  : "{ciphertext.hex()}",')
      print(f'      "tag" : "{tag.hex()}"' + '},')
    if decrypted != msg:
      print('failed decryption')
      print(msg.hex())
      print(decrypted.hex())

def test_hash(hash_func, test_vectors):
  print(f'===== testing {hash_func.__name__} =====')
  for tc in test_vectors:
    msg = bytes.fromhex(tc['msg'])
    tag = bytes.fromhex(tc['tag'])
    ctag = hash_func(msg)
    if tag != ctag:
      print('failed test')
      print(msg.hex())
      print(tag.hex())
      print(f'      "tag" : "{ctag.hex()}"' + '},')

def test_ktv():
  test_aead(ascon.Ascon128, ascon_ktv.ASCON_128_KTV)
  test_aead(ascon.Ascon128a, ascon_ktv.ASCON_128A_KTV)
  test_aead(ascon.Ascon80pq, ascon_ktv.ASCON_80PQ_KTV)
  test_hash(ascon.ascon_xof, ascon_ktv.ASCON_XOF_KTV)
  test_hash(ascon.ascon_hash, ascon_ktv.ASCON_HASH_KTV)
  test_hash(ascon.ascon_xofa, ascon_ktv.ASCON_XOFA_KTV)
  test_hash(ascon.ascon_hasha, ascon_ktv.ASCON_HASHA_KTV)


def benchmark(cipher_cls):
  from time import time
  print('benchmark', cipher_cls.__name__)
  key = bytes(range(cipher_cls.key_len))
  iv = bytes(range(cipher_cls.iv_len))
  aad = bytes()
  cipher = cipher_cls(key)
  for size, reps in [(16, 10000), (256, 1000), (4096, 100), (65536, 10)]:
    start = time()
    msg = bytes(size)
    for _ in range(reps):
      ct, tag = cipher.encrypt(iv, aad, msg)
    t = time() - start
    print(size, round(t, 2), round(t / reps, 5))


if __name__ == "__main__":
  test_ktv()
  for cipher in (ascon.Ascon128, ascon.Ascon128a, ascon.Ascon80pq):
    benchmark(cipher)
