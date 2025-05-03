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

import test_util

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# list of tuples (hash, bytes, repetitions, result-hex)
LONG_HASHES = [
  ("MD5", b'a', 2147483647, "bb2ef53aae423cb9fbf8788f187601e6"),
  ("MD5", b'a', 5000000000, "cf3147924864955e385804daee42d3ef"),
  ("SHA-1", b'a', 2147483647, "1e5b490b10255e37fd96d0964f2fbfb91ed47536"),
  ("SHA-1", b'a', 5000000000, "109b426b74c3dc1bd0e15d3524c5b837557647f2"),
  ("SHA-256", b'a', 2147483647,
        "6cc47f3907eea90fb8de9493cf025923fff2b88fcac896cbf38036d5913b6bed"),
  ("SHA-256", b'a', 5000000000,
        "59fefaeb480c09b569fb8e5f277e0165e3f33bd322a2d2148cf6dd49af40779c"),
  ("SHA-224", b'a', 2147483647,
        "bf5dbff84919d0bd40316439d102c6f856553b7a89ef9212fd200d9e"),
  ("SHA-224", b'a', 5000000000,
        "01acee23c428420235b7cd6a4e8c7ee453242f094f1d4477de6ad61a"),
  ("SHA-384", b'a', 2147483647,
        "08879ffbedb441c65ecf1c66286036c853632cf73262d5d3d6ecc621ee148e89"
            + "f8acf29c0849f72e2a98756d4d4b895f"),
  ("SHA-384", b'a', 5000000000,
        "7f1541299d24f30155b4a849c4e8abd67cbf273a996d7a8c384476e87c143abd"
            + "35eef2e1dd576960b9e5a0cd10607c43"),
  ("SHA-512", b'a', 2147483647,
        "7c69df3c6a06437c6d6ea91cb10812edcdaaeabda16c6436bf3279d82c7cf40e"
            + "2a94cc4b363206c1dce79904f9ce876e434cf78745a426ceef199c4d748acea9"),
  ("SHA-512", b'a', 5000000000,
        "080c2d9527c960c2a4a9124d728d36cd2effcaac73de09221bfc8b4afc6d52e0"
            + "4006f962f4fb31640642aece873f7906180cc3ebf794cd319d27d30889428011"),
]


def test_long_hash(log_timing=False):
  '''Tests hash algorithms with inputs longer than 2^32 bytes.'''
  from time import time
  errors = 0
  for md, bytes, repetitions, result in LONG_HASHES:
    msg = bytes * repetitions
    if log_timing:
      start = time()
    sha = hashes.Hash(test_util.get_hash(md), backend=default_backend())
    sha.update(msg)
    digest = sha.finalize()
    if log_timing:
      t = time()-start
      ns_per_byte = t * 10 ** 9 / len(msg)
      print("%s(%s*%d):%s ns/B" % (md, repr(bytes), repetitions, time()-start),
            ns_per_byte)
    if digest.hex() != result:
      print("Incorrect result for %s(%s*%d)" % (md, repr(bytes), repetitions))
      print("Expected:", result)
      print("Computed:", digest.hex())
      errors += 1
  assert errors == 0

if __name__ == "__main__":
  test_long_hash(log_timing=False)

