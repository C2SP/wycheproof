# Copyright 2017 Google Inc. All Rights Reserved.
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
# ==============================================================================

# Run as:
#   sage -python aes_gcm_test.py

import binascii
import aes_gcm


class TestVector(object):

  def __init__(self, key, iv, a, p, c, t):
    self.key = binascii.unhexlify(key)
    self.iv = binascii.unhexlify(iv)
    self.a = binascii.unhexlify(a)
    self.p = binascii.unhexlify(p)
    self.c = binascii.unhexlify(c)
    self.t = binascii.unhexlify(t)


test_vectors = [
    TestVector('00000000000000000000000000000000', '000000000000000000000000',
               '', '', '', '58e2fccefa7e3061367f1d57a4e7455a'),
    TestVector('00000000000000000000000000000000', '000000000000000000000000',
               '', '00000000000000000000000000000000',
               '0388dace60b6a392f328c2b971b2fe78',
               'ab6e47d42cec13bdf53a67b21257bddf'),
    TestVector(
        'feffe9928665731c6d6a8f9467308308', 'cafebabefacedbad',
        'feedfacedeadbeeffeedfacedeadbeefabaddad2',
        'd9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0'
        'c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39',
        '61353b4c2806934a777ff51fa22a4755699b2a714fcdc6f83766e5f97b6c742373806'
        '900e49f24b22b097544d4896b424989b5e1ebac0f07c23f4598',
        '3612d2e79e3b0785561be14aaca2fccb'),
]


def test_test_vectors():
  for test in test_vectors:
    gcm = aes_gcm.AesGcm(test.key)
    c, t = gcm.encrypt(test.iv, test.a, test.p)
    assert test.c == c
    assert test.t == t
    p = gcm.decrypt(test.iv, test.a, test.c, test.t)
    assert test.p == p
    try:
      gcm.decrypt(test.iv, test.a, test.c + '\x00', test.t)
      assert False
    except ValueError:
      return


if __name__ == '__main__':
  test_test_vectors()
