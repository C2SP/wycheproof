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

import aead_test_vector
import util
import flag

class AegisCommonTestGenerator(aead_test_vector.AeadTestGenerator):
  def __init__(self, algorithm:str, args):
    super().__init__(algorithm, args)

  def generate_prand(self):
    keysizes = [self.keysize]
    ivsizes = [self.ivsize]
    pseudorandom = flag.Flag(
        label="Pseudorandom",
        bug_type=flag.BugType.FUNCTIONALITY,
        description="The test vector contains pseudorandomly generated inputs. "
        "The goal of the test vector is to check the correctness of the "
        "implementation for various sizes of the input parameters. "
        "Some libraries do not support all the parameter sizes. ")
    # cnt, keysize, ivsize, aadsize, msgsize
    # Tests all message sizes from 0 .. 161. The range is quite large, since
    # vectorizing AEGIS128L using AVX-512 should give performance benefits.
    # At the same time this also means that errors occuring for messages
    # longer than a couple of registers are quite plausible.
    self.generate_pseudorandom(1, keysizes, ivsizes, [0], list(range(162)),
        flags=[pseudorandom])
    # Tests all aad sizes from 0 .. 161.
    self.generate_pseudorandom(1, keysizes, ivsizes, list(range(162)), [16],
        flags=[pseudorandom])
    # longer message size
    self.generate_pseudorandom(1, keysizes, ivsizes, [0],
      [223, 224, 225, 255, 256, 257, 511, 512, 513],
        flags=[pseudorandom])
    # longer aad size
    self.generate_pseudorandom(1, keysizes, ivsizes,
      [223, 224, 225, 255, 256, 257, 511, 512, 513], [20],
        flags=[pseudorandom])
    self.generate_pseudorandom(1, keysizes, ivsizes, [63, 64, 65], [63, 64, 65],
        flags=[pseudorandom])

  def generate_modified(self):
    # modified tags
    key = bytes(range(self.keysize))
    nonce = bytes(range(80, 80 + self.ivsize))
    aad = bytes()
    for msg in [bytes(range(n)) for n in [0, 15, 16, 17]]:
      self.generate_modified_tag(key, nonce, aad, msg)


  def generate_known_tv(self, known_tv):
    ktv = flag.Flag(
      label="Ktv",
      bug_type=flag.BugType.BASIC,
      description="Known test vector.")
    for t in known_tv:
      key, nonce, aad, msg, ct, tag = [bytes.fromhex(x) for x in t]
      self.add_vector(key, nonce, aad, msg, flags=[ktv])

