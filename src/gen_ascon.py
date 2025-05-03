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
import aead_test_vector
import producer
import util
import flag

ALGORITHMS = ["ASCON128", "ASCON128A", "ASCON80PQ"]


class AsconTestGenerator(aead_test_vector.AeadTestGenerator):

  def __init__(self, args):
    super().__init__(args.algorithm, args)
    if args.algorithm == "ASCON128":
      self.aead = ascon.Ascon128
    elif args.algorithm == "ASCON128A":
      self.aead = ascon.Ascon128a
    elif args.algorithm == "ASCON80PQ":
      self.aead = ascon.Ascon80pq
    else:
      raise ValueError("Unknown algorithm:" + args.algorithm)

  def generate_known_vectors(self, keysizes: list[int], ivsizes: list[int]):
    # TODO: find test vectors from a reference implementation
    flag_ktv = flag.Flag(
        label="Ktv",
        bug_type=flag.BugType.BASIC,
        description="Known test vector.")
    known_tv = []
    for t in known_tv:
      key, nonce, aad, msg, ct, tag = [bytes.fromhex(x) for x in t]
      if len(key) in keysizes:
        self.add_vector(key, nonce, aad, msg, flags=[ktv])

  def generate_pseudorandom_vectors(self, keysizes: list[int],
                                    ivsizes: list[int]):
    pseudorandom = flag.Flag(
        label="Pseudorandom",
        bug_type=flag.BugType.FUNCTIONALITY,
        description="The test vector contains pseudorandomly generated inputs. "
        "The goal of the test vector is to check the correctness of the "
        "implementation for various sizes of the input parameters.")

    # cnt, keysize, ivsize, aadsize, msgsize
    # Tests all message sizes from 0 .. 33.
    # The rate of ASCON is 8 or 16. Hence this covers up to two blocks.
    self.generate_pseudorandom(
        1, keysizes, ivsizes, [0], list(range(34)), flags=[pseudorandom])
    # Tests all aad sizes from 0 .. 34.
    self.generate_pseudorandom(
        1, keysizes, ivsizes, list(range(34)), [16], flags=[pseudorandom])
    # longer message size
    self.generate_pseudorandom(
        1, keysizes, ivsizes, [0], [224, 255, 256, 257], flags=[pseudorandom])
    # longer aad size
    self.generate_pseudorandom(
        1, keysizes, ivsizes, [224, 255, 256, 257], [20], flags=[pseudorandom])
    self.generate_pseudorandom(
        1, keysizes, ivsizes, [63, 64, 65], [63, 64, 65], flags=[pseudorandom])

  def generate_modified(self, keysizes: list[int], ivsizes: list[int]):
    for keysize in keysizes:
      for ivsize in ivsizes:
        key = bytes(range(keysize))
        nonce = bytes(range(80, 80 + ivsize))
        aad = bytes()
        for msg in [bytes(range(n)) for n in [0, 15, 16, 17]]:
          self.generate_modified_tag(key, nonce, aad, msg)

  def generate_all(self, args):
    # TODO: Add special cases
    #  - if the key is known then special case states can be forced.
    #  - it the key is known then the tag can be forced.
    keysizes = [self.aead.key_len]
    ivsizes = [self.aead.iv_len]
    self.generate_known_vectors(keysizes, ivsizes)
    self.generate_pseudorandom_vectors(keysizes, ivsizes)
    self.generate_modified(keysizes, ivsizes)


class AsconProducer(producer.Producer):

  def parser(self):
    res = self.default_parser()
    res.add_argument(
        "--algorithm",
        type=str,
        choices=ALGORITHMS,
        default="ASCON128",
        help="the name of the algorithm")
    return res

  def generate_test_vectors(self, namespace):
    tv = AsconTestGenerator(namespace)
    tv.generate_all(namespace)
    return tv.test


# DEPRECATED: Use Producer.produce() instead
def main(namespace):
  AsconProducer().produce(namespace)


if __name__ == "__main__":
  AsconProducer().produce_with_args()
