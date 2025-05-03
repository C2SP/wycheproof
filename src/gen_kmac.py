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

import keccak
import mac_test_vector
import producer
import flag
import util
from typing import Optional
import test_vector

ALGORITHMS = ["KMAC128", "KMAC256"]

# KMAC128 and KMAC256 are defined in Section 4 of
# https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf
# Section 8.4.1 and Section 8.4.2 discuss the key length and
# output length.
# Security strength is in Section 8.1
# KMAC128 has 128 bit security (unless small parameters are used).
#   (i.e. comparable to AES-CMAC)
# KMAC256 has 256 bit security (unless small parameters are used).
#   (i.e. comparable to HMACSHA256)
# KMAC output (for macs) must not be smaller than 32 bits and unless it
#   is a special case should not be smaller than 64 bits. 
#
class KmacTestVectorGenerator(mac_test_vector.MacTestVectorGenerator):
  """Generates test vectors for KMAC without customization.
  
  Some libraries only implement KMAC without customization. This is
  probably done so that KMAC can replace other MACs.
  """

  def __init__(self, algorithm: str, args):
    super().__init__(algorithm, args)
    if algorithm == "KMAC128":
      self.kmac = keccak.KMAC128
    elif algorithm == "KMAC256":
      self.kmac = keccak.KMAC256
    else:
     raise ValueError("Invalid algorithm name")

  @util.type_check
  def mac(self, key: bytes, msg: bytes, macsize: int = None) -> bytes:
    return self.kmac(key, msg, macsize)

  def generate_prand(self, key_sizes, mac_sizes, try_more_key_sizes):
    # cnt, keysize, msgsize, macsize
    self.generate_pseudorandom(1, key_sizes, [0], mac_sizes, "empty message")
    self.generate_pseudorandom(1, key_sizes, list(range(1, 16)), mac_sizes,
                           "short message")
    self.generate_pseudorandom(1, key_sizes, [16, 17, 24, 32], mac_sizes, "")
    self.generate_pseudorandom(1, key_sizes, [47, 48, 49, 112, 127, 128, 255],
                           mac_sizes, "long message")
    if try_more_key_sizes:
      self.generate_pseudorandom(1, [65, 129], [0, 16, 32], mac_sizes, "long key")

  def generate_modified(self, key_sizes, mac_sizes):
    for keysize in key_sizes:
      key = bytes(range(keysize))
      for mac_size in mac_sizes:
        for msgsize in (0, 16):
          msg = bytes(range(msgsize))
          self.generate_modified_tag(key, msg, mac_size)


def generate(namespace):
  alg = namespace.algorithm
  if getattr(namespace, "key_sizes", None):
    key_sizes = [x // 8 for x in namespace.key_sizes]
    try_more_key_sizes = False
  else:
    key_sizes = [32]
    try_more_key_sizes = True
  if getattr(namespace, "tag_sizes", None):
    tag_sizes = namespace.tag_sizes
    if any(size % 8 != 0 or size <= 32 for size in tag_sizes):
      raise ValueError("Tag sizes must be multiples of 8 and bigger than 32")
    mac_sizes = [size // 8 for size in tag_sizes]
  else:
    mac_sizes = [16]
  tv = KmacTestVectorGenerator(alg, namespace)
  tv.generate_prand(key_sizes, mac_sizes, try_more_key_sizes)
  tv.generate_modified(key_sizes, mac_sizes)
  return tv.test



class KmacProducer(producer.Producer):

  def parser(self):
    res = self.default_parser()
    res.add_argument(
        "--key_sizes", type=int, nargs="+", help="a list of key sizes in bits")
    res.add_argument(
        "--algorithm",
        type=str,
        choices=ALGORITHMS,
        help="the KMAC variant")
    res.add_argument(
        "--tag_sizes",
        type=int,
        nargs="+",
        help="a list of tag sizes in bits (default is [md_size, md_size//2] )")
    return res

  def generate_test_vectors(self, namespace):
    return generate(namespace)


# DEPRECATED: Use Producer.produce() instead
def main(namespace):
  KmacProducer().produce(namespace)


if __name__ == "__main__":
  KmacProducer().produce_with_args()
