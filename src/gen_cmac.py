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

import aes_cmac
import aria_cmac
import camellia_cmac
import cmac
import flag
import mac_test_vector
import producer
import util
from typing import Optional, List
import test_vector

IMPLEMENTATIONS = [
    aes_cmac.AesCmac, aria_cmac.AriaCmac, camellia_cmac.CamelliaCmac
]
ALGORITHMS = [alg.name for alg in IMPLEMENTATIONS]


# CVEs:
# CVE-2021-41117: Using AES-CMAC to generate pseudorandom bytes for RSA key
#     generation. The seed for this generator is strongly biased.
#     (CMAC is apparently OK).
# CVE-2020-15025: ntpd in ntp 4.2.8 before 4.2.8p15 and 4.3.x before 4.3.101
#     allows remote attackers to cause a denial of service (memory consumption)
#     by sending packets, because memory is not freed in situations where a CMAC
#     key is used and associated with a CMAC algorithm in the ntp.keys file.
#  CVE-2020-12788: CMAC verification functionality in Microchip Atmel ATSAMA5
#     products is vulnerable to vulnerable to timing and power analysis attacks.
#  CVE-2020-11683: A timing side channel was discovered in AT91bootstrap before
#     3.9.2.
#  CVE-2020-0117: In aes_cmac of aes_cmac.cc, there is a possible out of bounds
#      write due to an integer overflow.
#      Requires message sizes of about 2**16, hence not very feasible to check.
class CmacTestVectorGenerator(mac_test_vector.MacTestVectorGenerator):

  def __init__(self, algorithm: str, args):
    super().__init__(algorithm, args)
    for alg in IMPLEMENTATIONS:
      if alg.name == algorithm:
        self.cmac = alg
        break
    else:
      raise ValueError("Unknown algorithm:" + algorithm)
    self.block_size = self.cmac.block_cipher.block_size_in_bytes

  @util.type_check
  def mac(self, key: bytes, msg: bytes, mac_size_in_bytes: int) -> bytes:
    return self.cmac(key=key, macsize=mac_size_in_bytes).mac(msg)

  def generate_prand(self, key_sizes: List[int], tag_sizes: List[int]):
    """Generates pseudorandom test vectors

    Args:
      key_sizes: generates test vectors for these key sizes in bytes.
      tag_sizes: generates test vectors for these tag sizes in bytes.
    """
    # cnt, keysize, msgsize, tagsize
    self.generate_pseudorandom(1, key_sizes, [0], tag_sizes, "empty message")
    self.generate_pseudorandom(1, key_sizes, list(range(1, self.block_size)),
                               tag_sizes, "short message")
    self.generate_pseudorandom(1, key_sizes, [
        self.block_size, self.block_size + 1, self.block_size + 4,
        2 * self.block_size - 1, 2 * self.block_size
    ], tag_sizes, "")

  def generate_modified(self, key_sizes: List[int], tag_sizes: List[int]):
    """Generates test vectors with modified tags.

    Args:
      key_sizes: generates test vectors for these key sizes in bytes.
      tag_sizes: generates test vectors for these tag sizes in bytes.
    """
    for keysize in key_sizes:
      for tagsize in tag_sizes:
        key = bytes(range(keysize))
        for msgsize in (0, self.block_size // 2, self.block_size):
          msg = bytes(range(msgsize))
          self.generate_modified_tag(key, msg, tagsize)

  def generate_invalid_key_sizes(self, tag_sizes: List[int]):
    """Generates test vectors with modified tags.

    Args:
      key_sizes: generates test vectors for these key sizes in bytes.
      tag_sizes: generates test vectors for these tag sizes in bytes.
    """
    valid_key_sizes = self.cmac.block_cipher.key_sizes_in_bytes
    other_key_sizes = [0, 1, 8, 20, 40]
    invalid_key_sizes = [x for x in other_key_sizes if x not in valid_key_sizes]
    invalid_key_size = flag.Flag(
        label="InvalidKeySize",
        bug_type=flag.BugType.MISSING_STEP,
        description="The test vector contains a key with an invalid key size. "
        "Accepting such a key indicates an missing parameter verification.")
    for key_size in invalid_key_sizes:
      self.generate_pseudorandom(
          1, [key_size], [8],
          tag_sizes,
          f"invalid key of size {8 * key_size} bits",
          flags=[invalid_key_size])



  def generate_all(self,
                   key_sizes: Optional[List[int]] = None,
                   tag_sizes: Optional[List[int]] = None):
    """Generate test vectors for all test cases for the given algorithm.

    Args:
      key_sizes: generates test vectors for these key sizes in bytes. Default is
        the set of all valid key sizes of the underlying block cipher.
      tag_sizes: generates test vectors for these tag sizes in bytes. Default is
        the size of the block of the underlying block cipher.
    """
    valid_key_sizes = self.cmac.block_cipher.key_sizes_in_bytes
    if key_sizes is None:
      key_sizes = valid_key_sizes
    if tag_sizes is None:
      tag_sizes = [self.block_size]

    self.generate_prand(key_sizes, tag_sizes)
    self.generate_modified(key_sizes, [max(tag_sizes)])
    self.generate_invalid_key_sizes(tag_sizes[:2])


class CmacProducer(producer.Producer):
  def parser(self):
    res = self.default_parser()
    res.add_argument(
        "--algorithm",
        type=str,
        choices=ALGORITHMS,
        default="AES-CMAC",
        help="the CMAC algorithm")
    res.add_argument(
        "--key_sizes",
        type=int,
        choices=[128, 192, 256],
        nargs="+",
        help="a list of key sizes in bits")
    res.add_argument(
        "--mac_sizes",
        type=int,
        nargs="+",
        default=[128],
        help="a list of mac sizes in bits")
    return res

  def generate_test_vectors(self, namespace):
    algorithm = namespace.algorithm
    tv = CmacTestVectorGenerator(algorithm, namespace)
    key_sizes_in_bits = getattr(namespace, "key_sizes", None)
    if key_sizes_in_bits:
      key_sizes = [x // 8 for x in key_sizes_in_bits]
    else:
      key_sizes = None
    mac_sizes_in_bits = getattr(namespace, "mac_sizes", None)
    if mac_sizes_in_bits:
      for s in mac_sizes_in_bits:
        assert s % 8 == 0
        assert s <= 128
        assert s > 0
      mac_sizes = [x // 8 for x in namespace.mac_sizes]
    else:
      mac_sizes = None
    tv.generate_all(key_sizes, mac_sizes)
    return tv.test


# DEPRECATED: Use Producer.produce() instead
def main(namespace):
  CmacProducer().produce(namespace)


if __name__ == "__main__":
  CmacProducer().produce_with_args()
