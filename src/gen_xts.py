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

import aes_xts
import sm4_xts
import ind_cpa_vector
import producer
import test_vector
from typing import Optional
import util
import prand
import flag

ALGORITHMS = [
    "AES-XTS",
    "SM4-XTS",
]


class XtsTestVectorGenerator(ind_cpa_vector.IndCpaTestVectorGenerator):

  def __init__(self, algorithm: str):
    super().__init__()
    self.algorithm = algorithm
    self.test = test_vector.Test(self.algorithm)
    if self.algorithm == "AES-XTS":
      self.cipher = aes_xts.AesXts
    elif self.algorithm == "SM4-XTS":
      self.cipher = sm4_xts.Sm4Xts
    else:
      raise ValueError("Unsupported algorithm:" + algorithm)
    self.block_size = self.cipher.block_cipher.block_size_in_bytes
    keysizes = self.cipher.block_cipher.key_sizes_in_bytes
    self.key_sizes_in_bytes = [2 * x for x in keysizes]

  def encrypt(self, key: bytes, iv: bytes, msg: bytes) -> bytes:
    c = self.cipher(key)
    seq_nr = int.from_bytes(iv, "little")
    return c.encrypt(msg, seq_nr)

  def decrypt(self, key: bytes, iv: bytes, msg: bytes) -> bytes:
    c = self.cipher(key)
    seq_nr = int.from_bytes(iv, "little")
    return c.decrypt(msg, seq_nr)

  def generate_pseudorandom_tests(self, keysizes: list[int]):
    """Generates pseudorandom test vectors.

    The message size for XTS must be at least the size of a block.
    The IV is also called a sequence number. XTS uses little endian encoding of
    the sequence number. the
    """
    pseudorandom = flag.Flag(
        label="Pseudorandom",
        bug_type=flag.BugType.FUNCTIONALITY,
        description="The test vector contains pseudorandomly generated inputs. "
        "The goal of the test vector is to check the correctness of the "
        "implementation for various sizes of the input parameters. "
        "Of course a main goal is to check the the correctness of the "
        "ciphertext stealing.")

    # Format:
    # self.generate_pseudorandom(cnt, keysizes, noncesizes, msgsizes, comment)
    # The minimal message size is the size of the block cipher
    ivsizes = [8]
    for msg_size in range(self.block_size, 2 * self.block_size + 2):
      self.generate_pseudorandom(
          1,
          keysizes,
          ivsizes, [msg_size],
          f"message size = {msg_size}",
          flags=[pseudorandom])
    for i in (3, 4, 6, 8):
      for msg_size in [i * self.block_size, i * (self.block_size + 1)]:
        self.generate_pseudorandom(
            1,
            keysizes,
            ivsizes, [msg_size],
            f"message size = {msg_size}",
            flags=[pseudorandom])
    for iv_size in list(range(1, self.block_size + 1)):
      self.generate_pseudorandom(
          1,
          keysizes, [iv_size], [2 * self.block_size],
          f"iv size = {iv_size} bytes",
          flags=[pseudorandom])

  def generate_all(self, keysizes: Optional[list[int]] = None):
    if keysizes:
      keysizes = [x // 8 for x in keysizes]
    else:
      keysizes = list(self.key_sizes_in_bytes)
    self.generate_pseudorandom_tests(keysizes)


class XtsProducer(producer.Producer):

  def parser(self):
    res = self.default_parser()
    res.add_argument(
        "--key_sizes", type=int, nargs="+", help="a list of key sizes in bits")
    res.add_argument(
        "--algorithm",
        type=str,
        choices=ALGORITHMS,
        default="AES-XTS",
        help="the algorithm")
    return res

  def generate_test_vectors(self, namespace):
    algorithm = getattr(namespace, "algorithm", "AES-XTS")
    key_sizes = getattr(namespace, "key_sizes", None)
    tv = XtsTestVectorGenerator(algorithm)
    tv.generate_all(key_sizes)
    return tv.test


# DEPRECATED: Use Producer.produce() instead
def main(namespace):
  XtsProducer().produce(namespace)


if __name__ == "__main__":
  XtsProducer().produce_with_args()
