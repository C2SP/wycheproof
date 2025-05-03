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

import aes_modes
import aria_modes
import camellia_modes
import ind_cpa_vector
import producer
from collections.abc import Iterator
import test_vector
from typing import Optional
import util
import prand
import flag

ALGORITHMS = ["AES-CBC-PKCS5",
              "ARIA-CBC-PKCS5",
              "CAMELLIA-CBC-PKCS5",
]

class CbcPkcs5TestVectorGenerator(ind_cpa_vector.IndCpaTestVectorGenerator):
  def __init__(self, algorithm: str):
    super().__init__()
    self.algorithm = algorithm
    self.test = test_vector.Test(self.algorithm)
    if self.algorithm == "AES-CBC-PKCS5":
      self.cipher = aes_modes.AesCbcPkcs5
    elif self.algorithm == "ARIA-CBC-PKCS5":
      self.cipher = aria_modes.AriaCbcPkcs5
    elif self.algorithm == "CAMELLIA-CBC-PKCS5":
      self.cipher = camellia_modes.CamelliaCbcPkcs5
    else:
      raise ValueError("Unsupported algorithm:" + algorithm)
    self.block_size = self.cipher.block_cipher.block_size_in_bytes

  def check_padding(self, ba: bytes) -> bool:
    if len(ba) == 0:
      return False
    padlen = ba[-1]
    if (len(ba) % self.block_size == 0
        and 1 <= padlen <= self.block_size
        and len(ba) >= padlen):
      for i in range(1, padlen+1):
        if ba[-i] != padlen:
          return False
      return True
    return False

  @util.type_check
  # TODO: add generator type
  def invalid_paddings(self, msg: bytes) -> Iterator[tuple[bytes, str]]:
    padlen = self.block_size - (len(msg) % self.block_size)
    if len(msg) % self.block_size == 0 and not self.check_padding(msg):
      yield msg, "Using no padding at all"
    yield (msg + bytes([0]*padlen),
      "Using zero padding instead of PKCS #5 padding")
    yield (msg + bytes([255]*padlen), "Using a padding with 0xff instead of PKCS #5 padding")
    yield (msg + bytes([128]+[0]*(padlen-1)), "Using ISO/IEC 7816-4 padding instead of PKCS #5 padding")
    invalid_padlen = padlen + self.block_size
    yield (msg + bytes([invalid_padlen]*(invalid_padlen)),
           "The length of the padding is longer than 1 block")
    if padlen > 1:
      (yield msg + bytes([0]*(padlen-1) + [padlen]),
        "Using ANSI X.923 padding instead of PKCS #5 padding")
    if padlen > 1:
      pad = prand.randbytes(padlen, seed="adfa")
      pad = bytearray(pad)
      pad[-1] = padlen
      if pad == bytearray([padlen])*padlen:
        pad[0] ^= 0x01
      yield (msg + bytes(pad), "Using ISO 10126 padding instead of PKCS #5 padding")
    longpad = len(msg) + padlen + self.block_size
    if longpad < 256:
      yield msg + bytes([longpad]*padlen), "Padding is longer than the message"
    yield (msg + bytes([0] + [padlen]*(padlen-1)),
      "Invalid PKCS #5 padding")


  def generate_invalid_paddings(self, keysizes: list[int]):
    badpad = flag.Flag(
       label="BadPadding",
       bug_type=flag.BugType.MISSING_STEP,
       description="The ciphertext in this test vector is the message "
       "encrypted without a correct PKCS #5 padding. The goal is to find "
       "implementations that accept alternative paddings and implementations "
       "that are not properly checking the padding during decryption.")
    for keysize in keysizes:
      key = prand.randbytes(keysize, seed="18736918643uyid", label=str(keysize))
      iv = prand.randbytes(
          self.block_size, seed="18738712631", label=str(keysize))
      for msg in [
          b"",
          b"abcdefgh",
          b"0123456789abcde",
          b"0123456789ABCDEF",
          b"0123456789ABCDEFG",
          bytes(range(64, 96))]:
        for padding, comment in self.invalid_paddings(msg):
          cipher = self.cipher(key)
          invalid_ct = cipher.encrypt_nopadding(iv, padding)
          self.add_ind_cpa(key, iv, msg, invalid_ct, comment, flags=[badpad])

  def generate_pseudorandom_tests(self, keysizes: list[int], ivsizes: list[int]):
    """Generates pseudorandom test vectors.
       Some reasons for the selection are:
       Plaintext with a size that is a multiple of the block size add a new
       block. CBC should always be used with a nonce of size 16.
    """
    pseudorandom = flag.Flag(
        label="Pseudorandom",
        bug_type=flag.BugType.FUNCTIONALITY,
        description="The test vector contains pseudorandomly generated inputs. "
        "The goal of the test vector is to check the correctness of the "
        "implementation for various sizes of the input parameters.")

    # Format:
    # self.generate_pseudorandom(cnt, keysizes, noncesizes, msgsizes, comment)
    self.generate_pseudorandom(1, keysizes, ivsizes, [0], "empty message", flags=[pseudorandom])
    self.generate_pseudorandom(1, keysizes, ivsizes, [self.block_size * i for i in (1,2,3)],
                               "message size divisible by block size", flags=[pseudorandom])
    self.generate_pseudorandom(1, keysizes, ivsizes, list(range(1,self.block_size)),
                               "small plaintext size", flags=[pseudorandom])
    self.generate_pseudorandom(1, keysizes, ivsizes,
                               [self.block_size + 1,
                                self.block_size + 4,
                                2 * self.block_size - 1,
                                5 * self.block_size // 2,
                                5 * self.block_size],
                               "plaintext size > %d" % self.block_size, flags=[pseudorandom])

  def generate_all(self, keysizes: Optional[list[int]] = None):
    if keysizes:
      keysizes = [x // 8 for x in keysizes]
    else:
      keysizes = list(self.cipher.block_cipher.key_sizes_in_bytes)
    ivsizes = [self.block_size]
    self.generate_pseudorandom_tests(keysizes, ivsizes)
    self.generate_invalid_paddings(keysizes)


class CbcPkcs5Producer(producer.Producer):

  def parser(self):
    res = self.default_parser()
    res.add_argument(
        "--key_sizes",
        type=int,
        choices=[128, 192, 256],
        nargs="+",
        help="a list of key sizes in bits")
    res.add_argument(
        "--algorithm",
        type=str,
        choices=ALGORITHMS,
        default="AES-CBC-PKCS5",
        help="the algorithm")
    return res

  def generate_test_vectors(self, namespace):
    algorithm = getattr(namespace, "algorithm", "AES-CBC-PKCS5")
    key_sizes = getattr(namespace, "key_sizes", None)
    tv = CbcPkcs5TestVectorGenerator(algorithm)
    tv.generate_all(key_sizes)
    return tv.test


# DEPRECATED: Use Producer.produce() instead
def main(namespace):
  CbcPkcs5Producer().produce(namespace)


if __name__ == "__main__":
  CbcPkcs5Producer().produce_with_args()
