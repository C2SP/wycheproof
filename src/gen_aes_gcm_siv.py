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
import aes_gcm_siv
import aes_gcm_siv_tests
import producer
import util
import flag
from typing import Optional

AesGcmSiv = aes_gcm_siv.AesGcmSiv

class AesGcmSivTestGenerator(aead_test_vector.AeadTestGenerator):
  def __init__(self, args):
    super().__init__("AES-GCM-SIV", args)

  aead = aes_gcm_siv.AesGcmSiv

  def generate_prand(self):
    pseudorandom = flag.Flag(
        label="Pseudorandom",
        bug_type=flag.BugType.FUNCTIONALITY,
        description="The test vector contains pseudorandomly generated inputs. "
        "The goal of the test vector is to check the correctness of the "
        "implementation for various sizes of the input parameters. "
        "Some libraries do not support all the parameter sizes. ")
    key_sizes = [16, 32]
    iv_sizes = [12]
    # Pseudorandom test vectors
    self.generate_pseudorandom(1, key_sizes, iv_sizes, [0],
                          [0, 1, 8, 15, 16, 17, 24, 32], flags=[pseudorandom])
    self.generate_pseudorandom(1, key_sizes, iv_sizes,
                          [1, 2, 15, 16, 17, 32], [16], flags=[pseudorandom])
    # longer input sizes
    longer_sizes = [63, 64, 65, 127, 128, 129, 255, 256, 257, 511, 512, 513]
    self.generate_pseudorandom(1, key_sizes, iv_sizes,
                           longer_sizes, [16], flags=[pseudorandom])
    self.generate_pseudorandom(1, key_sizes, iv_sizes,
                           [0], longer_sizes, flags=[pseudorandom])


  def generate_wrap(self):
    # AES-GCM-SIV increments the counters modulo 2^32.
    # The following test vectors check this behaviour.
    wrap = flag.Flag(
      label="WrappedIv",
      bug_type=flag.BugType.MISSING_STEP,
      description="The counter for AES-GCM-SIV is reduced modulo 2**32. "
      "This test vector was constructed to test for correct wrapping "
      "of the counter.")

    for key_hex in ("00112233445566778899aabbccddeeff",
                  "000102030405060708090a0b0c0d0e0f"
                  "101112131415161718191a1b1c1d1e1f"):
      key = bytes.fromhex(key_hex)
      A = AesGcmSiv(key)
      for hex_tag in ("00000000000000000000000000000000",
                    "ffffffffffffffffffffffffffffffff",
                    "fefffffffefffffffefffffffeffffff",
                    "ffffff7f00112233445566778899aabb",
                    "ffffffffffffff7f0011223344556677"):
        tag = bytes.fromhex(hex_tag)
        ct = bytes(48)
        for i in range(16):
          N = bytes([i]) * 12
          AP = A.find_data_and_plaintext(N, ct, tag)
          if AP:
            aad, pt = AP
            self.add_vector(
              key, N, aad, pt, comment="Testing for ctr overflow", flags=[wrap])
            break

  def generate_ktv(self):

    # self.add_vector(key, iv, aad, msg, ct, tag, comment, valid, tagsize, flags)
    flag_ktv = flag.Flag(
        label="Ktv",
        bug_type=flag.BugType.BASIC,
        description="Known test vector.")

    # From draft
    comment = aes_gcm_siv_tests.get_test_vectors_ref()
    for test in aes_gcm_siv_tests.get_test_vectors():
      self.add_vector(
        bytes.fromhex(test["Key"]),
        bytes.fromhex(test["Nonce"]),
        bytes.fromhex(test["AAD"]),
        bytes.fromhex(test["Plaintext"]),
        bytes.fromhex(test["Result"]),
        bytes.fromhex(test["Tag"]),
        comment=comment,
        flags=[flag_ktv])

  def generate_modified_tag(self):
    modified_tag = flag.Flag(
        label="ModifiedTag",
        bug_type=flag.BugType.CAN_OF_WORMS,
        description="The test vector contains a ciphertext such that "
        "the actual and computed tag differ slightly. "
        "The goal of this test vector is to detect incomplete tag "
        "verification.",
        effect="The construction of the test vector requires the knowledge "
        "of the key, because any modification of the tag modifies "
        "the plaintext. Therefore, it is unclear whether an incomplete "
        "verification is exploitable.")

    def flip_bit(b: bytes, pos: int) -> bytes:
      ba = bytearray(b)
      byte, bit = divmod(pos, 8)
      ba[byte] ^= 1 << bit
      return bytes(ba)
      
    def inverse(b: bytes):
      return bytes(x ^ 0xff for x in b)

    for key_hex in ("00112233445566778899aabbccddeeff",
                  "00112233445566778899aabbccddeeff"
                  "00112233445566778899aabbccddeeff"):
      key = bytes.fromhex(key_hex)
      A = AesGcmSiv(key)
      for modified_bit in (0, 1, 7, 8, 31, 32, 56, 63, 64, 88, 96, 97, 120, 121,
                         126, 127, "0..127"):
        for ct, actual_tag in [
          (bytes(), bytes.fromhex("0987e35e40981a2730c1740c7201731f")),
          (bytes(16), bytes.fromhex("13a1883272188b4c8d2727178198fe95")),
          (bytes(8), bytes(16)),
          (bytes([0xff]) * 8, bytes([0xff]) * 16),
        ]:
          N = bytes(12)
          if modified_bit == "0..127":
            correct_tag = inverse(actual_tag)
          else:
            correct_tag = flip_bit(actual_tag, modified_bit)
          AP = A.find_modified_tag(N, ct, actual_tag, correct_tag)
          if AP:
            aad, pt = AP
            comment=f"Flipped bit {modified_bit} in tag"
            self.add_vector(
              key,
              N,
              aad,
              pt,
              ct,
              actual_tag,
              comment=comment,
              flags=[modified_tag])

  def generate_all(self):
    #   - Test vectors with invalid tags.
    #     I.e. we need test vectors where polyval(decrypted)
    #     are close to the tag provided in the test vector.
    #   - Test vectors with truncated tags?
    self.generate_ktv()
    self.generate_prand()
    self.generate_wrap()
    self.generate_modified_tag()


class AesGcmSivProducer(producer.Producer):

  def parser(self):
    res = self.default_parser()
    res.add_argument(
        "--key_sizes",
        type=int,
        choices=[128, 256],
        nargs="+",
        help="a list of key sizes in bits")
    return res

  def generate_test_vectors(self, namespace):
    tv = AesGcmSivTestGenerator(namespace)
    tv.generate_all()
    return tv.test


# DEPRECATED: Use AesEaxProducer.produce() instead
def main(namespace):
  AesGcmSivProducer().produce(namespace)


if __name__ == "__main__":
  AesGcmSivProducer().produce_with_args()
