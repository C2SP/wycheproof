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

import aes_siv
import aes_siv_test
import daead_test_vector
import flag
import producer
import test_generation
import util
from typing import Optional

class AesSivTestGenerator(daead_test_vector.DaeadTestGenerator):
  def __init__(self, args):
    super().__init__("AES-SIV-CMAC", args)

  def daead_cipher(self, key):
    return aes_siv.AesSiv(key)

  @util.type_check
  def add_known_vectors(self,
                        keysizes: list[int],
                        flags: Optional[list[flag.Flag]] = None):
    if flags is None:
      ktv = flag.Flag(
          label="Ktv",
          bug_type=flag.BugType.BASIC,
          description="Known test vector from RFC 5297")
      flags = [ktv]
    flags = self.add_flags(flags)
    for v in aes_siv_test.KTV:
      if len(v["aads"]) == 1:
        key = bytes.fromhex(v["key"])
        if len(key) not in keysizes:
          continue
        test = daead_test_vector.DaeadTestVector()
        test.key = key
        test.msg = bytes.fromhex(v["msg"])
        test.aad = bytes.fromhex(v["aads"][0])
        test.comment = v["comment"]
        test.result = "valid"
        test.ct = bytes.fromhex(v["ct"])
        test.flags = flags
        self.add_test(test)

  def generate_edge_cases_siv(self, keysizes: list[int]):
    edge_case_siv = flag.Flag(
        label="EdgeCaseSiv",
        bug_type=flag.BugType.EDGE_CASE,
        description="The SIV of this test vector has an edge case value. "
        "One purpose of these test vectors is to detect implementations "
        "where integer overflows of the counter is incorrectly implemented. "
        "AES-SIV itself prevents such overflow problems by clearing "
        "some msbs in the IV.")
    for keysize in keysizes:
      key = bytes(range(keysize))
      cipher = aes_siv.AesSiv(key)
      for siv in [
          bytes([0]*16),
          bytes([0xff]*16),
          bytes([0xff]*12+[0x7f]+[0xff]*3),
          bytes([0xff]*8+[0x7f]+[0xff]*7),
          bytes([0xff]*15+[0xfe])]:
        for aadsize in [0,16]:
          aad = bytes(range(aadsize))
          msg = cipher.s2v_find_plaintext(siv, aad)
          self.add_daead(key, aad, msg, comment="edge case SIV",
             flags=[edge_case_siv])

  @util.type_check
  def modify_tag(self,
                 key: bytes,
                 aad: bytes,
                 msg: bytes,
                 flags: Optional[list[flag.Flag]] = None):
    """Generates test vectors so that the SIV in the ciphertext and
       S2V(decrypted ciphertext, aad) has defined difference (e.g., they differ
       in just 1-bit).
       The main purpose of these test vectors is to detect sloppy tag
       verification."""
    if flags is None:
      modified_tag = flag.Flag(
          label="ModifiedTag",
          bug_type=flag.BugType.CAN_OF_WORMS,
          description="The test vector contains a ciphertext where the actual "
          "tag (rsp. SIV) and the expected tag have a small difference. "
          "The goal of this test vector is to detect incomplete tag "
          "verification.",
          effect="The construction of the test vector requires the knowledge "
          "of the key, because any modification of the tag (rsp. SIV) modifies "
          "the plaintext. Therefore, it is unclear whether an incomplete tag "
          "verification is directly exploitable. This needs further analysis.")
      flags = [modified_tag]
    cipher = aes_siv.AesSiv(key)
    siv = cipher.s2v(msg, aad)
    for siv2, comment in test_generation.modify_tag(siv):
      ct = siv2 + cipher.ctr_crypt(siv, msg)
      test = daead_test_vector.DaeadTestVector()
      test.key = bytes(key)
      test.msg = bytes(msg)
      test.aad = bytes(aad)
      test.comment = comment
      test.result = "invalid"
      test.ct = ct
      test.flags = self.add_flags(flags)
      self.add_test(test)

  def generate_modified_tags(self, keysizes):
    """Generates test vectors so that the SIV in the ciphertext and
       S2V(decrypted ciphertext, aad) has defined difference (e.g., they differ
       in just 1-bit)."""
    for keysize in keysizes:
      key = bytes(range(keysize))
      aad = bytes()
      for msg_size in [0, 8, 16, 20]:
        self.modify_tag(key, aad, bytes(range(48, 48 + msg_size)))

  def generate_pseudorandom_tests(self, keysizes):
    """Generates pseudorandom test vectors.
       Some reasons for the selection are:
       AES-SIV uses a different padding for plaintexts < 16 bytes than
       for plaintexts >= 16 bytes. CMAC paddings are different for input
       sizes divisible by 16 bytes than for others.
    """
    # Format:
    # self.generate_pseudorandom(cnt, keysizes, msgsizes, aadsizes, comment)
    # TODO: reorder arguments to the usual aadsizes, msgsizes.
    self.generate_pseudorandom(1, keysizes, [0], [0, 12, 15, 16, 20, 32],
                               "empty message")
    self.generate_pseudorandom(1, keysizes, [16, 32, 48], [16],
                               "message size divisible by block size")
    self.generate_pseudorandom(1, keysizes, list(range(1,16)), [12],
                               "small plaintext size")
    self.generate_pseudorandom(1, keysizes, [17, 20, 31, 40, 80], [12],
                               "plaintext size > 16")
    longer_sizes = [127, 128, 129, 255, 256, 257, 511, 512, 513]
    self.generate_pseudorandom(1, keysizes, longer_sizes, [0],
                               "longer message size")
    self.generate_pseudorandom(1, keysizes, [16], longer_sizes,
                               "longer aad size")

  def generate_all(self, keysizes):
    self.add_known_vectors(keysizes)
    self.generate_pseudorandom_tests(keysizes)
    self.generate_edge_cases_siv(keysizes)
    self.generate_modified_tags(keysizes)


class AesSivProducer(producer.Producer):

  def parser(self):
    res = self.default_parser()
    res.add_argument(
        "--key_sizes",
        type=int,
        choices=[256, 384, 512],
        nargs="+",
        help="a list of key sizes in bits")
    return res

  def generate_test_vectors(self, namespace):
    if getattr(namespace, "key_sizes", None):
      key_sizes = [x // 8 for x in namespace.key_sizes]
    else:
      key_sizes = [32, 48, 64]
    tv = AesSivTestGenerator(namespace)
    tv.generate_all(key_sizes)
    return tv.test


# DEPRECATED: Use the producer directly
def main(namespace):
  AesSivProducer().produce(namespace)


if __name__ == "__main__":
  AesSivProducer().produce_with_args()
