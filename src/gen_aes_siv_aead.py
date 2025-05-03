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
import aead_test_vector
import producer
import test_generation
import flag

class AesSivAeadTestGenerator(aead_test_vector.AeadTestGenerator):
  aead = aes_siv.AesSiv

  def __init__(self, args):
    super().__init__("AEAD-AES-SIV-CMAC", args)

  def add_known_vectors(self, keysizes):
    flag_ktv = flag.Flag(
        label="Ktv",
        bug_type=flag.BugType.BASIC,
        description="Known test vector.",
        links=["RFC 5297"])
    for v in aes_siv_test.KTV:
      if len(v["aads"]) == 2:
        key = bytes.fromhex(v["key"])
        msg = bytes.fromhex(v["msg"])
        aad = bytes.fromhex(v["aads"][0])
        iv = bytes.fromhex(v["aads"][1])
        ct = bytes.fromhex(v["ct"])
        tag = ct[:16]
        ct_raw = ct[16:]
        self.add_vector(
            key,
            iv,
            aad,
            msg,
            ct,
            tag,
            comment=comment,
            valid="valid",
            flags=[ktv])

  def generate_edge_cases_siv(self, keysizes, ivsizes):
    edge_case_siv = flag.Flag(
        label="EdgeCaseSiv",
        bug_type=flag.BugType.MISSING_STEP,
        description="The SIV of this test vector has an edge case value. "
        "One purpose of these test vectors is to detect implementations "
        "where integer overflows of the counter is incorrectly implemented. "
        "AES-SIV itself prevents such overflow problems by clearing "
        "some msbs in the IV.")
    for ivsize in ivsizes:
      iv = bytes(range(ivsize))
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
            msg = cipher.s2v_find_plaintext(siv, aad, iv)
            self.add_vector(key, iv, aad, msg, ct=None, tag=None,
                            comment="edge case SIV",
                            valid="valid",
                            flags=[edge_case_siv])

  def modify_tag(self, key, iv, aad, msg):
    """Generates test vectors so that the SIV in the ciphertext and

       S2V(decrypted ciphertext, aad) has defined difference (e.g., they differ
       in just 1-bit).
       The main purpose of these test vectors is to detect sloppy tag
       verification.
    """
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
    cipher = aes_siv.AesSiv(key)
    siv = cipher.s2v(msg, aad, iv)
    for siv2, comment in test_generation.modify_tag(siv):
      ct = cipher.ctr_crypt(siv, msg)
      self.add_vector(
          key,
          iv,
          aad,
          msg,
          ct,
          siv2,
          comment=comment,
          valid="invalid",
          flags=[modified_tag])

  def generate_modified_tags(self, keysizes, ivsizes):
    """Generates test vectors so that the SIV in the ciphertext and
       S2V(decrypted ciphertext, aad) has defined difference (e.g., they differ
       in just 1-bit)."""
    for keysize in keysizes:
      for ivsize in ivsizes:
        key = bytes(range(keysize))
        iv = bytes(range(ivsize))
        aad = bytes()
        for msg_size in [0, 8, 16, 20]:
          self.modify_tag(key, iv, aad, bytes(range(48, 48 + msg_size)))

  def generate_pseudorandom_vectors(self, key_sizes, iv_sizes):
    """Generates pseudorandom test vectors.

       keysizes is the list of valid keysizes.
       iv_sizes is a default list for the iv sizes.
       I.e. other iv_sizes are tried too.
    """
    pseudorandom = flag.Flag(
        label="Pseudorandom",
        bug_type=flag.BugType.FUNCTIONALITY,
        description="The test vector contains pseudorandomly generated inputs. "
        "The goal of the test vector is to check the correctness of the "
        "implementation for various sizes of the input parameters. "
        "Because of the S2V constrution it is possible to use IVs longer "
        "than a block size.")

    # cnt, keysize, ivsize, msgsize, aadsize
    self.generate_pseudorandom(
        1,
        key_sizes,
        iv_sizes, [0], [12, 16, 20],
        "empty message",
        flags=[pseudorandom])
    self.generate_pseudorandom(
        1,
        key_sizes,
        iv_sizes, [16, 32, 48], [16],
        "message size divisible by block size",
        flags=[pseudorandom])
    self.generate_pseudorandom(
        1,
        key_sizes,
        iv_sizes, [1, 2, 8, 14, 15], [12],
        "small plaintext size",
        flags=[pseudorandom])
    self.generate_pseudorandom(
        1,
        key_sizes,
        iv_sizes, [20, 40], [12],
        "plaintext size > 16",
        flags=[pseudorandom])
    self.generate_pseudorandom(
        1,
        key_sizes, [1], [0, 16, 20], [0, 16],
        "iv size is 1",
        flags=[pseudorandom])
    self.generate_pseudorandom(
        1,
        key_sizes, [20, 40], [0, 20], [0, 16],
        "iv size is longer than 1 block",
        flags=[pseudorandom])
    long_sizes = [63, 64, 65, 127, 128, 129, 255, 256, 257, 511, 512, 513]
    self.generate_pseudorandom(
        1,
        key_sizes, [12],
        long_sizes, [0],
        "long message size",
        flags=[pseudorandom])
    self.generate_pseudorandom(
        1,
        key_sizes, [12], [16],
        long_sizes,
        "long aad size",
        flags=[pseudorandom])


  def generate_all(self, keysizes):
    # typical IV sizes.
    ivsizes = [12, 16]
    self.add_known_vectors(keysizes)
    self.generate_pseudorandom_vectors(keysizes, ivsizes)
    self.generate_modified_tags(keysizes, ivsizes)
    self.generate_edge_cases_siv(keysizes, ivsizes)


class AesSivAeadProducer(producer.Producer):

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
      key_sizes = (32, 48, 64)
    tv = AesSivAeadTestGenerator(namespace)
    tv.generate_all(key_sizes)
    return tv.test


# DEPRECATED: Use AesEaxProducer.produce() instead
def main(namespace):
  AesSivAeadProducer().produce(namespace)


if __name__ == "__main__":
  AesSivAeadProducer().produce_with_args()
