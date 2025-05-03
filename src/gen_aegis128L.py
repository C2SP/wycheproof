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

import aegis
import aegis_ktv
import aead_test_vector
import gen_aegis_common
import producer
import util
import flag

# Old test vectors from https://eprint.iacr.org/2013/695.pdf
# The old version computes the tag as sum over S[0] .. S[7]
# http://competitions.cr.yp.to/round1/aegisv1.pdf computes the tag as sum over S[0] .. S[6]
LEGACY_TEST_VECTORS = [
  [ "00000000000000000000000000000000",
    "00000000000000000000000000000000",
    "",
    "00000000000000000000000000000000",
    "41de9000a7b5e40e2d68bb64d99ebb19",
    "8674521d074f983b2e830dd6f3edf4e5" ],
  [ "00000000000000000000000000000000",
    "00000000000000000000000000000000",
    "00000000000000000000000000000000",
    "00000000000000000000000000000000",
    "29a0ce1f5dce8c404d56d00491668604",
    "eb82ca639900a0699c859bfbf3020bfa" ],
  [ "00010000000000000000000000000000",
    "00000200000000000000000000000000",
    "00010203",
    "00000000000000000000000000000000",
    "1c0f229f289844def2c1ef28bea0abf0",
    "86f3cc5e3a68f6e485960820be163808" ],
  [ "10010000000000000000000000000000",
    "10000200000000000000000000000000",
    "0001020304050607",
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    "79d94593d8c2119d7e8fd9b8fc77845c5c077a05b2528b6ac54b563aed8efe84",
    "4ed71cf3d6a3e568e8085110e92e8bfb" ],
]

class Aegis128LTestGenerator(gen_aegis_common.AegisCommonTestGenerator):
  def __init__(self, args):
    super().__init__('AEGIS128L', args)

  aead = aegis.Aegis128L
  keysize = 16
  ivsize = 16

  # TODO: Change to correct test vectors and add
  #   comments about the incorrect value.
  def generate_legacy(self):
    legacy = flag.Flag(
        label="OldVersion",
        bug_type=flag.BugType.LEGACY,
        description="This is a test vector from "
        "https://eprint.iacr.org/2013/695.pdf. "
        "This paper describes an old version of AEGIS128L. "
        "The tag is computed as sum over S[0] .. S[7]. "
        "However, the Caesar competition submission "
        "http://competitions.cr.yp.to/round1/aegisv1.pdf "
        "computes the tag as sum over S[0] .. S[6].")
    for t in LEGACY_TEST_VECTORS:
      key, nonce, aad, msg, ct, tag = [bytes.fromhex(x) for x in t]
      self.add_vector(
          key,
          nonce,
          aad,
          msg,
          ct=ct,
          tag=tag,
          comment="https://eprint.iacr.org/2013/695.pdf",
          valid="invalid",
          flags=[legacy])

  def generate_tag_collision(self):
    """Generates a few test vectors that have the same tag."""
    tag_collision = flag.Flag(
        label="TagCollision_1",
        bug_type=flag.BugType.BASIC,
        description="The test vector contains a ciphertext with the "
        "same tag as another vector, but different plaintext and "
        "ciphertext.")
       
    key = bytes(16)
    iv = bytes(16)
    aad = bytes()
    cipher = aegis.Aegis128L(key)
    after = [bytes([0xff] * 16) for _ in range(8)]
    for i in range(3):
      prefix = bytes([i]) * 16
      s = cipher.initialize(iv)
      s = cipher.state_update(s, prefix, prefix)
      m = cipher.message_between_states(s, after)
      self.add_vector(key, iv, aad, 2 * prefix + m, comment="tag collision",
          flags=[tag_collision])

  def generate_mac_collision(self):
    """Generates a few test vectors with aad only with a tag collision."""
    tag_collision = flag.Flag(
        label="TagCollision_2",
        bug_type=flag.BugType.BASIC,
        description="The test vector contains a ciphertext with the "
        "same tag as another vector, but different aad.")
    key = bytes(16)
    iv = bytes(16)
    cipher = aegis.Aegis128L(key)
    for msg in [b"", bytes(range(16))]:
      for prefix in [bytes(32), bytes(range(32)),bytes([0xff]) * 32]:
        s = cipher.initialize(iv)
        for j in range(0, len(prefix), 32):
          s = cipher.state_update(s, prefix[j:j+16], prefix[j+16:j+32])
        after = [bytes([0xff] * 16) for _ in range(8)]
        aad = prefix + cipher.message_between_states(s, after)
        self.add_vector(key, iv, aad, msg,
                        comment="tag collision",
                        flags=[tag_collision])

  def generate_all(self, args):
    self.generate_legacy()
    self.generate_known_tv(aegis_ktv.TEST_VECTOR_AEGIS128L)
    self.generate_prand()
    self.generate_modified()
    self.generate_tag_collision()
    self.generate_mac_collision()


class Aegis128LProducer(producer.Producer):

  def parser(self):
    return self.default_parser()

  def generate_test_vectors(self, namespace):
    tv = Aegis128LTestGenerator(namespace)
    tv.generate_all(namespace)
    return tv.test


# DEPRECATED: Use Aegis128LProducer.produce() instead
def main(namespace):
  Aegis128LProducer().produce(namespace)


if __name__ == "__main__":
  Aegis128LProducer().produce_with_args()
