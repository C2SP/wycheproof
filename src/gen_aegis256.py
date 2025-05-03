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

# TODO: another typo is here:
# Test vectors from https://eprint.iacr.org/2013/695.pdf
# The SAC 2013 paper contains the same test vectors.
# The test vectors can be obtained by doing 6 instead of 7 rounds
# in finalize.
# However, both
# https://eprint.iacr.org/2013/695.pdf and
# https://competitions.cr.yp.to/round3/aegisv11.pdf
# require 7 steps in finalize.
# Implementations I found all use 7 steps:
# https://gitlab.codycook.us/github/linux/blob/b56a2d8af9147a4efe4011b60d93779c0461ca97/crypto/aegis256.c
# http://tomoyo.osdn.jp/cgi-bin/lxr/source/crypto/aegis256.c
# Aegis128 and Aegis128L, both use 7 steps in finalize.
# Hence it would be strange to reduce this to 6 steps for the 256-bit variant.
LEGACY_TEST_VECTORS = [
  [ "0000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "",
    "00000000000000000000000000000000",
    "b98f03a947807713d75a4fff9fc277a6",
    "a008acb1d372d73932ec5e6df9aca70a"],
  [ "0000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "00000000000000000000000000000000",
    "00000000000000000000000000000000",
    "b286705e6ccf368974ade9ff5550a4c5",
    "367f3f14897b31c6a66eb7b540eccc8b" ],
  [ "0001000000000000000000000000000000000000000000000000000000000000",
    "0000020000000000000000000000000000000000000000000000000000000000",
    "00010203",
    "00000000000000000000000000000000",
    "1f452a22fc07f2471ab4345d7ab121b1",
    "0d80d9c73cd4b8b3422b66cdaa45ae8a" ],
  [ "1001000000000000000000000000000000000000000000000000000000000000",
    "1000020000000000000000000000000000000000000000000000000000000000",
    "0001020304050607",
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    "f373079ed84b2709faee373584585d60accd191db310ef5d8b11833df9dec711",
    "787347bc96d3d0fdb33ddc8ee5ef4924" ],
]

class Aegis256TestGenerator(gen_aegis_common.AegisCommonTestGenerator):
  def __init__(self, args):
    super().__init__('AEGIS256', args)

  aead = aegis.Aegis256
  keysize = 32
  ivsize = 32

  def generate_tag_collision(self):
    """Generate a few test vectors with the same tag."""
    tag_collision = flag.Flag(
        label="TagCollision_1",
        bug_type=flag.BugType.BASIC,
        description="The test vector contains a ciphertext with the "
        "same tag as another vector, but different plaintext and "
        "ciphertext.")

    key = bytes(32)
    iv = bytes(32)
    aad = bytes()
    cipher = aegis.Aegis256(key)
    after = [bytes([0xff] * 16) for _ in range(6)]
    for i in range(4):
      prefix = bytes([i]) * 16
      s = cipher.initialize(iv)
      s = cipher.state_update(s, prefix)
      m = cipher.message_between_states(s, after)
      self.add_vector(key, iv, aad, prefix + m, comment="tag collision",
        flags=[tag_collision])

  def generate_legacy_vectors(self):
    legacy_ref = flag.Flag(
        label="OldVersion",
        bug_type=flag.BugType.LEGACY,
        description="This is a test vector from "
        "https://eprint.iacr.org/2013/695.pdf. "
        "The test vector contains a tag that was computed "
        "with only 6 instead of 7 rounds in finalize.")
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
          flags=[legacy_ref])
    # TODO: add comments

  def generate_all(self):
    self.generate_legacy_vectors()
    self.generate_known_tv(aegis_ktv.TEST_VECTOR_AEGIS256)
    self.generate_prand()
    self.generate_modified()
    self.generate_tag_collision()


class Aegis256Producer(producer.Producer):

  def parser(self):
    return self.default_parser()

  def generate_test_vectors(self, namespace):
    tv = Aegis256TestGenerator(namespace)
    tv.generate_all()
    return tv.test


# DEPRECATED: Use Aegis256Producer.produce() instead
def main(namespace):
  Aegis256Producer().produce(namespace)


if __name__ == "__main__":
  Aegis256Producer().produce_with_args()
