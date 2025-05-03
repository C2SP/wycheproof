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

class Aegis128TestGenerator(gen_aegis_common.AegisCommonTestGenerator):
  def __init__(self, args):
    super().__init__('AEGIS128', args)

  aead = aegis.Aegis128
  keysize = 16
  ivsize = 16

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
    cipher = aegis.Aegis128(key)
    after = [bytes([0xff] * 16) for _ in range(5)]
    for i in range(4):
      prefix = bytes([i]) * 16
      s = cipher.initialize(iv)
      s = cipher.state_update(s, prefix)
      m = cipher.message_between_states(s, after)
      self.add_vector(key, iv, aad, prefix + m, comment="tag collision",
         flags=[tag_collision])

  def generate_known_vectors(self):
    # TODO: add comments
    known_tv = aegis_ktv.TEST_VECTOR_AEGIS
    # known_tv = []
    for t in known_tv:
      key, nonce, aad, msg, ct, tag = [bytes.fromhex(x) for x in t]
      self.add_vector(key, nonce, aad, msg)

    known_tv = aegis_ktv.TEST_VECTOR_AEGIS128L
    # known_tv = []



  def generate_all(self, args):
    # TODO: Add special cases
    #  - if the key is known then special case states can be forced.
    #  - it the key is known then the tag can be forced.
    self.generate_known_tv(aegis_ktv.TEST_VECTOR_AEGIS)
    self.generate_prand()
    self.generate_modified()
    self.generate_tag_collision()


class Aegis128Producer(producer.Producer):

  def parser(self):
    return self.default_parser()

  def generate_test_vectors(self, namespace):
    tv = Aegis128TestGenerator(namespace)
    tv.generate_all(namespace)
    return tv.test


# DEPRECATED: Use Aegis128Producer.produce() instead
def main(namespace):
  Aegis128Producer().produce(namespace)


if __name__ == "__main__":
  Aegis128Producer().produce_with_args()
