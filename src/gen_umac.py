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

import aes
import mac_with_iv_test_vector
import producer
import struct
import flag
import util
import umac

# TODO: add more test vectors
#   - check for arithmetic overflow (like for VMAC)
#   - add generation for long MACs (n * b"abc")
#   - find test vectors for 128-bit tags.
# Format: (key, nonce, message, tag_hex, comment)

KNOWN_TEST_VECTORS = [
]

class UmacTestVectorGenerator(
    mac_with_iv_test_vector.MacWithIvTestVectorGenerator):

  def __init__(self):
    super().__init__("UMAC-AES")

  @util.type_check
  def mac_with_iv(self, key: bytes, iv: bytes, msg: bytes,
                  macsize: int) -> bytes:
    return umac.Umac(key, 8 * macsize).tag(message=msg, nonce=iv)


  def generate_known_vectors(self, key_sizes: list[int], iv_sizes: list[int],
                             tag_sizes: list[int]):
    """Adds known test vectors for given parameters.
  
    Args:
      key_sizes: a list of key sizes in bytes
      iv_sizes: a list of iv sizes in bytes
      tag_sizes: a list of tag sizes in bytes
    """
    ktv = flag.Flag(
        label="Ktv",
        bug_type=BugType.FUNCTIONALITY,
        description="Known test vector")
    for key, iv, msg, tag_hex, comment in KNOWN_TEST_VECTORS:
      if (len(key) in key_sizes and len(iv) in iv_sizes and
          len(tag_hex) // 2 in tag_sizes):
        tag = bytes.fromhex(tag_hex)
        self.add_mac(
            key=key,
            iv=iv,
            msg=msg,
            mac_size=len(tag),
            mac=tag,
            comment=comment,
            flags=[ktv])

  def generate_all(self, key_sizes, iv_sizes, tag_sizes):
    """Generates test vectors for given parameter sizes.

    Args:
      key_sizes: the key sizes in bytes
      iv_sizes: the IV sizes in bytes
      tag_sizes: the tag sizes in bytes
    """
    self.generate_known_vectors(key_sizes, iv_sizes, tag_sizes)

    # cnt, keysize, msgsize, macsize
    self.generate_pseudorandom(1, key_sizes, iv_sizes, [0], tag_sizes,
                               "empty message")
    self.generate_pseudorandom(1, key_sizes, iv_sizes,
                               [1, 2, 4, 7, 8, 15, 16, 17, 24], tag_sizes,
                               "short message")
    self.generate_pseudorandom(1, key_sizes, iv_sizes, [129, 256, 277],
                               tag_sizes, "long message")
    self.generate_pseudorandom(1, (0, 1, 8, 20, 40), iv_sizes, [8], tag_sizes,
                               "invalid key size")
    for keysize in key_sizes:
      key = bytes(range(keysize))
      for msgsize in (8, 16):
        for tagsize in tag_sizes:
          for ivsize in iv_sizes:
            msg = bytes(range(msgsize))
            iv = bytes(range(ivsize))
            self.generate_modified_tag(key, iv, msg, tagsize)

    for keysize in key_sizes:
      for tagsize in tag_sizes:
        for ivsize in iv_sizes:
          pass
          # TODO: add these cases
          # self.generate_extreme_cases(keysize, ivsize, tagsize)
          # self.generate_tag_collision(keysize, ivsize, tagsize)
          # self.generate_fixed_key(keysize, ivsize, tagsize)


def generate(namespace):
  if getattr(namespace, "key_sizes", None):
    key_sizes = [x // 8 for x in namespace.key_sizes]
  else:
    key_sizes = (16, 24, 32)
  if getattr(namespace, "tag_sizes", None):
    tag_sizes = [x // 8 for x in namespace.tag_sizes]
  else:
    tag_sizes = (8, 16)
  if getattr(namespace, "iv_sizes", None):
    iv_sizes = [x // 8 for x in namespace.iv_sizes]
  else:
    iv_sizes = [8, 12]

  # TODO: it is not clear yet how to divide the test vectors into
  # test groups. Possibly we might sort them by (keysize, iv-size, tag-size)
  tv = UmacTestVectorGenerator()
  tv.generate_all(key_sizes, iv_sizes, tag_sizes)
  if getattr(namespace, "iv_sizes", None) is None:
    tv.generate_faulty_nonces(key_sizes, tag_sizes)
  return tv.test


class UmacProducer(producer.Producer):

  def parser(self):
    res = self.default_parser()
    res.add_argument(
        "--key_sizes",
        type=int,
        choices=[128, 192, 256],
        nargs="+",
        help="a list of key sizes in bits")
    res.add_argument(
        "--tag_sizes",
        type=int,
        choices=[32, 64, 96, 128],
        nargs="+",
        help="a list of tag sizes in bits")
    res.add_argument(
        "--iv_sizes", type=int, nargs="+", help="a list of IV sizes in bits")
    return res

  def generate_test_vectors(self, namespace):
    return generate(namespace)


# DEPRECATED: Use Producer.produce() instead
def main(namespace):
  UmacProducer().produce(namespace)


if __name__ == "__main__":
  UmacProducer().produce_with_args()
