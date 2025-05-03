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

import jwe_aes
import jwe_aes_ktv
import aead_test_vector
import producer
import util
import flag


ALGORITHMS = sorted(jwe_aes.ALGORITHMS)
class JweAesTestGenerator(aead_test_vector.AeadTestGenerator):
  def __init__(self, algorithm, args):
    super().__init__(algorithm, args)
    if algorithm in jwe_aes.ALGORITHMS:
      self.aead = jwe_aes.ALGORITHMS[algorithm]
    else:
      raise ValueError("Unknown algorithm:" + algorithm)

    self.key_size = self.aead.aes_key_size + self.aead.hmac_key_size


  def generate_iv(self):
    """Generates test vectors with special case IVs.

    Args:
      key: the key.
      msg: the message to encrypt
    """
    key = bytes(range(self.key_size))
    msg = bytes(range(20))
    iv_flag = flag.Flag(
        label="SpecialCaseIv",
        bug_type=flag.BugType.FUNCTIONALITY,
        description="",
    )
    A = self.aead(key)
    for iv_hex in (
        "00000000000000000000000000000000",
        "ffffffffffffffffffffffffffffffff",
        "000102030405060708090a0b0c0d0e0f",
        "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0"):
      aad = b""
      iv = bytes.fromhex(iv_hex)
      self.add_vector(key, iv, aad, msg, comment="special case IV", flags=[iv_flag])

  def generate_ktv(self):
    flag_ktv = flag.Flag(
        label="Ktv",
        bug_type=flag.BugType.BASIC,
        description="Test vector from RFC 7518.")

    for t in jwe_aes_ktv.AesCbcHmac_KTV:
      if t["alg"] == self.algorithm:
        msg, key, nonce, aad, ct, tag = [
            bytes.fromhex(t[n]) for n in ("msg", "key", "iv", "aad", "ct", "tag")
        ]
        self.add_vector(key, nonce, aad, msg, flags=[flag_ktv])

  def generate_prand(self):
    pseudorandom = flag.Flag(
        label="Pseudorandom",
        bug_type=flag.BugType.FUNCTIONALITY,
        description="The test vector contains pseudorandomly generated inputs. "
        "The goal of the test vector is to check the correctness of the "
        "implementation for various sizes of the input parameters. "
        "Some libraries do not support all the parameter sizes. "
        "In particular the size of the IV is often restricted.")

    # cnt, keysize, ivsize, aadsize, msgsize
    # different message sizes with 12 byte IV
    keysizes = [self.key_size]
    ivsizes = [16]
    # different message sizes (This uses PKCS #7 padding. Hence
    # we just try everything up to 2 blocks
    self.generate_pseudorandom(
        1,
        keysizes, ivsizes, [0], list(range(34)), flags=[pseudorandom])
    # different aad sizes
    self.generate_pseudorandom(
        1, keysizes, ivsizes, [1, 8, 16, 24], [20], flags=[pseudorandom])
    # longer message size
    self.generate_pseudorandom(
        1,
        keysizes, ivsizes, [0],
        [63, 64, 65, 127, 128, 129, 255, 256, 257, 511, 512, 513],
        flags=[pseudorandom])
    # longer aad size
    self.generate_pseudorandom(
        1,
        keysizes, ivsizes,
        [63, 64, 65, 127, 128, 129, 255, 256, 257, 511, 512, 513], [20],
        flags=[pseudorandom])

  def generate_modified(self):
      """Generates test vectors with modified tags."""
      key = bytes(range(self.key_size))
      iv = bytes(range(80, 96))
      aad = bytes()
      message = bytes(range(32, 48))
      self.generate_modified_tag(key, iv, aad, message)

  def generate_all(self):
    self.generate_ktv()
    self.generate_prand()
    self.generate_iv()
    self.generate_modified()

class JweAesProducer(producer.Producer):

  def parser(self):
    res = self.default_parser()
    res.add_argument(
        "--algorithm",
        type=str,
        choices=ALGORITHMS,
        default="A128CBC-HS256",
        help="the name of the algorithm")
    return res

  def generate_test_vectors(self, namespace):
    algorithm = getattr(namespace, "algorithm")
    tv = JweAesTestGenerator(algorithm, namespace)
    tv.generate_all()
    return tv.test


# DEPRECATED: Use Producer.produce() instead
def main(namespace):
  JweAesProducer().produce(namespace)


if __name__ == "__main__":
  JweAesProducer().produce_with_args()
