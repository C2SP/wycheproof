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
import ccm
import producer
import test_vector
import util
import aes_ccm
import aria_ccm
import camellia_ccm
import sm4_ccm
import seed_ccm
import flag

ALGORITHMS = ["AES-CCM", "ARIA-CCM", "CAMELLIA-CCM", "SM4-CCM", "SEED-CCM"]

class CcmTestGenerator(aead_test_vector.AeadTestGenerator):

  # CVEs:
  #    CVE-2020-7069 PHP encrypts incorrectly (any test should detect this)
  #    CVE-2017-18330 buffer overflow with large inputs (covered)
  def __init__(self, args):
    super().__init__(args.algorithm, args)
    if args.algorithm == "AES-CCM":
      self.aead = aes_ccm.AesCcm
    elif args.algorithm == "ARIA-CCM":
      self.aead = aria_ccm.AriaCcm
    elif args.algorithm == "CAMELLIA-CCM":
      self.aead = camellia_ccm.CamelliaCcm
    elif args.algorithm == "SEED-CCM":
      self.aead = seed_ccm.SeedCcm
    elif args.algorithm == "SM4-CCM":
      self.aead = sm4_ccm.Sm4Ccm
    else:
      raise ValueError("Unknown algorithm:" + args.algorithm)

  def key_sizes_in_bytes(self):
    return self.aead.block_cipher.key_sizes_in_bytes


def generate(namespace):
  tv = CcmTestGenerator(namespace)
  if getattr(namespace, "key_sizes", None):
    key_sizes = [x // 8 for x in namespace.key_sizes]
  else:
    key_sizes = tv.key_sizes_in_bytes()
  pseudorandom = flag.Flag(
      label="Pseudorandom",
      bug_type=flag.BugType.FUNCTIONALITY,
      description="The test vector contains pseudorandomly generated inputs. "
      "The goal of the test vector is to check the correctness of the "
      "implementation for various sizes of the input parameters. "
      "Some libraries do not support all the parameter sizes. "
      "For example, CCM allows nonce sizes in the range 7 .. 13, "
      "but implementations may reject some of the smaller sizes.")
  # An example is  EVP_aead_aes_128_ccm_bluetooth in boringssl

  # check a range of message sizes
  tv.generate_pseudorandom(
      cnt=1,
      key_sizes=key_sizes,
      iv_sizes=[12],
      aad_sizes=[0],
      msg_sizes=(0, 1, 8, 16, 17, 24, 31, 33, 64, 66),
      comment="",
      flags=[pseudorandom])
  # Bluetooth
  if 16 in key_sizes:
    tv.generate_pseudorandom(
        cnt=1,
        key_sizes=[16],
        iv_sizes=[13],
        aad_sizes=[0, 8],
        msg_sizes=(0, 1, 8, 16, 17, 24, 31, 33, 64, 66),
        tag_sizes=[4, 8, 16],
        comment="",
        flags=[pseudorandom])
  # RFC 4309
  tv.generate_pseudorandom(
      cnt=1,
      key_sizes=key_sizes,
      # Section 4 of RFC 4309 describes the nonce format.
      # The nonce is a 3 byte salt followed by an 8 byte
      # IV.
      iv_sizes=[11],
      aad_sizes=[4, 8],
      msg_sizes=(0, 1, 8, 16, 17, 24, 31, 33, 64, 66),
      tag_sizes=[8, 12, 16],
      comment="",
      flags=[pseudorandom])
  # Check all valid nonce sizes.
  tv.generate_pseudorandom(
      cnt=1,
      key_sizes=key_sizes,
      iv_sizes=[7, 8, 9, 10, 11, 12, 13],
      aad_sizes=[0, 8],
      msg_sizes=[0, 16, 17],
      flags=[pseudorandom])
  # Check a range of aad sizes.
  # TODO aad sizes > 2**16 are not tested here.
  tv.generate_pseudorandom(
      cnt=1,
      key_sizes=key_sizes,
      iv_sizes=[12],
      aad_sizes=[0, 1, 2, 7, 8, 15, 16, 17, 31, 32, 65],
      msg_sizes=[0, 16],
      flags=[pseudorandom])
  # longer aad sizes
  tv.generate_pseudorandom(
      cnt=1,
      key_sizes=key_sizes,
      iv_sizes=[12],
      aad_sizes=[255, 256, 257, 511, 512, 513],
      msg_sizes=[16],
      flags=[pseudorandom])
  # longer msg sizes
  tv.generate_pseudorandom(
      cnt=1,
      key_sizes=key_sizes,
      iv_sizes=[12],
      aad_sizes=[0],
      msg_sizes=[255, 256, 257, 511, 512, 513],
      flags=[pseudorandom])
  # check all valid tag_sizes
  tv.generate_pseudorandom(
      cnt=1,
      key_sizes=key_sizes,
      iv_sizes=[12],
      aad_sizes=[0, 16],
      msg_sizes=[0, 16, 17, 31],
      tag_sizes=[4, 6, 8, 10, 12, 14, 16],
      flags=[pseudorandom])

  # modify the tag
  for keysize in key_sizes:
    key = bytes(range(keysize))
    nonce = bytes(range(80, 92))
    aad = bytes()
    msg = bytes(range(32, 48))
    tv.generate_modified_tag(key, nonce, aad, msg)

  # invalid nonce sizes
  ref_nonce = flag.Flag(
      label="InvalidNonceSize",
      bug_type=flag.BugType.MISSING_STEP,
      description="CCM is only defined for nonces of size 7 .. 13. "
      "No other nonce sizes should be used. "
      "The encoding of the octet B0 is undefined in these cases.")
  for keysize in key_sizes:
    key = bytes(range(keysize))
    for nonce_size in [0, 1, 2, 4, 6, 14, 15]:
      nonce = bytes(range(64, 64 + nonce_size))
      aad = bytes()
      msg = bytes(range(32, 48))
      tagsize = 12
      cipher = tv.aead(key, tagsize=tagsize, skip_checks=True)
      c,t = cipher.encrypt(nonce, aad, msg)
      tv.add_vector(
          key,
          nonce,
          aad,
          msg,
          c,
          t,
          comment="Invalid nonce size",
          valid="invalid",
          flags=[ref_nonce])
    for nonce_size in [16, 20, 32]:
      nonce = bytes(range(32, 32 + nonce_size))
      truncated_nonce = nonce[:15]
      tagsize = 12
      cipher = tv.aead(key, tagsize=tagsize)
      # Get an incorrect ciphertext by truncating the nonce.
      c,t = cipher.encrypt(truncated_nonce, aad, msg)
      tv.add_vector(
          key,
          nonce,
          aad,
          msg,
          c,
          t,
          comment="Nonce is too long",
          valid="invalid",
          flags=[ref_nonce])
    cve_2017_18330 = flag.Cve(
        "CVE-2017-18330",
        "CCM allows nonces longer then the block size of the cipher. "
        "Some implementations had memory overflows when the nonce was "
        "longer than 60 bytes. This test vector checks for such overflows.")
    for nonce_size in [64, 128, 268]:
      nonce = bytes([x % 256 for x in range(nonce_size)])
      truncated_nonce = nonce[:15]
      tagsize = 12
      cipher = tv.aead(key, tagsize=tagsize)
      # Get an incorrect ciphetext by truncating the nonce.
      c,t = cipher.encrypt(truncated_nonce, aad, msg)
      tv.add_vector(
          key,
          nonce,
          aad,
          msg,
          c,
          t,
          comment="Very long nonce",
          valid="invalid",
          flags=[cve_2017_18330, ref_nonce])

  # invalid tag sizes
  for keysize in key_sizes:
    key = bytes(range(keysize))
    nonce = bytes(range(70, 82))
    aad = bytes()
    msg = bytes(range(32, 48))
    # TODO Check size 0 and 1. For these the block B0 is
    #   undefined.
    invalid_tag_size = flag.Flag(
        label="InvalidTagSize",
        bug_type=flag.BugType.MISSING_STEP,
        description="CCM is only defined for tags of size "
        "4, 6, 8, 10, 12, 14, 16. No other tags sizes should be used. "
        "The encoding of the octet B0 is undefined in these cases.")
    for tagsize in [2, 3, 5, 7, 9, 11, 13, 15]:
      cipher = tv.aead(key, tagsize=tagsize, skip_checks=True)
      try:
        c,t = cipher.encrypt(nonce, aad, msg)
        tv.add_vector(
            key,
            nonce,
            aad,
            msg,
            c,
            t,
            comment="Invalid tag size",
            valid="invalid",
            flags=[invalid_tag_size])
      except Exception as ex:
        print(ex)

    aad = bytes()
    msg = bytes()
    insecure_tag_size = flag.Flag(
        label="InsecureTagSize",
        bug_type=flag.BugType.AUTH_BYPASS,
        description="Tag size 2 is invalid.",
        effect="Ciphertexts can be forged if tag size 2 is allowed.",
        links=["https://eprint.iacr.org/2003/070.pdf Section 3.3"])
    for tagsize in [2]:
      cipher = tv.aead(key, tagsize=tagsize, skip_checks=True)
      try:
        c,t = cipher.encrypt(nonce, aad, msg)
        tv.add_vector(
            key,
            nonce,
            aad,
            msg,
            c,
            t,
            comment="Invalid tag size",
            valid="invalid",
            flags=[insecure_tag_size])
      except Exception as ex:
        print(ex)

  return tv.test


class CcmProducer(producer.Producer):

  def parser(self):
    res = self.default_parser()
    res.add_argument(
        "--key_sizes",
        type=int,
        nargs="+",
        choices=[128, 192, 256],
        help="a list of key sizes in bits")
    res.add_argument(
        "--algorithm",
        type=str,
        choices=ALGORITHMS,
        default="AES-CCM",
        help="the name of the algorithm")
    return res

  def generate_test_vectors(self, namespace):
    return generate(namespace)


# DEPRECATED: Use Producer.produce() instead
def main(namespace):
  CcmProducer().produce(namespace)


if __name__ == "__main__":
  CcmProducer().produce_with_args()
