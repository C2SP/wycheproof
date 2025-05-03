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

import gmac
import mac_with_iv_test_vector
import producer
import flag
import util
import prand

ALGORITHMS = ["AES-GMAC"]

# Format: (key, nonce, message, tag_hex, comment)
KNOWN_TEST_VECTORS = [
]


# CVEs:
# CVE-2020-8912: A vulnerability in the in-band key negotiation exists in the
# AWS S3 Crypto SDK for GoLang # versions prior to V2. An attacker with write
# access to the targeted bucket can change the encryption algorithm of an
# object in the bucket, which can then allow them to change AES-GCM to AES-CTR.
# Using this in combination with a decryption oracle can reveal the
# authentication key used by AES-GCM as decrypting the GMAC tag leaves the
# authentication key recoverable as an algebraic equation. It is recommended
#  to update your SDK to V2 or later, and re-encrypt your files.
# [Can't be tested here.]
#
# CVE-2014-2107: Cisco IOS 12.2 and 15.0 through 15.3, when used with the
# Kailash FPGA before 2.6 on RSP720-3C-10GE and RSP720-3CXL-10GE devices,
# allows remote attackers to cause a denial of service (route switch
# processor outage) via crafted IP packets, aka Bug ID CSCug84789.
# [No idea why a search for GMAC returns this CVE].
#
# CVE-2013-5548: The IKEv2 implementation in Cisco IOS, when AES-GCM or
# AES-GMAC is used, allows remote attackers to bypass certain IPsec
# anti-replay features via IPsec tunnel traffic, aka Bug ID CSCuj47795.
# [Can't get any details.]

class GmacTestVectorGenerator(
    mac_with_iv_test_vector.MacWithIvTestVectorGenerator):

  def __init__(self, gmac_type: type = gmac.AesGmac):
    super().__init__(gmac_type.name)
    self.gmac_type = gmac_type

  @util.type_check
  def mac_with_iv(self, key: bytes, iv: bytes, msg: bytes,
                  macsize: int) -> bytes:
    return self.gmac_type(key, macsize).mac(iv, msg)


  def generate_known_vectors(self, key_sizes: list[int], iv_sizes: list[int],
                             tag_sizes: list[int]):
    """Adds known test vectors for given parameters.
  
    Args:
      key_sizes: a list of key sizes in bytes
      iv_sizes: a list of iv sizes in bytes
      tag_sizes: a list of tag sizes in bytes
    """
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
            comment=comment)

  def generate_invalid_and_exceptional_sizes(self, key_sizes: list[int],
                                             iv_sizes: list[int],
                                             tag_sizes: list[int]):
    """Generates test vectors with invalid and exceptional sizes."""
    msg_sizes = [16]
    zeroiv = flag.Flag(
        label="ZeroLengthIv",
        bug_type=flag.BugType.AUTH_BYPASS,
        description="GCM does not allow an IV of length 0. "
        "Computing the GMAC using an IV of length 0 leaks the "
        "authentication key. This happens even if just a single "
        "GMAC is computed.",
        cves=["CVE-2017-7822"])
    invalid_key_size = flag.Flag(
        label="InvalidKeySize",
        bug_type=flag.BugType.MISSING_STEP,
        description="The test vector contains a key with an invalid key size. "
        "Accepting such a key indicates an missing parameter verification.")

    self.generate_pseudorandom(
        1, (0, 1, 8, 20, 40),
        iv_sizes,
        msg_sizes,
        tag_sizes,
        comment="invalid key size",
        flags=[invalid_key_size])
    self.generate_pseudorandom(
        1,
        key_sizes, [0],
        msg_sizes,
        tag_sizes,
        comment="invalid nonce size",
        valid="invalid",
        flags=[zeroiv])

    # TODO: What is the effect of an incorrect GHASH computation
    #   when computing GMAC?
    # For GCM invalid comutations with long IVs often lead to the leak of
    # the authentication key. For GMAC the behaviour seems more dependent on
    # the actual bug.
    longiv = flag.Flag(
        label="LongIv",
        bug_type=flag.BugType.FUNCTIONALITY,
        description="GCM allows long IVs. Such IVs are compressed using GHASH "
        "to generate the value J0. Hence GMAC is defined for long IVs too. "
        "However, some implementations may restrict the range "
        "of the IV sizes.",
        # effect="needs to be determined"
    )
    self.generate_pseudorandom(
        1,
        key_sizes, [20, 32, 64, 128],
        msg_sizes,
        tag_sizes,
        comment="long iv sizes",
        flags=[longiv])

  def generate_prand(self, key_sizes: list[int], iv_sizes: list[int],
                     tag_sizes: list[int]):
    """Generates test vectors for given parameter sizes.

    Args:
      key_sizes: the key sizes in bytes
      iv_sizes: the IV sizes in bytes
      tag_sizes: the tag sizes in bytes
    """
    pseudorandom = flag.Flag(
        label="Pseudorandom",
        bug_type=flag.BugType.FUNCTIONALITY,
        description="The test vector contains pseudorandomly generated inputs. "
        "The goal of the test vector is to check the correctness of the "
        "implementation for various sizes of the input parameters. "
        "Some libraries do not support all the parameter sizes. "
        "In particular the size of the IV is often restricted.")
    # cnt, keysize, ivsizes, msgsizes, macsize
    self.generate_pseudorandom(
        1,
        key_sizes,
        iv_sizes, [0],
        tag_sizes,
        "empty message",
        flags=[pseudorandom])
    self.generate_pseudorandom(
        1,
        key_sizes,
        iv_sizes, [1, 2, 4, 7, 8, 15, 16, 17, 24],
        tag_sizes,
        "short message",
        flags=[pseudorandom])
    self.generate_pseudorandom(
        1,
        key_sizes,
        iv_sizes, [129, 256, 277],
        tag_sizes,
        "long message",
        flags=[pseudorandom])

  def generate_modified(self, key_sizes: list[int], iv_sizes: list[int],
                        tag_sizes: list[int]):
    """Generates test vectors with modified tag.

    Args:
      key_sizes: the key sizes in bytes
      iv_sizes: the IV sizes in bytes
      tag_sizes: the tag sizes in bytes
    """
    for keysize in key_sizes:
      key = bytes(range(keysize))
      for msgsize in (8, 16):
        for tagsize in tag_sizes:
          for ivsize in iv_sizes:
            msg = bytes(range(msgsize))
            iv = bytes(range(ivsize))
            self.generate_modified_tag(key, iv, msg, tagsize)

  def generate_special_cases(self,
                             key_sizes: list[int],
                             iv_sizes: list[int],
                             tag_sizes: list[int],
                             seed: bytes = b"12l3kjqwher31k"):
    """Generates test vectors for special cases.

    Args:
      key_sizes: the key sizes in bytes
      iv_sizes: the IV sizes in bytes
      tag_sizes: the tag sizes in bytes
    """

    special_case = flag.Flag(
        label="SpecialCaseTag",
        bug_type=flag.BugType.EDGE_CASE,
        description="The test vector has been constructed such that "
        "the tag is a special case. Such a construction is done by "
        "fixing the tag and then computing a message from the tag.")
    for tag_size in tag_sizes:
      if tag_size != 16:
        # not implemented
        continue
      for key_size in key_sizes:
        for iv_size in iv_sizes:
          for tag in [bytes(16), bytes([0xff] * 16)]:
            ident = b"%d %d %d" % (key_size, iv_size, tag_size)
            key = prand.randbytes(key_size, seed, ident + b"key")
            nonce = prand.randbytes(iv_size, seed, ident + b"iv")
            mac = self.gmac_type(key, tag_size)
            msg = mac.inverse_mac(nonce, tag)
            self.add_mac(
                key=key,
                iv=nonce,
                msg=msg,
                mac_size=tag_size,
                mac=tag,
                comment="special case",
                flags=[special_case])

  def generate_all(self, key_sizes: list[int], iv_sizes: list[int],
                   tag_sizes: list[int], invalid_sizes: bool):
    """Generates test vectors for given parameter sizes.

    Args:
      key_sizes: the key sizes in bytes
      iv_sizes: the IV sizes in bytes
      tag_sizes: the tag sizes in bytes
      invalid_sizes: includes invalid and exceptional sizes.
    """
    self.generate_known_vectors(key_sizes, iv_sizes, tag_sizes)
    self.generate_prand(key_sizes, iv_sizes, tag_sizes)
    self.generate_modified(key_sizes, iv_sizes, tag_sizes)
    self.generate_special_cases(key_sizes, iv_sizes, tag_sizes)
    if invalid_sizes:
      self.generate_invalid_and_exceptional_sizes(key_sizes, iv_sizes,
                                                  tag_sizes)


def generate(namespace):
  algorithm_name = getattr(namespace, "algorithm", "AES-GMAC")
  if algorithm_name == "AES-GMAC":
    algorithm = gmac.AesGmac
  else:
    raise ValueError("Unsupported algorithm:" + algorithm_name)
  block_cipher = algorithm.block_cipher

  if getattr(namespace, "key_sizes", None):
    key_sizes = [x // 8 for x in namespace.key_sizes]
  else:
    # TODO: should be chosen algorithm dependent
    key_sizes = block_cipher.key_sizes_in_bytes
  if getattr(namespace, "tag_sizes", None):
    tag_sizes = [x // 8 for x in namespace.tag_sizes]
  else:
    tag_sizes = [algorithm.block_cipher.block_size_in_bytes]
  if getattr(namespace, "iv_sizes", None):
    iv_sizes = [x // 8 for x in namespace.iv_sizes]
  else:
    iv_sizes = [12, 16]

  tv = GmacTestVectorGenerator(algorithm)
  tv.generate_all(key_sizes, iv_sizes, tag_sizes,
                  getattr(namespace, "invalid_sizes", False))
  return tv.test


class GmacProducer(producer.Producer):

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
        choices=list(range(32, 136, 8)),
        nargs="+",
        help="a list of tag sizes in bits")
    res.add_argument(
        "--iv_sizes", type=int, nargs="+", help="a list of IV sizes in bits")
    res.add_argument(
        "--algorithm",
        type=str,
        choices=ALGORITHMS,
        default="AES-GMAC",
        help="the GMAC algorithm")
    res.add_argument(
        "--invalid_sizes",
        help="includes test vectors with invalid and exceptional sizes",
        action="store_true")
    return res

  def generate_test_vectors(self, namespace):
    return generate(namespace)


# DEPRECATED: Use Producer.produce() instead
def main(namespace):
  GmacProducer().produce(namespace)


if __name__ == "__main__":
  GmacProducer().produce_with_args()
