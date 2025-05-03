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

import hmac_algorithms
import mac_test_vector
import producer
import flag
import util
import typing
import test_vector



class HmacTestVectorGenerator(mac_test_vector.MacTestVectorGenerator):
  """Generates test vectors for HMAC.
  
  One thing to note is that HMAC test vectors don't give good coverage
  as most of the bugs cannot be detected with test vectors.

  Common causes for CVEs are:
  - completely missing HMAC verification [e.g. CVE-2022-29226]
  - determining the size of the digest from the tag
  - using the wrong key [CVE-2021-41106]
  - predictable keys [CVE-2019-11323, CVE-2019-10112]
  - not checking the size of the digest, which may lead to buffer overflow
    or other bugs. [CVE-2019-9469, CVE-2018-9860, CVE-2016-6302]
  - small key size [CVE-2018-5382]
  - integer overflow with long messages
  - determining the cryptographic primitive from the ciphertext [CVE-2016-10555]
  - checking the CBC padding despite invalid tag. [CVE-2017-12973]
  - Lucky thirteen attack
  - small timing differences during verification

  Other bugs are:
  - mishandling partial updates


  Things that can actually be checked:
  CVE-2019-16143: Incorrect HMAC computation with blake because of block size.
  """

  def __init__(self, md: str, args):
    hmac = hmac_algorithms.HmacAlgorithm(md)
    super().__init__(hmac, args)
    self.md = md
    self.hmac = hmac

  @util.type_check
  def mac(self, key: bytes, msg: bytes, macsize: int = None) -> bytes:
    h = self.hmac.new(key)
    h.update(msg)
    res = h.digest()
    if macsize is None:
      return res
    if len(res) < macsize:
      raise ValueError("macsize too large")
    return res[:macsize]

  def generate_truncated(self):
    if self.md == "SHA-512/256":
      wrong_md_name = "SHA-512"
      size = 32
    elif self.md == "SHA-512/224":
      wrong_md_name = "SHA-512"
      size = 28
    else:
      return
    wrong_hmac = hmac_algorithms.HmacAlgorithm(wrong_md_name)
    truncated_hmac = flag.Flag(
       label = "TruncatedHmac",
       bug_type=flag.BugType.FUNCTIONALITY,
       description="A truncated HMAC is not the same as an HMAC with "
       "a truncated hash. This test vector an HMAC that was simply "
       "truncated instead of using the correct hash function.")
    for key in [bytes(range(32))]:
      for msg in [b"123400"]:
        h = wrong_hmac.new(key)
        h.update(msg)
        tag = h.digest()[:size]
        d = mac_test_vector.MacTestVector()
        d.result = "invalid"
        d.comment = f"using {wrong_md_name} instead of {self.md}"
        d.key = key
        d.msg = msg
        d.tag = tag
        d.tagSize = size
        d.flags = self.add_flags([truncated_hmac])
        self.add_test(d)

  def generate_prand(self, key_sizes, mac_sizes, mdsize, try_more_key_sizes):
    # cnt, keysize, msgsize, macsize
    self.generate_pseudorandom(1, key_sizes, [0], mac_sizes, "empty message")
    self.generate_pseudorandom(1, key_sizes, list(range(1, 16)), mac_sizes,
                           "short message")
    self.generate_pseudorandom(1, key_sizes, [16, 17, 24, 32], mac_sizes, "")
    self.generate_pseudorandom(1, key_sizes, [47, 48, 49, 112, 127, 128, 255],
                           mac_sizes, "long message")
    if try_more_key_sizes:
      self.generate_pseudorandom(1, [mdsize // 2], [0, 16, 32], mac_sizes,
                               "short key")
      self.generate_pseudorandom(1, [65], [0, 16, 32], mac_sizes, "long key")

  def generate_modified(self, key_sizes, mac_sizes):
    for keysize in key_sizes:
      key = bytes(range(keysize))
      for mac_size in mac_sizes:
        for msgsize in (0, 16):
          msg = bytes(range(msgsize))
          self.generate_modified_tag(key, msg, mac_size)


def generate(namespace):
  md = namespace.sha
  mdsize = util.digest_size(md)
  if getattr(namespace, "key_sizes", None):
    key_sizes = [x // 8 for x in namespace.key_sizes]
    try_more_key_sizes = False
  else:
    key_sizes = [mdsize]
    try_more_key_sizes = True
  if getattr(namespace, "tag_sizes", None):
    tag_sizes = namespace.tag_sizes
    if any(size % 8 != 0 or size <= 32 for size in tag_sizes):
      raise ValueError("Tag sizes must be multiples of 8 and bigger than 32")
    if any(size > 8*mdsize for size in tag_sizes):
      raise ValueError("Tag sizes cannot be larger than %d" % (8 * mdsize))
    mac_sizes = [size // 8 for size in tag_sizes]
  else:
    mac_sizes = [mdsize, mdsize // 2]
  tv = HmacTestVectorGenerator(md, namespace)
  if mdsize in mac_sizes:
    tv.generate_truncated()
  tv.generate_prand(key_sizes, mac_sizes, mdsize, try_more_key_sizes)
  tv.generate_modified(key_sizes, mac_sizes)
  return tv.test



class HmacProducer(producer.Producer):

  def parser(self):
    res = self.default_parser()
    res.add_argument(
        "--key_sizes", type=int, nargs="+", help="a list of key sizes in bits")
    res.add_argument(
        "--sha",
        type=str,
        choices=hmac_algorithms.HASHES,
        help="the underlying hash function")
    res.add_argument(
        "--tag_sizes",
        type=int,
        nargs="+",
        help="a list of tag sizes in bits (default is [md_size, md_size//2] )")
    return res

  def generate_test_vectors(self, namespace):
    return generate(namespace)


# DEPRECATED: Use Producer.produce() instead
def main(namespace):
  HmacProducer().produce(namespace)


if __name__ == "__main__":
  HmacProducer().produce_with_args()
