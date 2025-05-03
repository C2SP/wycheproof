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
import prand
import flag
import struct
import util
import vmac
from typing import Optional

# Format: (key, nonce, message, tag_hex, comment)
KNOWN_TEST_VECTORS = [
    [
        b"abcdefghijklmnop",  # 128-bit key 
        b"bcdefghi",
        b"",
        "2576BE1C56D8B81B",
        "https://tools.ietf.org/html/draft-krovetz-vmac-01"
    ],
    [
        b"abcdefghijklmnop",
        b"bcdefghi",
        b"",
        "472766C70F74ED23481D6D7DE4E80DAC",
        "https://tools.ietf.org/html/draft-krovetz-vmac-01"
    ],
    [
        b"abcdefghijklmnop",
        b"bcdefghi",
        b"abc", "2D376CF5B1813CE5",
        "https://tools.ietf.org/html/draft-krovetz-vmac-01"
    ],
    [
        b"abcdefghijklmnop",
        b"bcdefghi",
        b"abc",
        "4EE815A06A1D71EDD36FC75D51188A42",
        "https://tools.ietf.org/html/draft-krovetz-vmac-01"
    ],
    [
        b"abcdefghijklmnop",
        b"bcdefghi",
        b"abc" * 16,
        "E8421F61D573D298",
        "https://tools.ietf.org/html/draft-krovetz-vmac-01"
    ],
    [
        b"abcdefghijklmnop",
        b"bcdefghi",
        b"abc" * 16,
        "09F2C80C8E1007A0C12FAE19FE4504AE",
        "https://tools.ietf.org/html/draft-krovetz-vmac-01"
    ],
    [
        b"abcdefghijklmnop",
        b"bcdefghi",
        b"abc" * 100,
        "09BA597DD7601113",
        "https://tools.ietf.org/html/draft-krovetz-vmac-01"
    ],
    [
        b"abcdefghijklmnop",
        b"bcdefghi",
        b"abc" * 100,
        "2B6B02288FFC461B75485DE893C629DC",
        "https://tools.ietf.org/html/draft-krovetz-vmac-01"
    ],
]


def inverse_nh(k: list[int], value: int, seed: bytes = b"12l3j12l3"):
  """Returns a list m of the same size as k such that nh(k, m) == value.
  """
  if len(k) % 2 != 0:
    raise ValueError("expected k of even size")
  if len(k) < 4:
    raise ValueError("k too short")

  # Generate a random m
  w = [prand.randrange(0, 2**64, seed=seed, label=b"%d" % ki) for ki in k]
  t = sum(w[i]*w[i+1] for i in range(4, len(k), 2))
  rem = (value - t) % 2**126
  q = prand.randrange(2**63, 2**64, seed=seed, label=b"12kl3")
  a, b = divmod(rem, q)
  w[0] = 1
  w[1] = b
  w[2] = q
  w[3] = a
  m = [(wi - ki) % 2**64 for wi, ki in zip(w, k)]
  # sanity test
  assert vmac.nh(k, m) == value
  return m


def inverse_l3_hash(mac: vmac.Vmac, offset: int, res: int,
                    start: int = 1234567):
  """Returns m such that mac.l3_hash(m, offset) == res

  Args:
    mac: a VMAC instance
    offset: determines which part of the hash is inverted
    res: the expected result of l3_hash (must be in the range
         0 .. P64 - 1 
    start: an integer that defines the start of the search.
  """
  # P64  = 2 ** 64 - 257
  # PP = 2 ** 64 - 2 ** 32
  # P127 = 2 ** 127 - 1
  if res < 0 or res >= vmac.P64:
    raise ValueError("res out of range")
  k0, k1 = mac.l3_keys[offset]
  f1 = start
  while True:
    f0 = res * pow(f1, -1, vmac.P64) % vmac.P64
    m0 = (f0 - k0) % vmac.P64
    m1 = (f1 - k1) % vmac.P64
    m = vmac.PP * m0 + m1
    if 0 <= m < vmac.P127:
      # Verify result
      assert mac.l3_hash(m, offset) == res
      return m
    f1 = (f1 + 1) % vmac.P64


def inverse_l3_and_l2_hash(mac: vmac.Vmac,
                           offset: int,
                           res: int,
                           start: int = 1234567,
                           x1_start: int = 1640674083127384920347224171236831329
                          ) -> int:
  """Inverts l3_hash and l2_hash.

     Returns [x0, x1], such that
     mac.l3_hash(mac.l2_hash([x0, x1], 0, offset), offset) == res
  """
  if res < 0 or res >= vmac.P64:
    raise ValueError("res out of range")
  if res == 0:
    raise ValueError("not supported")
  k0, k1 = mac.l3_keys[offset]
  t0, t1 = mac.l2_keys[offset]
  k = ((t0 & vmac.MASK_POLY) << 64) | (t1 & vmac.MASK_POLY)
  inv_k = pow(k, -1, vmac.P127)

  f1 = start
  x1 = x1_start
  while True:
    f0 = res * pow(f1, -1, vmac.P64) % vmac.P64
    m0 = (f0 - k0) % vmac.P64
    m1 = (f1 - k1) % vmac.P64
    m = vmac.PP * m0 + m1
    if 0 <= m < vmac.P127:
      bitlen = 0
      y0 = (m - x1) * inv_k % vmac.P127
      x0 = (y0 - k) % vmac.P127
      if 0 < x0 < 2**126:
        # Verify result
        assert mac.l2_hash([x0, x1], 0, offset) == m
        assert mac.l3_hash(m, offset) == res
        return [x0, x1]
    f1 = (f1 + 1) % vmac.P64
    x1 = (x1 + 1) % 2**126


class VmacTestVectorGenerator(
    mac_with_iv_test_vector.MacWithIvTestVectorGenerator):

  def __init__(self):
    super().__init__("VMAC-AES")

  @util.type_check
  def mac_with_iv(self, key: bytes, iv: bytes, msg: bytes,
                  macsize: int) -> bytes:
    return vmac.Vmac(key, 8 * macsize).mac(m=msg, nonce=iv)

  flag_invalid_nonce = flag.Flag(
      label="InvalidNonce",
      bug_type=flag.BugType.MISSING_STEP,
      description="VMAC nonces are at most 127 bit long. The most significant "
      " bit of the nonce must be 0, since blocks with msb 1 are used for the "
      "key derivation.")

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
        bug_type=flag.BugType.FUNCTIONALITY,
        description="Known test vector",
        links=["https://tools.ietf.org/html/draft-krovetz-vmac-01"])

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

  def generate_extreme_cases(self,
                             key_size: int,
                             iv_size: int,
                             tag_size: int):
    """Generates edge cases for VMAC.

    VMAC uses multiplication and addition where the results are
    sometimes 128-bit long. This opens the possibility for
    incorrect integer arithmetic, such as incorrect carries.
    This function generates test vectors with edge cases such
    minimal or maximal temporary results.

    Args:
      key_size: the key size in bytes
      iv_size: the iv size in bytes
      tag_size: the tag size in bytes
    """
    flag_special = flag.Flag(
        label="EdgeCase",
        bug_type=flag.BugType.EDGE_CASE,
        description="The test vector contains a value that checks "
        "for arithmetic errors.")
    key = bytes(range(key_size))
    iv = bytes(range(16, 16 + iv_size))
    mac = vmac.Vmac(key, 8 * tag_size)
    # extreme cases
    # input + key == special case
    for length in [2, 4, 8]:
      for lr in [(2**64 - 1, 2**64 - 1),
                 (2**64 - 1, 1),
                 (1, 2**64 - 1),
                 (2**63, 2**63),
                 (2**63 - 1, 2**63 + 1),
                 (2**63 + 1, 2**63 - 1, 1, 1),
                 (2**62, 2**63),
                 (2**62 + 1, 2**62 - 1),
                 (2**48 - 1, 2**48 + 1, 22253377, 12648641),
                 (2**32, 2**32),
                 (2**32 - 1, 2**32 + 1),
                 (2**32 + 1, 2**32 - 1)]:
        inp = [None] * length
        for i in range(length):
          inp[i] = (lr[i % len(lr)] - mac.l1_keys[0][i]) % 2**64
        msg = b"".join(struct.pack("<Q", v) for v in inp)
        self.add_mac(
            key,
            iv,
            msg,
            tag_size,
            "special case for l1_hash",
            flags=[flag_special])

    # Special cases for l2_hash
    for l2 in [0, 1, 2**64 -1, 2**64, 2**96 - 1, 2**96, 2**96 + 1, 2**126-1]:
      m = inverse_nh(mac.l1_keys[0], l2, seed=b"1283679841k")
      msg = b"".join(struct.pack("<Q", v) for v in m)
      self.add_mac(
          key,
          iv,
          msg,
          tag_size,
          "special case for l2_hash input",
          flags=[flag_special])

    # Special case for l2_hash result
    for l2 in [0, 1, 2**126, vmac.P127 - 1]:
      t0, t1 = mac.l2_keys[0]
      k = ((t0 & vmac.MASK_POLY) << 64) | (t1 & vmac.MASK_POLY)
      m0 = prand.randrange(0, 2**125, seed=b"12k31j23", label=b"%d" % l2)
      for j in range(32):
        m1 = (l2 - k**2 - k*(m0 + j)) % vmac.P127
        if m1 < 2**126:
          m = inverse_nh(mac.l1_keys[0], m0 + j, seed=b"13213142131")
          m += inverse_nh(mac.l1_keys[0], m1, seed=b"121k314jkx3")
          msg = b"".join(struct.pack("<Q", v) for v in m)
          self.add_mac(
              key,
              iv,
              msg,
              tag_size,
              "special case for l2_hash",
              flags=[flag_special])
          break
    # Special cases for l3_hash
    for offset in range(mac.offsets):
      for res in [1, 2, vmac.PP, vmac.P64 - 1]:
        x = inverse_l3_and_l2_hash(mac, offset, res)
        m = inverse_nh(mac.l1_keys[offset], x[0])
        m += inverse_nh(mac.l1_keys[offset], x[1])
        msg = b"".join(struct.pack("<Q", v) for v in m)
        self.add_mac(
            key,
            iv,
            msg,
            tag_size,
            "special case for l3_hash result",
            flags=[flag_special])

  def generate_tag_collision(self,
                             key_size: int,
                             iv_size: int,
                             tag_size: int):
    """Generates test cases with the same tag.

    VMAC is not a hash and tag collisions can be generated easily.
    Moreover, VMAC is not even "plaintext aware", in the sense
    that that a sender knowing the key can choose a key and a message
    such that the VMAC(key, message + pwd) is the same for all
    pwd of say size 8. Hence the sender can generate a valid VMAC
    for message + pwd without knowing pwd.

    Args:
      key_size: the key size in bytes
      iv_size: the iv size in bytes
      tag_size: the tag size in bytes
    """
    flag_collision = flag.Flag(
        label="TagCollision",
        bug_type=flag.BugType.FUNCTIONALITY,
        description="VMAC is not a hash function. "
        "Tag collisions can be generated easily. Additionally, "
        "VMAC is not \"plaintext aware\", in the following sense: "
        "a sender knowing the key can choose a key and a message "
        "such that the VMAC(key, message + pwd) is the same for all "
        "pwd of say size 8. Hence the sender can generate a valid VMACs "
        "for message + pwd without knowing pwd. "
        "This test vector contains such a chosen message.")

    key = bytes(range(key_size))
    iv = bytes(range(16, 16 + iv_size))
    mac = vmac.Vmac(key, 8 * tag_size)

    # The method used here only works for 64-bit tags.
    if tag_size == 8:
      for length in [2, 4, 8]:
        for lr in [(0, 0),
                   (0, 1),
                   (0, 0x0101010101010101),
                   (0, 2**64-1),
                   (1, 0),
                   (2**64-1, 0)]:
          inp = [None] * length
          for i in range(length):
            inp[i] = (lr[i% 2] - mac.l1_keys[0][i]) % 2**64
          msg = b"".join(struct.pack("<Q", v) for v in inp)
          self.add_mac(
              key, iv, msg, tag_size, "tag collision", flags=[flag_collision])

  def generate_fixed_key(self,
                       key_size: int,
                       iv_size: int,
                       tag_size: int):
    """Generates test vectors with a set of precomputed keys.

    The set of special keys is the result of a search for
    keys such that the hash keys are special cases.

    Args:
      key_size: the key size in bytes
      iv_size: the iv size in bytes
      tag_size: the tag size in bytes
    """
    SPECIAL_KEYS = [
        (bytes.fromhex("000000000000000000000000457308e8"),
         "large l3_hash key"),
        (bytes.fromhex("0000000000000000000000007bad75f1"),
         "large l3_hash key"),
        (bytes.fromhex("00000000000000000000000094835214"),
         "large l3_hash key"),
    ]
    for key, comment in SPECIAL_KEYS:
      if len(key) == key_size:
        iv = bytes(range(iv_size))
        msg = bytes(range(32, 48))
        self.add_mac(key, iv, msg, tag_size, comment)

  def add_mac_with_long_iv(self,
                           key: bytes,
                           iv: bytes,
                           msg: bytes,
                           mac_size: int,
                           comment: str = "",
                           flags: Optional[list[flag.Flag]] = None):
    """Adds a test vector where the IV is potentially invalid.

    VMAC does not allow 128-bit IVs where the msb  of the IV is 1.
    This method generates a test vector for detecting implementations that
    ignore this restriction. I.e. the test vector is invalid, the tag
    is computed without a check for the size of the nonce.

    Args:
      key: the key
      iv: the (potentially incorrect) IV
      msg: the message to authenticate
      mac_size: the size of the MAC in bytes
      comment: explains the test case
    """
    if flags is None:
      flags = []
    try:
      if len(iv) == 16 and iv[0] >= 128:
        flags += [flag_invalid_nonce]
        mac = vmac.Vmac(key, 8 * mac_size, accept_faulty_nonces=True)
        tag = mac.mac(msg, iv)
        result = "invalid"
      else:
        tag = self.mac_with_iv(key, iv, msg, mac_size)
        result = "valid"
    except Exception as ex:
      tag = b""
      result = "invalid"

    test = mac_with_iv_test_vector.MacWithIvTestVector()
    test.key = key
    test.iv = iv
    test.msg = msg
    test.tag = bytes()
    test.tagSize = mac_size
    test.comment = comment
    test.flags = self.add_flags(flags)
    test.tag = tag
    test.result = result
    self.add_test(test)

  def generate_faulty_nonces(self, key_sizes: list[int], tag_sizes: list[int]):
    """Generates test vectors with faulty nonces.

    One particular case is that 128-bit nonces with the most significant bit set
    are not allowed by VMAC.

    Args:
      key_sizes: the key sizes in bytes
      tag_sizes: the tag sizes in bytes
    """
    msb_set = flag.Flag(
        label="MsbNonce",
        description="The nonce of VMAC must be have a bit length shorter than "
        "the block length of the underlying cipher. Hence a 16 byte nonce, "
        "where the most significant bit is set is not allowed.")

    for keysize in key_sizes:
      key = bytes(range(keysize))
      for msgsize in (8, 16):
        for tagsize in tag_sizes:
          msg = bytes(range(msgsize))
          iv = bytes([0x80]) + bytes(range(15))
          self.add_mac_with_long_iv(
              key,
              iv,
              msg,
              tagsize,
              "most significant bit of IV is set",
              flags=[msb_set])

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
          self.generate_extreme_cases(keysize, ivsize, tagsize)
          self.generate_tag_collision(keysize, ivsize, tagsize)
          self.generate_fixed_key(keysize, ivsize, tagsize)


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
  tv = VmacTestVectorGenerator()
  tv.generate_all(key_sizes, iv_sizes, tag_sizes)
  if getattr(namespace, "iv_sizes", None) is None:
    tv.generate_faulty_nonces(key_sizes, tag_sizes)
  return tv.test


class VmacProducer(producer.Producer):

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
        choices=[64, 128],
        nargs="+",
        help="a list of tag sizes in bits")
    res.add_argument(
        "--iv_sizes", type=int, nargs="+", help="a list of IV sizes in bits")
    return res

  def generate_test_vectors(self, namespace):
    return generate(namespace)


# DEPRECATED: Use Producer.produce() instead
def main(namespace):
  VmacProducer().produce(namespace)


if __name__ == "__main__":
  VmacProducer().produce_with_args()
