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
import flag
import poly1305
import util
from typing import Optional


def modify_tag(tag: bytes) -> bytes:

  def modify(tag, delta):
    val = poly1305.le_bytes_to_int(tag)
    val ^= delta
    return poly1305.int_to_bytes(val)

  for bit in [
      0, 1, 7, 8, 31, 32, 33, 63, 64, 77, 80, 96, 97, 120, 121, 126, 127
  ]:
    yield modify(tag, 1 << bit), "Flipped bit %s in tag" % bit
  yield modify(tag, 2**63 + 2**127), "Flipped bit 63 and 127 in tag"
  yield bytes(16), "Tag changed to all zero"
  yield bytes([255]) * 16, "tag change to all 1"


class ChachaCommonTestGenerator(aead_test_vector.AeadTestGenerator):

  def __init__(self, algorithm: str, args):
    super().__init__(algorithm, args)

  @util.type_check
  def gen_test(self,
               key: Optional[bytes] = None,
               nonce: Optional[bytes] = None,
               aad: Optional[bytes] = None,
               pt: Optional[bytes] = None,
               ct: Optional[bytes] = None,
               tag: Optional[bytes] = None,
               comment: Optional[str] = "",
               valid: Optional[str] = None,
               flags: Optional[list[flag.Flag]] = None):
    """Generates a test vector.

    The test generation tries
       to find values for the parameters left empty.

    Args:
      key: the key. If None then a default value is used.
      nonce: the nonce. If None then a default value is used.
      pt: the plaintext. If None and ct is specified then ct is decrypted.
        Otherwise pt is empty.
      aad: additional data. If the tag is specified, then an aad is computed to
        match the tag.
      tag: the tag. if None, then it is computed from other values.
      valid: if None, then the value is computed from the other values.
    """
    if comment is None:
      comment = ""
    assert isinstance(comment, str)

    # There is no way to determine key or nonce from other variables.
    if key is None:
      key = bytes(range(128, 160))
    if nonce is None:
      nonce = bytes(range(24))

    # If plaintext or ciphertext is missing try determining them from the
    # other.
    try:
      if pt is None and ct:
        pt = self.crypt_raw(key, nonce, ct)
      if ct is None and pt:
        ct = self.crypt_raw(key, nonce, pt)
    except Exception as e:
      valid = "invalid"
      if comment == "":
        comment = str(e)
    if pt is None:
      pt = ""
    if ct is None:
      ct = ""

    # If the AAD is missing. Try to find one matching the tag.
    if aad is None:
      if tag:
        aad = self.find_aad(key, nonce, ct, tag)
      else:
        aad = bytes.fromhex("00112233")

    # Encrypt and check if redundant parameters are consistent.
    try:
      c, t = self.encrypt(key, nonce, aad, pt)
    except Exception as ex:
      valid = "invalid"
      c, t = b"", b""
      if not comment:
        comment = str(ex)
    if ct != c:
      assert valid != "valid"
      valid = "invalid"
      if not comment:
        comment = "ciphertext is incorrect"

    # If tag is missing use the computed tag,
    # otherwise check if the tag is valid.
    if tag is None:
      tag = t
    elif tag != t:
      valid = "invalid"
      if comment:
        comment += " "
      comment += "expected tag:" + t.hex()

    if valid is None:
      valid = "valid"

    if flags is None:
      flags = []

    test = aead_test_vector.AeadTestVector()
    test.key = key
    test.msg = pt
    test.ct = ct
    test.aad = aad
    test.iv = nonce
    test.tag = tag
    test.comment = comment
    test.result = valid
    test.tagSize = 16
    test.flags = self.add_flags(flags)
    self.add_test(test)

  @util.type_check
  def gen_test_chacha(self,
                      key: Optional[bytes] = None,
                      nonce: Optional[bytes] = None,
                      aad: Optional[bytes] = None,
                      pt: Optional[bytes] = None,
                      ct: Optional[bytes] = None,
                      tag: Optional[bytes] = None,
                      comment: Optional[str] = "",
                      valid: Optional[str] = None,
                      flags: Optional[list[flag.Flag]] = None):
    """Generates a test vector.

    The test generation tries
       to find values for the parameters left empty. The following
       behaviour is implemented:

       key is None: a default value is used.
       nonce is None: a default value is used.
       pt is None: if the ciphertext is specified then the
                   ciphertext is decrypted (without checking tags)
                   otherwise an empty plaintext is used.
       aad is None: if the tag is specified then an aad is chosen
                    such that the ciphertext is valid.
       tag is None: a valid tag is computed from the other values
       valid is None: the value is determined from the test vector.
    """
    if comment is None:
      comment = ""
    assert isinstance(comment, str)

    # There is no way to determine key or nonce from other variables.
    if key is None:
      key = bytes(range(128, 160))
    if nonce is None:
      nonce = bytes(range(12))

    # If plaintext or ciphertext is missing try determining them from the
    # other.
    try:
      if pt is None and ct:
        pt = self.crypt_raw(key, nonce, ct)
      if ct is None and pt:
        ct = self.crypt_raw(key, nonce, pt)
    except Exception as e:
      valid = "invalid"
      if comment == "":
        comment = str(e)
    if pt is None:
      pt = ""
    if ct is None:
      ct = ""

    # If the AAD is missing. Try to find one matching the tag.
    if aad is None:
      if tag:
        aad = self.find_aad(key, nonce, ct, tag)
      else:
        aad = bytes.fromhex("00112233")

    # Encrypt and check if redundant parameters are consistent.
    try:
      c, t = self.encrypt(key, nonce, aad, pt)
    except Exception as ex:
      valid = "invalid"
      c, t = b"", b""
      if not comment:
        comment = str(ex)
    if ct != c:
      valid = "invalid"
      if not comment:
        comment = "ciphertext is incorrect"

    # If tag is missing use the computed tag,
    # otherwise check if the tag is valid.
    if tag is None:
      tag = t
    elif tag != t:
      valid = "invalid"
      if comment:
        comment += " "
      comment += "expected tag:" + t.hex()

    if valid is None:
      valid = "valid"

    if flags is None:
      flags = []

    test = aead_test_vector.AeadTestVector()
    test.key = key
    test.msg = pt
    test.ct = ct
    test.aad = aad
    test.iv = nonce
    test.tag = tag
    test.comment = comment
    test.result = valid
    test.tagSize = 16
    test.flags = self.add_flags(flags)
    self.add_test(test)

  def generate_pseudorandom_vectors(self):
    """Generates some test vectors pseudorandomly.

       for a range of message sizes and aad sizes.
    """
    pseudorandom = flag.Flag(
        label="Pseudorandom",
        bug_type=flag.BugType.FUNCTIONALITY,
        description="The test vector contains pseudorandomly generated inputs. "
        "The goal of the test vector is to check the implementation for "
        "different input sizes.")

    self.generate_pseudorandom(
        cnt=1,
        key_sizes=[self.key_size_in_bytes],
        iv_sizes=[self.iv_size_in_bytes],
        aad_sizes=[0, 8],
        msg_sizes=list(range(34)) +
        [47, 64, 97, 127, 128, 255, 256, 257, 511, 512, 513],
        flags=[pseudorandom])
    self.generate_pseudorandom(
        cnt=1,
        key_sizes=[self.key_size_in_bytes],
        iv_sizes=[self.iv_size_in_bytes],
        aad_sizes=list(range(18)) +
        [30, 31, 32, 33, 47, 127, 128, 129, 255, 256, 257, 511, 512, 513],
        msg_sizes=[16],
        flags=[pseudorandom])

  def generate_invalid_nonces(self):
    """Generates test vectors with invalid nonce sizes."""
    invalid_nonce_size = flag.Flag(
        label="InvalidNonceSize",
        bug_type=flag.BugType.MODIFIED_PARAMETER,
        description="RFC 7539 restricts the size of the nonce of "
        "CHACHA-POLY1305 to 12 bytes and XCHACHA-POLY1305 to 24 bytes. "
        "Other sizes are invalid.")
    for nonce_size in (0, 8, 11, 12, 13, 14, 16, 24, 20, 32):
      if nonce_size == self.iv_size_in_bytes:
        continue
      key = bytes(range(32, 64))
      nonce = bytes(range(nonce_size))
      self.gen_test(
          key=bytes(range(32, 64)),
          nonce=bytes(range(nonce_size)),
          aad=b"",
          pt=b"",
          ct=b"",
          comment=f"nonce has size {nonce_size}.",
          flags=[invalid_nonce_size])

  def generate_edge_case_tags(self):
    """Generate test vectors with edge case tags.

       I.e. these test vectors are generated by fixing the tag,
       then searching for ct and aad resulting in the given tag.
    """
    edge_case_tag = flag.Flag(
        label="EdgeCaseTag",
        bug_type=flag.BugType.EDGE_CASE,
        description="The tag contains an edge case. The goal of the "
        "test vector is to check for arithmetic errors in the final "
        "modular addition of CHACHA-POLY-1305.")
    key = bytes(range(64, 64 + self.key_size_in_bytes))
    nonce = bytes(range(self.iv_size_in_bytes))
    for tag_hex in [
        "000102030405060708090a0b0c0d0e0f",
        "00000000000000000000000000000000",
        "ffffffffffffffffffffffffffffffff",
        "00000080000000800000008000000080",
        "ffffff7fffffff7fffffff7fffffff7f",
        "01000000010000000100000001000000",
        "ffffffff000000000000000000000000",
    ]:
      self.gen_test(
          key=key,
          nonce=nonce,
          aad=None,  # an aad will be derived from the tag
          ct=bytes([255]) * 64,
          tag=bytes.fromhex(tag_hex),
          comment="edge case for tag",
          flags=[edge_case_tag])

  def generate_special_case_ct(self):
    """Generates test vectors, where the ciphertext is a special case."""
    edge_case_ct = flag.Flag(
        label="EdgeCaseCiphertext",
        bug_type=flag.BugType.EDGE_CASE,
        description="The test vector contains values where the ciphertext "
        "is a special case. The purpose of the test vector is to detect "
        "incorrect poly1305 computations.")
    key = bytes(range(128, 128 + self.key_size_in_bytes))
    for ct_block in [
        bytes(16),
        bytes([255]) * 16,
        bytes.fromhex("00000080") * 4,
        bytes.fromhex("80000000") * 4,
        bytes.fromhex("ffffff7f") * 4,
        bytes.fromhex("7fffffff") * 4,
        bytes.fromhex("00000000ffffffff") * 2,
        bytes.fromhex("ffffffff00000000") * 2,
    ]:
      for blocks in (2, 4, 8):
        nonce = bytes(range(self.iv_size_in_bytes))
        aad = ct_block
        ct = ct_block * blocks
        self.gen_test(key, nonce, aad, ct=ct, flags=[edge_case_ct])

  def generate_modified_tag(self):
    """Generates test vectors with modified tags."""
    modified_tag_flag = flag.Flag(
        label="ModifiedTag",
        bug_type=flag.BugType.AUTH_BYPASS,
        description="The test vector contains a ciphertext where the tag "
        "has been modified. The goal of the test vector is to detect "
        "implementations with partial or incorrect tag verification.")
    key = bytes(range(32, 32 + self.key_size_in_bytes))
    for ptsize in [0, 16, 33]:
      pt = bytes(range(ptsize))
      aad = bytes(range(3))
      nonce = bytes(range(self.iv_size_in_bytes))
      ct, tag = self.encrypt(key, nonce, aad, pt)
      for modified_tag, comment in modify_tag(tag):
        self.gen_test(
            key,
            nonce,
            aad,
            pt,
            ct,
            modified_tag,
            comment=comment,
            valid="invalid",
            flags=[modified_tag_flag])
