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

import AST
import collections
import flag
import prand
import test_generation
import test_vector
import util
from typing import Optional, Union


class AeadTest(test_vector.TestType):
  """Test vectors of type AeadTest test authenticated encryption with additional data.
  The test vectors are intended for testing both encryption and decryption.
  Test vectors with "result" : "valid" are valid encryptions.
  Test vectors with "result" : "invalid" are using invalid parameters
  or contain an invalid ciphertext or tag.
  """


class AeadTestVector(test_vector.TestVector):
  """A test vector for authenticated encryption with additional data."""
  test_attributes = ["key", "iv", "aad", "msg", "ct", "tag"]
  group_attributes = ["tagSize"]
  schema = {
      "key": {
          "type": AST.HexBytes,
          "desc": "the key",
      },
      "iv": {
          "type": AST.HexBytes,
          "desc": "the nonce",
      },
      "aad": {
          "type": AST.HexBytes,
          "desc": "additional authenticated data",
      },
      "msg": {
          "type": AST.HexBytes,
          "desc": "the plaintext",
      },
      "ct": {
          "type": AST.HexBytes,
          "desc": "the ciphertext (without iv and tag)",
      },
      "tag": {
          "type":
              AST.HexBytes,
          "short":
              "the authentication tag",
          "desc":
              """The authenticatian tag.
                 Most encryption append the tag to the ciphertext.
                 Encryption results in the concatenation ct || tag
                 and decryption expects ct || tag as input.

                 There are however some exceptions. For example
                 AEAD-AES-SIV-CMAC (RFC 5297) computes a synthetic IV (SIV),
                 which is used to initialize the counter for AES.
                 The typical encoding here is to prepend the SIV.
                 I.e. implementations would expect ciphertext of the
                 form tag || ct or iv || tag || ct.""",
      },
  }

  def index(self):
    return len(self.key), len(self.iv), self.tagSize


class AeadTestGroup(test_vector.TestGroup):
  """A test group for authenticated encryption with additional data."""
  algorithm = None
  allow_acceptable = False
  testtype = AeadTest
  vectortype = AeadTestVector
  schema = {
      "tagSize": {
          "type":
              int,
          "short":
              "the expected size of the tag in bits",
          "desc":
              """The expected size of the tag in bits.
                     This is the size that should be used to initialize
                     instance of the cipher. The actual tag in the
                     test vector may have a different size. Such a test
                     vector is always invalid and an implementation is expected
                     to reject such tags.
                     All tag sizes are multiples of 8 bits.
                 """
      },
      "ivSize": {
          "type":
              int,
          "short":
              "the IV size in bits",
          "desc":
              """The IV size in bits.
                     All IV sizes are multiple of 8 bits."""
      },
      "keySize": {
          "type": int,
          "desc": "the keySize in bits",
      },
  }



  def __init__(self, idx):
    """sizes are in bytes"""
    super().__init__()
    keySize, ivSize, tagSize = idx
    self.keySize = keySize
    self.ivSize = ivSize
    self.tagSize = tagSize

  def as_struct(self, sort_by=None):
    if sort_by is None:
      sort_by = "comment"
    group = collections.OrderedDict()

    group["type"] = self.testtype
    group["keySize"] = 8 * self.keySize
    group["ivSize"] = 8 * self.ivSize
    group["tagSize"] = 8 * self.tagSize
    group["tests"] = self.get_all_vectors(sort_by=sort_by)
    return group


class AeadTestGenerator(test_vector.TestGenerator):

  def __init__(self, algorithm, args):
    self.algorithm = algorithm
    self.test = test_vector.Test(algorithm, args)

  def new_testgroup(self, idx):
    return AeadTestGroup(idx)

  def aead(key, tagsize=None):
    raise NotImplementedError()

  @util.type_check
  def add_vector(self,
                 key: bytes,
                 iv: bytes,
                 aad: bytes,
                 msg: bytes,
                 ct: Optional[bytes] = None,
                 tag: Optional[bytes] = None,
                 comment: str = "",
                 valid: str = "valid",
                 tagsize: Optional[int] = None,
                 flags: Optional[list[flag.Flag]] = None):
    test = AeadTestVector()
    if flags is None:
      flags = []
    flags = self.add_flags(flags)
    try:
      if tagsize is None and tag is not None:
        tagsize = len(tag)
      if tagsize is None:
        cipher = self.aead(key)
        tagsize = cipher.tagsize
      else:
        cipher = self.aead(key, tagsize)
      c, t = cipher.encrypt(iv, aad, msg)
      if not t:
        comment += "empty tag"
      if ct is None:
        ct = c
      elif ct != c:
        valid = "invalid"
        if comment == "":
          comment = "expected ct:" + ct.hex()
      if tag is None:
        tag = t
      elif tag != t:
        valid = "invalid"
        if comment == "":
          comment = "expected tag:" + tag.hex()
    # TODO: Distinguish between faulty parameters and
    #   programming bugs.
    except Exception as ex:
      valid = "invalid"
      if ct is None:
        ct = bytes()
      if tag is None:
        tag = bytes()
      if comment == "":
        comment = "Encryption failed:" + str(ex)
    assert tagsize is not None
    test.comment = comment
    test.key = key
    test.iv = iv
    test.aad = aad
    test.msg = msg
    test.ct = ct
    test.tag = tag
    test.tagSize = tagsize
    test.result = valid
    test.flags = flags
    self.add_test(test)

  def generate_pseudorandom(self,
                            cnt: int,
                            key_sizes: list[int],
                            iv_sizes: list[int],
                            aad_sizes: list[int],
                            msg_sizes: list[int],
                            comment: str = "",
                            valid: str = "valid",
                            prefix: str = "",
                            flags: Optional[list[flag.Flag]] = None,
                            tag_sizes: list[Optional[int]] = [None]):
    """Generate pseudorandom test vectors. All sizes are in bytes"""
    for key_size in key_sizes:
      for msg_size in msg_sizes:
        for iv_size in iv_sizes:
          for aad_size in aad_sizes:
            for tagsize in tag_sizes:
              for i in range(cnt):
                if tagsize is None:
                  ident = (f"{prefix} {key_size} {msg_size} {iv_size} "
                           f"{aad_size} {i}")
                else:
                  ident = (f"{prefix} {key_size} {msg_size} {iv_size} "
                           f"{aad_size} {tagsize} {i}")
                ident = ident.encode("ascii")
                key = prand.randbytes(key_size, b"key:", ident)
                msg = prand.randbytes(msg_size, b"msg:", ident)
                iv = prand.randbytes(iv_size, b"iv:", ident)
                aad = prand.randbytes(aad_size, b"aad:", ident)
                self.add_vector(
                    key,
                    iv,
                    aad,
                    msg,
                    comment=comment,
                    valid=valid,
                    flags=flags,
                    tagsize=tagsize)




  @util.type_check
  def generate_modified_tag(self,
                            key: bytes,
                            iv: bytes,
                            aad: bytes,
                            msg: bytes,
                            flags: Optional[list[flag.Flag]] = None):
    modified_tag = flag.Flag(
        label="ModifiedTag",
        bug_type=flag.BugType.AUTH_BYPASS,
        description="The test vector contains a ciphertext with a modified "
        "tag. The test vector was obtained by manipulating a valid "
        "ciphertext. The purpose of the test is to check whether the "
        "verification fully checks the tag.",
        effect="Failing to fully verify a tag reduces the security level "
        "of an encryption.")
    if flags is None:
      flags = [modified_tag]
    else:
      flags = flags + [modified_tag]
    c, t = self.aead(key).encrypt(iv, aad, msg)
    for modified, comment in test_generation.modify_tag(t):
      self.add_vector(
          key,
          iv,
          aad,
          msg,
          ct=c,
          tag=modified,
          comment=comment,
          flags=flags)
