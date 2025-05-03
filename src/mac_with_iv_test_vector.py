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
import flag
import test_vector
import test_generation
import util
import prand
from typing import Optional


class MacWithIvTest(test_vector.TestType):
  """MacWithIvTest is intended for testing MACs that use an IV for randomization.

     In some cases the MAC is only secure if each MAC computation uses a distinct IV.
     Reusing the same IV multiple times may leak key material.
     Examples are GMAC and VMAC.
  """


class MacWithIvTestVector(test_vector.TestVector):
  """A test vector for message authentication codes (MAC) that use an IV."""
  schema = {
      "key": {
          "type": AST.HexBytes,
          "desc": "the key",
      },
      "iv": {
          "type": AST.HexBytes,
          "desc": "the initailisation vector",
      },
      "msg": {
          "type": AST.HexBytes,
          "desc": "the plaintext",
      },
      "tag": {
          "type": AST.HexBytes,
          "desc": "the authentication tag",
      },
  }

  test_attributes = ["key", "iv", "msg", "tag"]
  group_attributes = ["tagSize"]

  def index(self):
    assert isinstance(self.key, bytes)
    return len(self.key), len(self.iv), self.tagSize


class MacWithIvTestGroup(test_vector.TestGroup):
  vectortype = MacWithIvTestVector
  testtype = MacWithIvTest
  schema = {
      "tagSize": {
          "type": int,
          "desc": "the expected size of the tag in bits",
      },
      "ivSize": {
          "type": int,
          "desc": "the IV size in bits",
      },
      "keySize": {
          "type": int,
          "desc": "the key size in bits",
      }
  }

  def __init__(self, idx):
    """idx = (keySize, ivSize, tagSize) in bytes"""
    keySize, ivSize, tagSize = idx
    super().__init__()
    self.keySize = keySize
    self.tagSize = tagSize
    self.ivSize = ivSize

  def as_struct(self, sort_by=None):
    if sort_by is None:
      sort_by = "comment"
    group = {}
    group["type"] = self.testtype
    group["keySize"] = 8 * self.keySize
    group["ivSize"] = 8 * self.ivSize
    group["tagSize"] = 8 * self.tagSize
    group["tests"] = self.get_all_vectors(sort_by=sort_by)
    return group


class MacWithIvTestVectorGenerator(test_vector.TestGenerator):

  def __init__(self, algorithm):
    self.algorithm = algorithm
    self.test = test_vector.Test(algorithm)

  def new_testgroup(self, idx):
    return MacWithIvTestGroup(idx)

  # Must be overriden by subclass
  def mac_with_iv(self, key, iv, message, tagsizeInBits):
    raise NotImplementedError()

  @util.type_check
  def add_mac(self,
              key: bytes,
              iv: bytes,
              msg: bytes,
              mac_size: int,
              comment: str = "",
              valid: str = "valid",
              flags: Optional[list[flag.Flag]] = None,
              mac: Optional[bytes] = None):
    if flags is None:
      flags = []
    test = MacWithIvTestVector()
    test.key = key
    test.iv = iv
    test.msg = msg
    if mac is not None:
      test.tag = mac
    else:
      test.tag = bytes()
    test.tagSize = mac_size
    test.comment = comment
    test.flags = self.add_flags(flags)
    try:
      tag = self.mac_with_iv(key, iv, msg, mac_size)
      if mac is None or mac == test.tag:
        test.result = valid
        test.tag = tag
      else:
        test.result = "invalid"
    except Exception as ex:
      test.result = "invalid"
    self.add_test(test)

  def generate_pseudorandom(self,
                            cnt: int,
                            key_sizes: list[int],
                            iv_sizes: list[int],
                            msg_sizes: list[int],
                            mac_sizes: list[int],
                            comment: str = "",
                            valid: str = "valid",
                            flags: Optional[list[flag.Flag]] = None):
    """Genrate pseudorandom MACS for various sizes.

       All sizes are in bits.
    """
    if not flags:
      # if no flags are given, use generic one
      pseudorandom = flag.Flag(
          label="Pseudorandom",
          bug_type=flag.BugType.FUNCTIONALITY,
          description="The test vector contains pseudorandomly generated inputs. "
          "The goal of the test vector is to check the correctness of the "
          "implementation for various sizes of the input parameters.")
      flags = [pseudorandom]
    for key_size in key_sizes:
      for iv_size in iv_sizes:
        for msg_size in msg_sizes:
          for mac_size in mac_sizes:
            for i in range(cnt):
              ident = b"%d %d %d %d %d" % (key_size, iv_size, msg_size,
                                           mac_size, i)
              key = prand.randbytes(key_size, b"key:" + ident)
              iv = prand.randbytes(iv_size, b"iv:" + ident)
              msg = prand.randbytes(msg_size, b"msg:" + ident)
              self.add_mac(key, iv, msg, mac_size, comment, valid, flags)

  def generate_modified_tag(self,
                            key: bytes,
                            iv: bytes,
                            msg: bytes,
                            tag_size: int,
                            flags: Optional[list[flag.Flag]] = None):
    if not flags:
      modified_tag = flag.Flag(
          label="ModifiedTag",
          bug_type=flag.BugType.AUTH_BYPASS,
          description="The test vector contains a modified MAC. "
          "The purpose of the test is to check whether the "
          "verification fully checks the tag.")
      flags = [modified_tag]
    t = self.mac_with_iv(key, iv, msg, tag_size)
    for modified_tag, comment in test_generation.modify_tag(t):
      if modified_tag == t:
        continue
      d = MacWithIvTestVector()
      d.result = "invalid"
      d.comment = comment
      d.key = key
      d.iv = iv
      d.msg = msg
      d.tag = modified_tag
      d.tagSize = tag_size
      d.flags = self.add_flags(flags)
      self.add_test(d)
