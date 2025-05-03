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
import test_vector
import test_generation
import prand
import util
import flag
from typing import Optional


class MacTest(test_vector.TestType):
  """Test vectors of type MacTest are intended for testing the
     generation and verification of MACs.

     Test vectors with invalid MACs may contain vectors that
     contain invalid tags, invalid parameters or invalid formats.
     Hence they are not ideal for testing if an implementation
     is susceptible to padding attacks. Future version might
     include separate files to simplify such tests."""

class MacTestVector(test_vector.TestVector):
  """A test vector for message authentication codes (MAC)."""
  schema = {
     "key" : {
         "type" : AST.HexBytes,
         "desc" : "the key",
     },
     "msg" : {
         "type" : AST.HexBytes,
         "desc" : "the plaintext",
     },
     "tag" : {
         "type" : AST.HexBytes,
         "desc" : "the authentication tag",
     },
  }

  test_attributes = ["key", "msg", "tag"]
  group_attributes = ["tagSize"]

  def index(self):
    assert isinstance(self.key, bytes)
    return len(self.key), self.tagSize

# TODO: Add a flag describing whether the algorithm is deterministic.
# Document whether the group is meant for generation or verification.
class MacTestGroup(test_vector.TestGroup):
  vectortype = MacTestVector
  testtype = MacTest
  schema = {
     "tagSize" : {
         "type" : int,
         "desc" : "the expected size of the tag in bits",
     },
     "keySize" : {
         "type" : int,
         "desc" : "the keySize in bits",
     }
  }

  def __init__(self, idx):
    """idx = (keySize, tagSize) in bytes"""
    keySize, tagSize = idx
    super().__init__()
    self.keySize = keySize
    self.tagSize = tagSize

  def as_struct(self, sort_by=None):
    if sort_by is None:
      sort_by = "comment"
    group = {}
    group["type"] = self.testtype
    group["keySize"] = 8 * self.keySize
    group["tagSize"] = 8 * self.tagSize
    group["tests"] = self.get_all_vectors(sort_by=sort_by)
    return group

class MacTestVectorGenerator(test_vector.TestGenerator):

  def __init__(self, algorithm, args):
    self.algorithm = algorithm
    self.test = test_vector.Test(algorithm, args)

  def new_testgroup(self, idx):
    return MacTestGroup(idx)

  # Must be overriden by subclass
  def mac(self, key: bytes, message: bytes, tag_size_in_bytes: int):
    raise NotImplementedError()

  def add_mac(self,
              key: bytes,
              msg: bytes,
              mac_size: int,
              comment: str = "",
              valid: str = "valid",
              flags: Optional[list[flag.Flag]] = None):
    if flags is None:
      flags = []
    test = MacTestVector()
    test.key = key
    test.msg = msg
    test.tag = bytes()
    test.tagSize = mac_size
    test.comment = comment
    test.flags = self.add_flags(flags)
    try:
      test.tag = self.mac(key, msg, mac_size)
      test.result = "valid"
    except Exception as ex:
      test.result = "invalid"
    self.add_test(test)

  def generate_pseudorandom(self,
                            cnt: int,
                            key_sizes: list[int],
                            msg_sizes: list[int],
                            tag_sizes: list[int],
                            comment: str = "",
                            valid: str = "valid",
                            flags: Optional[list[flag.Flag]] = None):
    """Genrate pseudorandom MACS for various sizes.

    Args:
      cnt: the number of test vectors per case
      key_sizes: the key sizes in bytes.
      msg_sizes: the message sizes in bytes.
      tag_sizes: the tag sizes in bytes.
      comment: a description of the test cases.
      valid: one of valid, invalid or acceptable.
      flags: a list of flags
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
      for msg_size in msg_sizes:
        for tag_size in tag_sizes:
          for i in range(cnt):
            ident = b"%d %d %d %d" % (key_size, msg_size, tag_size, i)
            key = prand.randbytes(key_size, b"key:" + ident)
            msg = prand.randbytes(msg_size, b"msg:" + ident)
            self.add_mac(key, msg, tag_size, comment, valid, flags)

  def generate_modified_tag(self, key, msg, tag_size, flags=None):
    if not flags:
      modified_tag = flag.Flag(
          label="ModifiedTag",
          bug_type=flag.BugType.AUTH_BYPASS,
          description="The test vector contains a modified MAC. "
          "The purpose of the test is to check whether the "
          "verification fully checks the tag.")
      flags = [modified_tag]
    t = self.mac(key, msg, tag_size)
    for modified_tag, comment in test_generation.modify_tag(t):
      if modified_tag == t:
        continue
      d = MacTestVector()
      d.result = "invalid"
      d.comment = comment
      d.key = key
      d.msg = msg
      d.tag = modified_tag
      d.tagSize = tag_size
      d.flags = self.add_flags(flags)
      self.add_test(d)
