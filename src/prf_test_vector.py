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
import util
import flag
import prand
from typing import Optional


class PrfTest(test_vector.TestType):
  """Test vectors of type PrfTest are intended for testing pseudorandom functions.

     Test vectors of this type take two inputs: a key and a message and return
     a pseudorandom result of fixed length.
     Invalid test vectors contain invalid inputs.
  """

class PrfTestVector(test_vector.TestVector):
  """A test vector for pseudorandom functions."""
  schema = {
      "key": {
          "type": AST.HexBytes,
          "desc": "the key",
      },
      "msg": {
          "type": AST.HexBytes,
          "desc": "the plaintext",
      },
      "prf": {
          "type": AST.HexBytes,
          "desc": "the generated pseudorandom bytes",
      },
  }

  test_attributes = ["key", "msg", "prf"]

  def index(self):
    assert isinstance(self.key, bytes)
    return len(self.key)

class PrfTestGroup(test_vector.TestGroup):
  vectortype = PrfTestVector
  testtype = PrfTest
  schema = {
      "keySize": {
          "type": int,
          "desc": "the keySize in bits",
      }
  }

  def __init__(self, idx):
    """idx = keySize in bytes"""
    keySize = idx
    super().__init__()
    self.keySize = keySize

  def as_struct(self, sort_by=None):
    if sort_by is None:
      sort_by = "comment"
    group = {}
    group["type"] = self.testtype
    group["keySize"] = 8 * self.keySize
    group["tests"] = self.get_all_vectors(sort_by=sort_by)
    return group

class PrfTestVectorGenerator(test_vector.TestGenerator):
  def __init__(self, algorithm):
    self.algorithm = algorithm
    self.test = test_vector.Test(algorithm)

  def new_testgroup(self, idx):
    return PrfTestGroup(idx)

  # Must be overriden by subclass
  def prf(self, key, message):
    raise NotImplementedError()

  def add_prf(self,
              key: bytes,
              msg: bytes,
              expected: bytes = None,
              comment: str = "",
              valid: str = "valid",
              flags: Optional[list[flag.Flag]] = None):
    if flags is None:
      flags = []
    test = PrfTestVector()
    test.key = key
    test.msg = msg
    test.comment = comment
    test.flags = self.add_flags(flags)
    try:
      test.prf = self.prf(key, msg)
      test.result = "valid"
    except Exception as ex:
      test.prf = bytes()
      test.result = "invalid"
      print(ex)
    if expected is not None and expected != test.prf:
      assert expected == test.prf
    self.add_test(test)

  def generate_pseudorandom(self,
                            cnt: int,
                            key_sizes: list[int],
                            msg_sizes: list[int],
                            comment: str = "",
                            valid: str = "valid",
                            flags: Optional[list[str]] = None):
    """Genrate pseudorandom tests for various sizes.

    Args:
      cnt: the number of test vectors per case
      key_sizes: the key sizes in bytes.
      msg_sizes: the message sizes in bytes.
      comment: a description of the test cases.
      valid: one of valid, invalid or acceptable.
      flags: a list of flags
    """
    pseudorandom = flag.Flag(
          label="Pseudorandom",
          bug_type=flag.BugType.FUNCTIONALITY,
          description="The test vector contains pseudorandomly generated inputs. "
          "The goal of the test vector is to check the correctness of the "
          "implementation for various sizes of the input parameters.")
    if flags is None:
      flags = [pseudorandom]
    # prand(bytes, seed="", label="")
    for key_size in key_sizes:
      for msg_size in msg_sizes:
        for i in range(cnt):
          ident = b"%d %d %d" % (key_size, msg_size, i)
          key = prand.randbytes(key_size, b"key:" + ident)
          msg = prand.randbytes(msg_size, b"msg:" + ident)
          self.add_prf(key, msg, None, comment, valid, flags)
