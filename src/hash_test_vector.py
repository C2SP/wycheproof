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


class HashTest(test_vector.TestType):
  """Test vectors of type HashTest are intended for testing hash functions.
  
  A goal of the test vectors is to test long inputs. A somewhat common
  mistake is to overflow a counter when the input is longer than 2**32 bytes.
  The test vectors contain an input and the number n of repetitions as well
  as the hash result of hashing the concatenation of n times the input.
  """

class HashTestVector(test_vector.TestVector):
  """A test vector for hash functions."""
  schema = {
     "msg" : {
         "type" : AST.HexBytes,
         "desc" : "the input of the hash function",
     },
     "repetitions" : {
         "type" : int,
         "desc" : "number of times the input is repeated",
     },
     "hash" : {
         "type" : AST.HexBytes,
         "desc" : "the hash of repetitions times msg",
     },
  }

  test_attributes = ["msg", "repetitions", "hash"]
  group_attributes = []

  def index(self):
    return None

class HashTestGroup(test_vector.TestGroup):
  vectortype = HashTestVector
  testtype = HashTest
  schema = {}

  def __init__(self, idx = None):
    super().__init__()

  def as_struct(self, sort_by=None):
    if sort_by is None:
      sort_by = "comment"
    group = {}
    group["type"] = self.testtype
    group["tests"] = self.get_all_vectors(sort_by=sort_by)
    return group

class HashTestVectorGenerator(test_vector.TestGenerator):

  def __init__(self, algorithm, args):
    self.algorithm = algorithm
    self.test = test_vector.Test(algorithm, args)

  def new_testgroup(self, idx):
    return HashTestGroup(idx)

  # Must be overriden by subclass
  def hash(self, message: bytes, repetitions: int):
    raise NotImplementedError()

  def add_hash(self,
              msg: bytes,
              repetitions: int,
              *,
              digest: Optional[bytes] = None,
              comment: str = "",
              flags: Optional[list[flag.Flag]] = None):
    if flags is None:
      flags = []
    test = HashTestVector()
    test.msg = msg
    test.repetitions = repetitions
    if digest is None:
      digest = self.hash(msg, repetitions)
    test.digest = digest
    test.result = "valid"
    self.add_test(test)

  def generate_pseudorandom(self,
                            cnt: int,
                            msg_sizes: list[int],
                            repetitions: list[int] = [1],
                            comment: str = "",
                            flags: Optional[list[flag.Flag]] = None):
    """Genrate pseudorandom hashes for various sizes.

    Args:
      cnt: the number of test vectors per case
      msg_sizes: the message sizes in bytes.
      repetitions: the number of repetitions
      comment: a description of the test cases.
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
    for msg_size in msg_sizes:
      for i in range(cnt):
        ident = f"{msg_size} {i}"
        msg = prand.randbytes(msg_size, b"msg:" + ident)
        for rep in repetitions:
          self.add_hash(msg, repetitions, comment=comment, flags=flags)

