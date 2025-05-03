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
import prand
import util
import flag
from typing import Optional

class KeywrapTestVector(test_vector.TestVector):
  """A test vector for key wrap primitives.

     Key wrap primitives are typically symmetric encryptions that
     were specifically desigend for encrypting key material.
     In some cases the input size is restricted to typical key sizes
     e.g. a multiple of 8 bytes.
     The encryption may assume that the wrapped bytes have high entropy.
     Hence some of the key wrap primitives are deterministic.
  """
  schema = {
     "key" : {
        "type" : AST.HexBytes,
        "desc" : "the wrapping key",
     },
     "msg" : {
        "type" : AST.HexBytes,
        "desc" : "the key bytes to wrap",
     },
     "ct" : {
        "type" : AST.HexBytes,
        "desc" : "the wrapped key",
     }
  }

  test_attributes = ["key", "msg", "ct"]
  group_attributes = ["keySize"]
  since = "0.4.1"

  def index(self):
    assert isinstance(self.key, bytes)
    return len(self.key)


class KeywrapTest(test_vector.TestType):
  """Test vectors of type Keywrap are intended for tests
     checking the wrapping and unwrapping of key material.

     Invalid test vectors may contain vectors with
     invalid sizes, or invalid paddings. This is not
     ideal for testing whether unwrapping allows some
     padding oracle. If there are key wrapping primitives
     that can be attacked when padding oracles are present
     then we might add additional files just for checking
     against padding attacks.
  """

class KeywrapTestGroup(test_vector.TestGroup):
  schema = {
     "keySize" : {
         "type" : int,
         "desc" : "the keySize in bits",
     }
  }
  since = "0.4.1"
  vectortype = KeywrapTestVector
  testtype = KeywrapTest

  def __init__(self, key_size: int):
    super().__init__()
    self.keySize = key_size

  def as_struct(self, sort_by: Optional[str] = None):
    if sort_by is None:
      sort_by = "comment"
    group = {}
    group["type"] = self.testtype
    group["keySize"] = 8 * self.keySize
    group["tests"] = self.get_all_vectors(sort_by=sort_by)
    return group

class KeywrapTestVectorGenerator(test_vector.TestGenerator):
  def __init__(self, algorithm):
    self.algorithm = algorithm
    self.test = test_vector.Test(algorithm)

  def new_testgroup(self, idx):
    return KeywrapTestGroup(idx)

  # Must be overriden by subclass
  def wrap(self, key, data):
    raise NotImplementedError()

  @util.type_check
  def add_keywrap(self,
                  key: bytes,
                  msg: bytes,
                  ct: Optional[bytes] = None,
                  comment: str = "",
                  valid: str = "valid",
                  flags: Optional[list[flag.Flag]] = None):
    if flags is None:
      flags = []
    test = KeywrapTestVector()
    test.key = key
    test.msg = msg
    test.comment = comment
    test.flags = self.add_flags(flags)
    if ct is not None:
      test.ct = ct
      test.result = valid
    else:
      try:
        test.ct = self.wrap(key, msg)
        test.result = valid
      except Exception as ex:
        test.ct = ""
        test.result = "invalid"
        if not test.comment:
          test.comment = str(ex)
    self.add_test(test)

  def generate_pseudorandom(self,
                            cnt: int,
                            key_sizes: list[int],
                            data_sizes: list[int],
                            comment: str = "",
                            valid: str = "valid",
                            flags: Optional[list[flag.Flag]] = None):
    """Genrate pseudorandom wrappings for various key_sizes and data_sizes.
    
    Args:
      cnt: the number of test vectors generate for each parameter set
      key_sizes: a list of key sizes in bytes
      data_sizes: a list of sizes in byte for the data
      comment: a description of the parameter sets
      valid: determines if the parameter sets are valid or not
      flags: some flags describing the test cases
    """
    for key_size in key_sizes:
      for data_size in data_sizes:
        for i in range(cnt):
          ident = b"%d %d %d" % (key_size, data_size, i)
          key = prand.randbytes(key_size, b"key:" + ident)
          data = prand.randbytes(data_size, b"data:" + ident)
          self.add_keywrap(key, data, None, comment, valid, flags)
