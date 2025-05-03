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
import flag
import util
from typing import Optional

class DaeadTest(test_vector.TestType):
  """Test vectors of type DaeadTest are intended for verifying

     encryption and decryption of deterministic authenticated encryption
     with additional data.

     Unlike the test vectors for AEAD the tag is included in the
     ciphertext, since deterministic authenticated encryption frequently
     uses a synthetic IV (SIV) that is used both as IV and MAC, and
     since the position of the SIV often depends on the primitive.
  """

class DaeadTestVector(test_vector.TestVector):
  """A test vector used for authenticated deterministic

     encryption with additional data.
  """
  test_attributes = ["key", "aad", "msg", "ct"]

  schema = {
      "key": {
          "type": AST.HexBytes,
          "desc": "the key",
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
          "desc": "the ciphertext including tag",
      },
  }

  def index(self):
    # Check that self.key is bytes (not hex string)
    assert isinstance(self.key, bytes)
    return len(self.key)

class DaeadTestGroup(test_vector.TestGroup):
  vectortype = DaeadTestVector
  testtype = DaeadTest
  schema = {
      "keySize": {
          "type": int,
          "desc": "the keySize in bits",
      }
  }

  def __init__(self, keySize):
    """sizes are in bytes"""
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

class DaeadTestGenerator(test_vector.TestGenerator):
  def __init__(self, algorithm, args=None):
    self.algorithm = algorithm
    self.test = test_vector.Test(algorithm, args)

  # All instance of DaeadTestGenerator use the same class DaeadTestGroup
  # (as wall as DaeadTestVector) to store the tests.
  def new_testgroup(self, idx):
    return DaeadTestGroup(idx)

  # Must be overriden by subclass
  def daead_cipher(self, key: bytes):
    raise NotImplementedError()

  def encrypt(self, key: bytes, aad: bytes, message: bytes):
    return self.daead_cipher(key).encrypt_deterministically(aad, message)

  def decrypt(self, key: bytes, aad: bytes, ct: bytes):
    return self.daead_cipher(key).encrypt_deterministically(aad, message)

  @util.type_check
  def add_daead(self,
                key: bytes,
                aad: bytes,
                msg: bytes,
                comment: str = "",
                valid: str = "valid",
                flags: Optional[list[flag.Flag]] = None):
    flags = self.add_flags(flags)
    test = DaeadTestVector()
    test.key = bytes(key)
    test.msg = bytes(msg)
    test.aad = bytes(aad)
    test.comment = comment
    test.ct = ""
    test.flags = flags
    try:
      test.ct = self.encrypt(key, aad, msg)
      test.result = valid
    except Exception as ex:
      test.comment += str(ex)
      test.result = "invalid"
    self.add_test(test)

  @util.type_check
  def generate_pseudorandom(self,
                            cnt: int,
                            key_sizes: list[int],
                            msg_sizes: list[int],
                            aad_sizes: list[int],
                            comment: Optional[str],
                            valid: str = "valid",
                            flags: Optional[list[flag.Flag]] = None):
    """Genrate pseudorandom vectors for various sizes.

       All sizes are in bits.
    """
    if flags is None:
      pseudorandom = flag.Flag(
          label="Pseudorandom",
          bug_type=flag.BugType.FUNCTIONALITY,
          description="The test vector contains pseudorandomly generated inputs. "
          "The goal of the test vector is to check the correctness of the "
          "implementation for various sizes of the input parameters.")
      flags = [pseudorandom]
    # prand(bytes, seed="", label="")
    for key_size in key_sizes:
      for msg_size in msg_sizes:
        for aad_size in aad_sizes:
          for i in range(cnt):
            ident = f"{key_size} {msg_size} {aad_size} {i}"
            key = prand.randbytes(key_size, "key:" + ident)
            msg = prand.randbytes(msg_size, "msg:" + ident)
            aad = prand.randbytes(aad_size, "aad:" + ident)
            self.add_daead(key, aad, msg, comment, valid, flags)
