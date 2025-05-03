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
import util
import prand
import flag
from typing import Optional


class IndCpaTest(test_vector.TestType):
  """Test vectors of type IndCpaTest are intended for tests that verify
     encryption and decryption of symmetric ciphers without authentication.
  """

# TODO: Add flags that distinguish invalid inputs from invalid paddings.
#   Document this, so that tests can determine if invalid paddings leak information.
class IndCpaTestVector(test_vector.TestVector):
  """A test vector that is used for symmetric primitives that are
     indistinguishable under chosen plaintext attacks. 
     These primitives are without an integrity check and hence
     without additional authenticated data.

     For example AES using cipher block chaining (CBC) is tested using
     this format.
  """

  test_attributes = ["key", "iv", "msg", "ct"]
  schema = {
     "key" : {
        "type" : AST.HexBytes,
        "desc" : "the key",
     },
     "iv" : {
        "type" : AST.HexBytes,
        "desc" : "the initialization vector",
     },
     "msg" : {
        "type" : AST.HexBytes,
        "desc" : "the plaintext",
     },
     "ct" : {
        "type" : AST.HexBytes,
        "desc" : "the raw ciphertext (without IV)",
     }
  }

  def index(self):
    assert isinstance(self.key, bytearray)
    assert isinstance(self.iv, bytearray)
    return len(self.key), len(self.iv)

class IndCpaTestGroup(test_vector.TestGroup):
  vectortype = IndCpaTestVector
  testtype = IndCpaTest
  schema = {
     "ivSize" : {
         "type" : int,
         "desc" : "the IV size in bits",
     },
     "keySize" : {
         "type" : int,
         "desc" : "the keySize in bits",
     }
  }

  def __init__(self, idx):
    """sizes are in bytes"""
    super().__init__()
    keySize, ivSize = idx
    self.keySize = keySize
    self.ivSize = ivSize

  def as_struct(self, sort_by=None):
    if sort_by is None:
      sort_by = "comment"
    group = {}
    group["type"] = self.testtype
    group["keySize"] = 8 * self.keySize
    group["ivSize"] = 8 * self.ivSize
    group["tests"] = self.get_all_vectors(sort_by=sort_by)
    return group

class IndCpaTestVectorGenerator(test_vector.TestGenerator):
  # Must be overriden by subclass
  def cipher(self, key):
    raise NotImplementedError()

  def new_testgroup(self, idx):
    return IndCpaTestGroup(idx)

  def encrypt(self, key: bytes, iv: bytes, message: bytes) -> bytes:
    return self.cipher(key).encrypt(iv, message)

  def decrypt(self, key:bytes, iv:bytes, ct:bytes) -> bytes:
    return self.cipher(key).decrypt(iv, ct)

  @util.type_check
  def add_ind_cpa(self, key:bytes, iv:bytes, msg:bytes, ct:bytes=None, comment:str="",
                  valid:str="valid", flags:Optional[list[flag.Flag]]=None):
    if flags is None:
      flags = []
    test = IndCpaTestVector()
    test.key = bytearray(key)
    test.msg = bytearray(msg)
    test.iv = bytearray(iv)
    test.comment = comment
    test.ct = ""
    test.flags = self.add_flags(flags)
    try:
      ct2 = self.encrypt(key, iv, msg)
      if ct is not None:
        test.ct = ct
        test.result = valid if ct == ct2 else "invalid"
      else:
        test.ct = ct2
        test.result = valid
    except Exception as ex:
      test.comment += str(ex)
      test.result = "invalid"
    self.add_test(test)

  @util.type_check
  def generate_pseudorandom(self,
                            cnt: int,
                            key_sizes: list[int],
                            iv_sizes: list[int],
                            msg_sizes: list[int],
                            comment: str = "",
                            valid: str = "valid",
                            flags: Optional[list[flag.Flag]] = None):
    """Genrate pseudorandom vectors for various sizes.
       All sizes are in bits."""
    # prand(bytes, seed="", label="")
    for key_size in key_sizes:
      for msg_size in msg_sizes:
        for iv_size in iv_sizes:
          for i in range(cnt):
            ident = b"%d %d %d %d" % (key_size, msg_size, iv_size, i)
            key = prand.randbytes(key_size, b"key:" + ident)
            msg = prand.randbytes(msg_size, b"msg:" + ident)
            iv = prand.randbytes(iv_size, b"iv:" + ident)
            self.add_ind_cpa(key, iv, msg, None, comment, valid, flags)
