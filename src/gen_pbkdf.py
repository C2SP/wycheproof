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
import pbkdf
import producer
import prand
import test_vector
import typing
import util
from typing import Optional

class PbkdfTestVector(test_vector.TestVector):
  """A test vector for PBKDF (or any other key derivation function with
     input password, salt, iteration count, size.
  """
  test_attributes = ["password", "salt", "iterationCount", "dkLen", "dk"]
  schema = {
     "password" : {
         "type" : AST.HexBytes,
         "desc" : "the password",
     },
     "salt" : {
         "type" : AST.HexBytes,
         "desc" : "the salt",
     },
     "iterationCount" : {
         "type" : int,
         "desc" : "the iteration count",
     },
     "dkLen" : {
         "type" : int,
         "desc" : "the intended length of the output in bytes",
     },
     "dk" : {
         "type" : AST.HexBytes,
         "desc" : "the derived key",
     },
  }

  def index(self):
    return ""

class PbkdfTest(test_vector.TestType):
  """Test vector of type PbkdfTest are for password based key derivations. 
 
     These test vectors are intended for password based key deriavation
     functions that take as input a tuple (password, salt, iteration count and
     output size).
  """

class PbkdfTestGroup(test_vector.TestGroup):
  """A test group for key derivation functions that take 4 arguments
     (password, salt, iteration count and output size) as input."""
  algorithm = "PBKDF"
  testtype = PbkdfTest
  vectortype = PbkdfTestVector
  schema = {}

  def __init__(self, dummy):
    super().__init__()

  def as_struct(self, sort_by=None):
    if sort_by is None:
      sort_by = "comment"
    group = collections.OrderedDict()
    group["type"] = self.testtype
    group["tests"] = self.get_all_vectors(sort_by=sort_by)
    return group

class PbkdfTestGenerator(test_vector.TestGenerator):
  """A generator for Pbkdf test vectors."""
  def __init__(self, namespace):
    self.args = namespace
    self.algorithm = namespace.algorithm
    self.sha = namespace.sha
    if self.algorithm == "PBKDF1":
      self.pbkdf = pbkdf.PBKDF1(self.sha)
    elif self.algorithm == "PBKDF2":
      self.pbkdf = pbkdf.PBKDF2(self.sha)
    self.name = self.algorithm + "-" + self.sha
    self.test = test_vector.Test(self.name)
    self.maxsize = 2**32
    super().__init__()

  def new_testgroup(self, idx):
    return PbkdfTestGroup(idx)

  @util.type_check
  def gen_test(self,
               password: bytes,
               salt: bytes,
               iteration_count: int,
               dk_len: int,
               flags = None,
               comment = ""):
    if flags is None:
      flags = []
    if dk_len > self.maxsize:
      raise ValueError("Not implemented")
    dk = self.pbkdf(password, salt, iteration_count, dk_len)
    test = PbkdfTestVector()
    test.comment = comment
    test.password = password
    test.salt = salt
    test.iterationCount = iteration_count
    test.dkLen = dk_len
    test.dk = dk
    test.flags = flags
    test.result = "valid"
    self.add_test(test)

  def generate_known_test_vectors(self):
    pass

  def generate_pseudorandom(
      self,
      cnt: int,
      password_sizes: list[int],
      salt_sizes: list[int],
      iteration_counts: list[int],
      dk_lengths: list[int],
      comment: str = "",
      seed: bytes = "",
      flags: Optional[list[str]] = None):
    """Generates pseudorandom test vectors.

    Args:
      cnt: the number of test cases generated per options
      password_sizes: as list of sizes in bytes
      salt_sizes: a list of size for the salt in bytes
      iteration_counts: a list of counts for the number of iterations
      dk_lengths: a list of lengths for the dk
      comment: describes what is special about the test cases
      seed: a seed for the pseudorandom genration
      flags: an optional ist of flags.
    """
    for pw_size in password_sizes:
      for salt_size in salt_sizes:
        for c in iteration_counts:
          for dk_len in dk_lengths:
            for i in range(cnt):
              ident = b"%s %d %d %d %d %d" % (
                      seed, pw_size, salt_size, c, dk_len, i)
              pw = prand.randbytes(pw_size, b"pw:", ident)
              salt = prand.randbytes(salt_size, b"salt:", ident)
              self.gen_test(password = pw,
                            salt=salt,
                            iteration_count = c,
                            dk_len = dk_len,
                            comment=comment, flags=flags)


  def generate_all(self):
    self.generate_known_test_vectors()
    # typical
    if self.algorithm == "PBKDF1":
      salt_sizes = [8]
      dk_lengths = [16]
    else:
      salt_sizes = [8, 16]
      dk_lengths = [16, 42, 65]
    self.generate_pseudorandom(cnt=1,
                               password_sizes=[8, 12, 17],
                               salt_sizes=salt_sizes,
                               iteration_counts=[4096],
                               dk_lengths=dk_lengths,
                               seed=b"jklkj214uid")


class PbkdfProducer(producer.Producer):

  def parser(self):
    res = self.default_parser()
    res.add_argument("--alg",
                     type=str,
                     default="PBKDF1",
                     choices=["PBKDF1", "PBKDF2"])
    res.add_argument("--sha",
                     type=str,
                     default="SHA-1",
                     choices=pbkdf.SUPPORTED_HASHES)
    return res

  def generate_test_vectors(self, namespace):
    tv = PbkdfTestGenerator(namespace)
    tv.generate_all()
    return tv.test


# DEPRECATED: Use Producer.produce() instead
def main(namespace):
  PbkdfProducer().produce(namespace)


if __name__ == "__main__":
  PbkdfProducer().produce_with_args()
