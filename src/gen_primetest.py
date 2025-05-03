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
import pseudoprimes
import producer
import test_vector
import typing
import util
import flag
from typing import Optional


class PrimalityTestVector(test_vector.TestVector):
  """A test vector for a primality test.

  The result is valid if value is prime and invalid if
  it is 0, 1, -1 or composite. The status of the negative of a prime
  is somewhat unlclear. Some libraries accept them as primes.
  Because of this the negative of a prime has result "acceptable".
  """
  test_attributes = ["value"]
  schema = {
      "value": {
          "type": AST.BigInt,
          "desc": "the integer to test"
      },
  }

  def index(self):
    return ""


class PrimalityTest(test_vector.TestType):
  """Test vector of type PrimalityTest are intended for testing primality tests."""


class PrimalityTestGroup(test_vector.TestGroup):
  """A test group for primality tests."""
  algorithm = "PrimalityTest"
  testtype = PrimalityTest
  vectortype = PrimalityTestVector
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


class PrimalityTestGenerator(test_vector.TestGenerator):
  """A generator of test vectors for a primality test."""

  def __init__(self, namespace):
    self.args = namespace
    self.name = "PrimalityTest"
    self.test = test_vector.Test(self.name)
    super().__init__()

  def new_testgroup(self, dummy):
    return PrimalityTestGroup(dummy)

  @util.type_check
  def gen_test(self,
               value: int,
               result: str,
               flags: Optional[list[flag.Flag]] = None,
               comment=""):
    if flags is None:
      flags = []
    test = PrimalityTestVector()
    test.comment = comment
    test.value = AST.BigInt(value)
    test.result = result
    test.flags = self.add_flags(flags)
    self.add_test(test)

  def generate_nonprimes(self):
    seen = set()
    for w in pseudoprimes.NONPRIMES:
      if len(w) != 4:
        print(w)
      comment, ref, flags, values = w
      if flags is None:
        flags = []
      else:
        flags = flags[:]
      if ref is not None:
        label, text, link = ref
        if link is None:
          links = []
        else:
          links = [link]
        flags += [
            flag.Flag(
                label=label,
                bug_type=flag.BugType.UNKNOWN,
                description=text,
                links=links)
        ]
      for value in values:
        flags_value = flags[:]
        if isinstance(value, pseudoprimes.Product):
          flags_value += value.flags()
        val = int(value)
        if val in seen:
          continue
        seen.add(val)
        self.gen_test(val, "invalid", flags_value, comment)

  def generate_primes(self):
    prime = flag.Flag(
        label="Prime",
        bug_type=flag.BugType.BASIC,
        description="The test vector contains a prime number. "
        "While there are a fair number of probably primality tests "
        "that sometimes do not recognize composite numbers, such "
        "tests generally do not declare a prime to be composite. "
        "Failing to recognize a prime typically indicates an error "
        "in the implementation of the algorithm.")
    seen = set()
    for comment, value in pseudoprimes.primes():
      if value in seen:
        continue
      seen.add(value)
      self.gen_test(value, "valid", [prime], comment)

  def generate_negative_primes(self):
    neg_prime = flag.Flag(
        label="NegativeOfPrime",
        bug_type=flag.BugType.FUNCTIONALITY,
        description="Some libraries accept the negative of a prime number "
        " as prime. For crypto libraries this just adds another "
        " potential pitfall.")
    for p in (257, 3303820997,
              3340530119,
              5887258746928580303,
              6430974998173972123,
              333610163647978885748406477874282560251,
              296419181658219306038085634872587616223,
              79400289762731105433305818291671708242242275199296386769913771891140431753099):
      self.gen_test(-p, "acceptable", [neg_prime], "negative of a prime")

  def generate_all(self):
    self.generate_nonprimes()
    self.generate_primes()
    self.generate_negative_primes()


class PrimalityTestProducer(producer.Producer):

  def parser(self):
    return self.default_parser()

  def generate_test_vectors(self, namespace):
    tv = PrimalityTestGenerator(namespace)
    tv.generate_all()
    return tv.test


# DEPRECATED: Use Producer.produce() instead
def main(namespace):
  PrimalityTestProducer().produce(namespace)


if __name__ == "__main__":
  PrimalityTestProducer().produce_with_args()
