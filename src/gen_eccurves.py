# Copyright 2022 Google Inc. All Rights Reserved.
# Author: bleichen@google.com (Daniel Bleichenbacher)
#
# Generating EC parameters for curves.

import AST
import ec
import ec_groups
import flag
import mod_arith
import prand
import producer
import test_vector
import util
from typing import Optional


class EcCurveTestVector(test_vector.TestVector):
  """EC parameters for prime order curves in Weierstrass form.

  The test vectors contain the parameters of known elliptic curves.
  The main purpose of these test vectors is to check for typos in
  implementations.
  """
  test_attributes = ["name", "oid", "ref", "p", "n", "a", "b", "gx", "gy", "h"]
  schema = {
      "name": {
          "type": str,
          "desc": "The name of the curve",
      },
      "oid": {
          "type": str,
          "desc": "The OID of the curve",
      },
      "ref": {
          "type": str,
          "desc": "A reference for the definition of the curve",
      },
      "p": {
          "type": AST.BigInt,
          "desc": "The order of underlying field",
      },
      "n": {
          "type": AST.BigInt,
          "desc": "The order of the generator",
      },
      "a": {
          "type": AST.BigInt,
          "desc": "The value a of the Weierstrass equation",
      },
      "b": {
          "type": AST.BigInt,
          "desc": "The value b of the Weierstrass equation",
      },
      "gx": {
          "type": AST.BigInt,
          "desc": "x-coordinate of the generator",
      },
      "gy": {
          "type": AST.BigInt,
          "desc": "y-coordinate of the generator",
      },
      "h": {
          "type": Optional[int],
          "desc": "[optional] the cofactor",
      },
  }

  def index(self):
    return tuple()


class EcCurveTest(test_vector.TestType):
  """Test vectors of type EcCurveTest are for checking curve parameters."""


class EcCurveTestGroup(test_vector.TestGroup):
  testtype = EcCurveTest
  vectortype = EcCurveTestVector
  schema = {}

  def __init__(self, idx):
    super().__init__()

  def as_struct(self, sort_by=None):
    if sort_by is None:
      sort_by = "comment"
    group = {}
    group["type"] = self.testtype
    group["tests"] = self.get_all_vectors(sort_by=sort_by)
    return group


class EcCurveTestGenerator(test_vector.TestGenerator):
  algorithm = "EcCurveTest"

  def __init__(self):
    self.test = test_vector.Test(self.algorithm)

  def new_testgroup(self, idx):
    return EcCurveTestGroup(idx)

  def get_flags(self, group: ec_groups.EcGroup) -> list[flag.Flag]:
    res = []
    return res

  @util.type_check
  def add_group(self,
                group: ec_groups.EcGroup,
                flags: Optional[list[flag.Flag]] = None):
    if flags is None:
      flags = []
    flags += self.get_flags(group)
    test = EcCurveTestVector(
        comment="",
        name=group.name,
        ref=group.ref,
        oid=group.get_oid(),
        p=AST.BigInt(group.p),
        n=AST.BigInt(group.n),
        a=AST.BigInt(group.a),
        b=AST.BigInt(group.b),
        gx=AST.BigInt(group.g[0]),
        gy=AST.BigInt(group.g[1]),
        h=group.h,
        flags=self.add_flags(flags),
        result="valid")
    self.add_test(test)

  def generate_all(self):
    for group in ec_groups.all_prime_order_curves:
      if not group.oid:
        # If the group does not have an OID then it is
        # either experimental or still a draft.
        continue
      self.add_group(group)


class EcCurveProducer(producer.Producer):

  def parser(self):
    return self.default_parser()

  def generate_test_vectors(self, namespace):
    tv = EcCurveTestGenerator()
    tv.generate_all()
    return tv.test


# DEPRECATED: Use Producer.produce() instead
def main(namespace):
  EcCurveProducer().produce(namespace)


if __name__ == "__main__":
  EcCurveProducer().produce_with_args()
