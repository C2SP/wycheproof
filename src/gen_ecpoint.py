# Copyright 2017 Google Inc. All Rights Reserved.
# Author: bleichen@google.com (Daniel Bleichenbacher)
#
# Generating test cases for EC point compression and decompression.

import asn
import AST
import ec
import ec_groups
import producer
import test_vector
import typing
import util

# Point encodings
ENCODINGS = ("compressed", "uncompressed")

# TODO: Currently compressed and uncompressed encodings are in distinct
#   test vectors. It might be possible to merge them into one testvectors.
#   This might simplify test code (i.e. no need to parse and define the field compressed).
#
class EcPointTestVector(test_vector.TestVector):
  test_attributes = ['encoded', 'x', 'y']
  schema = {
    'encoded' : {
       'type' : AST.HexBytes,
       'desc' : 'X509 encoded point on the curve',
    },
    'x' : {
       'type' : AST.BigInt,
       'desc' : 'x-coordinate of the point',
    },
    'y' : {
       'type' : AST.BigInt,
       'desc' : 'y-coordinate of the point',
    },
  }

class EcPointTest(test_vector.TestType):
  '''Test vectors of type EcPointTest tests the
     encoding and decoding of points on an elliptic curve.'''

class EcPointTestGroup(test_vector.TestGroup):
  algorithm = "EC"
  testtype = EcPointTest
  vectortype = EcPointTestVector
  schema = {
    'encoding' : {
       'type' : str,
       'desc' : 'the encoding used',
       'enum' : ENCODINGS
    },
    'curve' : {
       'type' : AST.EcCurve,
       'desc' : 'the name of the elliptic curve',
    }
  }

  def __init__(self, curve: ec_groups.EcGroup, encoding: str):
    if encoding not in ENCODINGS:
      raise ValueError("Unsupported encoding:" + encoding)
    super().__init__()
    self.curve = curve
    self.encoding = encoding

  def as_struct(self, sort_by: typing.Optional[str] = None):
    if sort_by is None:
      sort_by = "comment"
    group = {}
    group['encoding'] = self.encoding
    group['curve'] = self.curve.name
    group['tests'] = self.get_all_vectors(sort_by=sort_by)
    return group

class EcPointGenerator(test_vector.TestGenerator):
  algorithm = "EcPointEncoding"
  def __init__(self):
    self.test = test_vector.Test(self.algorithm)

  def get_group(self, ec_group: ec_groups.EcGroup, encoding: str):
    c = ec_group.name
    idx = (c, encoding)
    if idx in self.test.testgroups:
      return self.test.testgroups[idx]
    group = EcPointTestGroup(ec_group, encoding)
    self.test.add_group(idx, group)
    return group

  def encode(self, ec_group: ec_groups.EcGroup, x: int, y: int, encoding: str):
    if encoding == 'compressed':
      return ec_group.encode_compressed([x,y])
    elif encoding == 'uncompressed':
      return ec_group.encode_uncompressed([x,y])
    else:
      raise NotImplementedError(encoding)

  def generate_points(self, ec_group: ec_groups.EcGroup):
    p = ec_group.p
    yield 'generator', ec_group.g
    x = 0
    while True:
      y = ec_group.get_y(x)
      if y != None:
        yield "x = " + str(x), [x,y]
        if x > 1: break
      x += 1
    xn = 1
    while True:
      y = ec_group.get_y(p-x)
      if y != None:
        yield "x = -" + str(x), [p-x,y]
        if x > 1: break
      x += 1

  def generate_test_vectors(self, ec_group: ec_groups.EcGroup, encoding: str):
    group = self.get_group(ec_group, encoding)
    for comment, point in self.generate_points(ec_group):
      x,y = point
      if ec_group.curve.is_on_curve(x,y):
        result = "valid"
      else:
        result = "invalid"
      encoded = self.encode(ec_group, x, y, encoding)
      test = EcPointTestVector(x=x, y=y, encoded=encoded,
                result=result,comment=comment)
      group.add_test(test)


# TODO: check if the encoding is used correctly.
# TODO: add curves
class EcPointProducer(producer.Producer):

  def parser(self):
    res = self.default_parser()
    res.add_argument(
        '--encoding',
        type=str,
        choices=["compressed", "uncompressed"],
        default='asn',
        help='the encoding of the EC point')
    return res

  def generate_test_vectors(self, namespace):
    tv = EcPointGenerator()
    for ec_group in ec_groups.predefined_curves:
      for encoding in ['compressed', 'uncompressed']:
        tv.generate_test_vectors(ec_group, encoding)
    return tv.test


# DEPRECATED: Use Producer.produce() instead
def main(namespace):
  EcPointProducer().produce(namespace)


if __name__ == "__main__":
  EcPointProducer().produce_with_args()
