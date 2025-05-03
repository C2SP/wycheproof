# Copyright 2016 Google Inc. All Rights Reserved.
# Author: bleichen@google.com (Daniel Bleichenbacher)
#
# Generating test cases for ECDSA.
# The main focus here is to generate test cases with special values
# such as 0,1 etc. The motivation for testing with these values is that
# 0 is frequently used in encodings of the point at infinity. Careless
# parsing could lead to easily forgeable signatures.
# So far I"ve only seen DSA implementations that fall for such signatures.
# Though some implementations do have minor flaws.

# TODO:
#   - make pseudorandom
#   - add asn fuzzing
#   - unify types (i.e. points can be lists or tuples):

import AST
import ec
import ec_key
import ec_groups
import flag
import mod_arith
import prand
import producer
import test_vector
import util
from typing import Optional
from copy import copy

ECKEY_ENCODINGS = ["asn", "pem", "webcrypto"]


def find_point_and_alternative_prime(p: int,
                                     a: int,
                                     b: int,
                                     m: int = 1) -> tuple[tuple[int, int], int]:
  """Find a point (x,y) and an alternative prime q.

  This function finds a point (x, y) and a prime q such that
    y^2 == x^3+ax+b (mod pq).

  Args:
    p: the order of the original field
    a: coefficient a of the elliptic curve equation
    b: coefficient b of the elliptic curve equation
    m: a small multiplier. The multiplier could be used to generate more
      results.
  Returns: a point (x,y) and a prime q
  """
  x = int(m * p**(2./3.))
  while True:
    x += 1
    y2 = x**3 + a*x + b
    y = mod_arith.modsqrt(y2, p)
    if y is None:
      continue
    diff = y2 - y*y
    if diff <= 0:
      continue
    q = diff // p
    if q % 2 == 0:
      continue
    # A simple pseudoprimality test is sufficient, since
    # non-primes will not make this public key valid.
    if pow(2, q, q) != 2:
      continue
    if q.bit_length() != p.bit_length():
      continue
    return (x, y), q


def modify_point_and_p(group: ec_groups.EcGroup, w):
  """An iterator that returns EC groups and a point P

     such that P is a point on both the original group
     and the modified group.
  """
  ref = flag.Flag(
      label="ModifiedPrime",
      bug_type=flag.BugType.MODIFIED_PARAMETER,
      description="The modulus of the public key has been modified. "
      "The public point of the public key has been chosen so that it is "
      "both a point on both the curve of the modified public key and the "
      "private key.")
  p = group.p
  a = group.a % p
  b = group.b % p
  v, q = find_point_and_alternative_prime(p, a, b)
  modified_group = copy(group)
  modified_group.p = q
  modified_group.g = v
  yield True, "modified prime", modified_group, v, [ref]


def modify_group(group: ec_groups.EcGroup, point):
  # replace by NistP224 or NistP256, or secp256k1
  modified_group = flag.Flag(
      label="ModifiedGroup",
      bug_type=flag.BugType.MODIFIED_PARAMETER,
      description="The EC curve of the public key has been modified. "
      "EC curve primitives should always check that the keys are on the "
      "expected curve.")
  privkey = 0xb054db4ef81a262b7f50ebc96ad94abb2ce15c00d243111231a848f7cd510fa4
  for c2 in (ec_groups.curveP224, ec_groups.curveP256, ec_groups.secp256k1):
    if group.p != c2.p:
      pub = ec_key.EcPrivateKey(c2, privkey).public()
      yield True, "using " + c2.name, c2, pub.w, [modified_group]
  # Modify a,b: a == 0
  c = copy(group)
  x,y = point
  c.a = 0
  c.b = (y**2 - x**3) % group.p
  c.g = point
  modified_ab = flag.Flag(
      label="Modified curve parameter",
      bug_type=flag.BugType.MODIFIED_PARAMETER,
      description="The parameters a and b of the curve have been modified. "
      "The parameters haven been chosen so that public key or generator "
      "still are also valid points on the new curve.")
  yield True, "a = 0", c, point, [modified_ab]


def max_cofactor(group) -> int:
  """Returns the maximum cofactor for a group.

  FIPS-PUB 186-4 table 1, p.36.

  Args:
    group: the EC group.

  Returns:
    the maximum cofactor
  """
  if group.n.bit_length() <= 223:
    return 2**10
  elif group.n.bit_length() <= 255:
    return 2**14
  elif group.n.bit_length() <= 383:
    return 2**16
  elif group.n.bit_length() <= 511:
    return 2**24
  else:
    return 2**32


def get_flags_cofactor(group, h) -> list[flag.Flag]:
  """Returns a list of flags for a given cofactor.

  Args:
    group: the EC group
    h: the cofactor
    footnotes: footnotes
  """
  flag_modified_cofactor = flag.Flag(
      label="ModifiedCofactor",
      bug_type=flag.BugType.MODIFIED_PARAMETER,
      description="The cofactor has been modified. ",
      effect="The seriousness of accepting a key with modified cofactor "
      "depends on whether the primitive using the key actually uses the "
      "cofactor.")
  flags = []
  if h is None:
    return [flag_modified_cofactor]
  if h <= 0:
    flags.append(
        flag.Flag(
            label="NegativeCofactor",
            bug_type=flag.BugType.MODIFIED_PARAMETER,
            description="The cofactor of the curve is negative."))
    return flags
  if h > max_cofactor(group):
    flags.append(
        flag.Flag(
            label="LargeCofactor",
            bug_type=flag.BugType.MODIFIED_PARAMETER,
            description="The cofactor is larger than the limits specified in"
            " FIPS-PUB 186-4 table 1, p.36."))
  if not flags:
    return [flag_modified_cofactor]
  return flags


def modify_cofactor(group, w):
  for h, desc in ((-1, "-1"), (0, "0"), (1, "1"), (2, "2"), (group.n, "n"),
                  (None, "None")):
    if h != group.h:
      c = copy(group)
      c.h = h
      flags = get_flags_cofactor(group, h)
      valid_cofactor = h is None or 0 < h < max_cofactor(group)
      yield valid_cofactor, f"cofactor = {desc}", c, w, flags


def modify_order(group: ec_groups.EcGroup, w):
  wrong_order = flag.Flag(
      label="WrongOrder",
      bug_type=flag.BugType.MODIFIED_PARAMETER,
      description="The order of the public key has been modified.",
      effect="If this order is used in a cryptographic primitive "
      "instead of the correct order then an invalid curve attack is "
      "possible and the private keys may leak. "
      "E.g. ECDHC in BC 1.52 suffered from this.")
  isValidOrder = lambda n : n > 0
  for n in (-group.n, 0, 1, group.n >> 32):
    c = copy(group)
    c.n = n
    yield isValidOrder(n), "order = %d" % n, c, w, [wrong_order]


def modify_generator(group, w):
  modified_generator = flag.Flag(
      label="ModifiedGenerator",
      bug_type=flag.BugType.MODIFIED_PARAMETER,
      description="The generator of the EC group has been modified.",
      effect="The seriousness of the modification depends on whether "
      "the cryptographic primitive uses the generator. In the worst "
      "case such a modification allows an invalid curve attack.")
  c = copy(group)
  g = c.g
  c.g = (0,0)
  yield True, "generator = (0,0)", c, w, [modified_generator]
  c.g = (g[0], g[1]+2)
  yield True, "generator not on curve", c, w, [modified_generator]


def modify_pub_point(group, w):
  modified_public_point = flag.Flag(
      label="ModifiedPublicPoint",
      bug_type=flag.BugType.MODIFIED_PARAMETER,
      description="The public point of the key has been modified and is "
      "not on the curve.",
      effect="Not checking that a public point is on the curve may allow "
      "an invalid curve attack.")
  yield True, "public point not on curve", group, (w[0], w[1] +
                                                   2), [modified_public_point]
  yield True, "public point = (0,0)", group, (0, 0), [modified_public_point]


def modify_curve_with_small_order(group, w):
  weak_public_key = flag.Flag(
      label="WeakPublicKey",
      bug_type=flag.BugType.MODIFIED_PARAMETER,
      description="The vector contains a weak public key. "
      "The curve is not a named curve, the public key point has order 3 "
      "and has been chosen to be on the same curve as the private key. "
      "This test vector is used to check ECC implementations for "
      "missing steps in the verification of the public key.")
  p = group.p
  max_tries = 128
  for j in range(max_tries):
    k = prand.randrange(1, group.n, bytes([j]))
    P = k * group.generator()
    x,y = P.x, P.y
    l = mod_arith.modsqrt(3*x, p)
    if l is None:
      continue
    xx = x*x%p
    a = (2*y*l - 3*x*x)%p
    b = (y*y - x * (xx + a))%p
    c = copy(group)
    c.a = a
    c.b = b
    c.g = (x,y)
    w = (x,(-y)%p)
    yield True, "public key of order 3", c, w, [weak_public_key]
    break


def modify_with_isomorphisms(group, w):
  try:
    y = group.get_point(w[0], w[1])
  except:
    return
  for group2, w2 in ec_groups.isomorphic_points(group, y):
    isomorphic_public_key = flag.Flag(
        label="IsomorphicPublicKey",
        bug_type=flag.BugType.MODIFIED_PARAMETER,
        description="The public key in this test vector uses an isomorphic "
        "curve. Such isomorphisms are sometimes used to speed up "
        "implementations. For example the brainpool curves are using this.")
    yield (True, "public key on isomorphic curve " + group2.name, group2,
           (w2.x, w2.y), [isomorphic_public_key])


def modified_key(key):
  """yields quintuples (isValid, comment, group, w, flags)

     isValid determines whether the key is valid.
  """
  group = key.group
  w = key.w
  yield from modify_pub_point(group, w)
  yield from modify_order(group, w)
  yield from modify_generator(group, w)
  yield from modify_cofactor(group, w)
  yield from modify_point_and_p(group, w)
  yield from modify_group(group, w)
  yield from modify_curve_with_small_order(group, w)
  yield from modify_with_isomorphisms(group, w)


def modify_key(key) -> tuple[bool, str, ec_key.EcPublicKey, list]:
  for v, txt, c, w, flags in modified_key(key):
    yield v, txt, ec_key.EcPublicKey(c, w), flags

# TODO: Instead of using a field encoding, there should be
#   multiple classes. This class uses ASN encoding. Another class would
#   be using PEM, maybe there should be a webcrypto class.
class EcPublicKeyTestVector(test_vector.TestVector):
  """Draft version for test vectors that test importing of EC public keys.

     The test vectors contain modified EC public keys.
     The goal of the test is to recognize if importing the EC public keys
     notices inconsistencies and bad formatting."""
  test_attributes = ["encoded", "p", "n", "a", "b", "gx", "gy", "h", "wx", "wy"]
  group_attributes = ["encoding"]
  schema = {
      # The type depends on the encoding  (ASN, PEM, ...)
      "encoded": {
          "type": AST.Asn,
          "desc": "Encoded EC public key over a prime order field",
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
      "wx": {
          "type": AST.BigInt,
          "desc": "x-coordinate of the public point",
      },
      "wy": {
          "type": AST.BigInt,
          "desc": "y-coordinate of the public point",
      },
  }
  def index(self):
    return self.encoding

class EcPublicKeyVerify(test_vector.TestType):
  """Test vectors of type EcPublicKeyVerify are intended for test
     that check the verification of EC public key.

     In particular, implementations are expected to verify that
     the public key uses a correct encoding, that the public key
     point is on the curve, that the point is not a point of
     low order. If the public key encodes additional parameters
     e.g. cofactor and order then the test expects that
     these parameters are verified."""

class EcPublicKeyTestGroup(test_vector.TestGroup):
  testtype = EcPublicKeyVerify
  vectortype = EcPublicKeyTestVector
  schema = {
    "encoding" : {
        "type" : str,
        "desc" : "the encoding of the encoded keys",
        "enum" : ECKEY_ENCODINGS,
    },
  }

  def __init__(self, encoding):
    super().__init__()
    self.encoding = encoding

  def as_struct(self, sort_by=None):
    if sort_by is None:
      sort_by = "comment"
    group = {}
    group["type"] = self.testtype
    group["encoding"] =  self.encoding
    group["tests"] = self.get_all_vectors(sort_by=sort_by)
    return group

class EcPublicKeyTestGenerator(test_vector.TestGenerator):
  algorithm = "EcPublicKeyTest"

  def __init__(self, encoding):
    assert encoding in ("asn","pem","webcrypto")
    self.encoding = encoding
    self.test = test_vector.Test(self.algorithm)

  def new_testgroup(self, idx):
    return EcPublicKeyTestGroup(idx)

  @util.type_check
  def add_pub(self,
              is_valid: bool,
              comment: str,
              key: ec_key.EcPublicKey,
              flags: Optional[list[flag.Flag]] = None):
    if flags is None:
      flags = []
    flags = self.add_flags(flags)
    result = ["invalid", "valid"][is_valid]
    c = key.group
    w = key.w
    g = c.g
    if self.encoding == "asn":
      encoded = bytearray(key.encode())
    elif self.encoding == "pem":
      encoded = key.pem()
    elif self.encoding == "webcrypto":
      try:
        encoded = key.jwk()
        if encoded == None:
          return
      except Exception:
        # Webcrypt can"t encode most modified keys.
        # We just ignore these keys.
        return
    else:
      raise NotImplementedError("Unknown encoding:" + self.encoding)
    args = {
        "comment" : comment,
        "result" : result,
        "encoded" : encoded,
        "encoding" : self.encoding,
        "p" : AST.BigInt(c.p),
        "n" : AST.BigInt(c.n),
        "a" : AST.BigInt(c.a),
        "b" : AST.BigInt(c.b),
        "gx" : AST.BigInt(c.g[0]),
        "gy" : AST.BigInt(c.g[1]),
        "wx" : AST.BigInt(w[0]),
        "wy" : AST.BigInt(w[1]),
        "flags" : flags}
    if isinstance(c.h, int):
      args["h"] = c.h

    test = EcPublicKeyTestVector(**args)
    self.add_test(test)

  def generate_all(self, curve):
    group = ec_groups.named_curve(curve)
    privkey = prand.randrange(1, group.n, seed="12lk3j123", label=group.name)
    pubkey = ec_key.EcPrivateKey(group, privkey).public()
    self.add_pub(True, "unmodified", pubkey, [flag.NORMAL])
    for v, txt, mod, flags in modify_key(pubkey):
      self.add_pub(v, txt, mod, flags)


class EcPublicKeyProducer(producer.Producer):

  def parser(self):
    res = self.default_parser()
    res.add_argument(
        "--curve", type=str, default="secp256r1", help="the name of the curve")
    res.add_argument(
        "--encoding",
        type=str,
        choices=ECKEY_ENCODINGS,
        default="asn",
        help="the encoding of the EC keys")
    return res

  def generate_test_vectors(self, namespace):
    tv = EcPublicKeyTestGenerator(namespace.encoding)
    curve = getattr(namespace, "curve", "secp256r1")
    tv.generate_all(curve)
    return tv.test


# DEPRECATED: Use Producer.produce() instead
def main(namespace):
  EcPublicKeyProducer().produce(namespace)


if __name__ == "__main__":
  EcPublicKeyProducer().produce_with_args()
