# Copyright 2019 Google Inc. All Rights Reserved.
# Author: bleichen@google.com (Daniel Bleichenbacher)
#
# Generating test cases for ECDH timing tests.
# The main focus here is to generate test cases with special values
# such as 0,1 etc. The motivation for testing with these values is that
# 0 is frequently used in encodings of the point at infinity. Careless
# parsing could lead to easily forgeable signatures.
# So far I"ve only seen DSA implementations that fall for such signatures.
# Though some implementations do have minor flaws.

import amd_sev_ec
import asn
import asn_fuzzing
import AST
import base64
import collections
import ec
import ec_groups
import ec_key
import group
import producer
import special_values_ec
import test_vector
import timing_test_vector
import typing
import util
import prand

def repeat_bits(bits, length, mod):
  res = bits
  while res < mod:
    res = (res << length) | bits
  res &= 2 ** mod.bit_length() - 1
  if res >= mod:
    res &= 2 ** (mod.bit_length() - 1) - 1
  return res

ENCODINGS = ("asn","pem","ecpoint", "jwk", "amd_sev")

# Some definitions for type hints
# A point on a curve.
EcPoint = group.Point

@util.type_check
def ecdh(ec_group: ec_groups.EcGroup, priv: int, pub: ec_key.EcPublicKey):
  """Computes an ECDH exchange over ec_group using a private key priv and
     a public key pub. This function is used to generate test vectors for
     an ECDH key exchange. For some of the test vectors the public key is
     slightly modified. For example, the cofactor might be incorrect.
     The basic rule that we follow here is that ignoring such a change in
     a public key is acceptable as long as this change does not modify
     the result of the ecdh computation. I.e., the private key or the code
     determine, which curve to use. The public key should never define the
     curve.

     The situation is different for X25519 computations, where the public
     key may be on a twist and where an DH exchange using the twisted curve
     is an acceptable outcome. X25519 test vectors are not computed here.
  """
  # Convert the public key into a point from the given group.
  # TODO: The situation where priv and pub are not on the
  #   same curve, but isomorphic curves is not defined.
  #   ECDH implementations would have to agree on which curve to use.
  #   As long as we have no definition, the test vectors will be
  #   invalid, and the shared key included in the test vector will be
  #   the shared key computed on the curve from the private key.
  Y = ec_group.get_point(pub.w[0], pub.w[1])
  S = priv * Y
  return asn.encode_bigint_fixedlength(S.affine_x(), ec_group.encoding_length)

class EcdhEcpointTimingVector(timing_test_vector.TimingTestVector):
  """A pair of points for a timing test.

     Typically one point is a special case, while the other is
     not. The labels define the properties of the public points.
  """
  test_attributes = ["private", "publicA", "publicB"]
  status = "alpha"
  schema = {
    "publicA" : {
       "type" : AST.Der,
       "desc" : "ASN encoded public point",
       "ref" : "X9.62, Section 4.3.6",
    },
    "publicB" : {
       "type" : AST.Der,
       "desc" : "ASN encoded public point",
       "ref" : "X9.62, Section 4.3.6",
    },
    "private" : {
       "type" : AST.BigInt,
       "desc" : "the private key",
    },
  }

  def index(self):
    return self.curve, self.point

class EcdhEcpointTiming(test_vector.TestType):
  """Test vectors of type EcdhEcpointTiming are intended for
     testing an ECDH implementations against timing attacks.

     Each test vector contains two public keys.
     One of them is typically special. A secure implementation
     should not be able to select the special vector through
     timing.
  """

class EcdhEcpointTimingGroup(test_vector.TestGroup):
  testtype = EcdhEcpointTiming
  vectortype = EcdhEcpointTimingVector
  encoding = "ecpoint"
  status = "alpha"
  schema = {
     "curve" : {
         "type" : AST.EcCurve,
         "desc" : "the curve of the private key",
     },
     "specialPoint" : {
         "type" : AST.Der,
         "desc" : "the special point used for the timing attack",
     },
     "encoding" : {
         "type" : str,
         "desc" : "the encoding of the public key",
         "enum" : ["ecpoint"],
     },
  }

  def __init__(self, idx):
    super().__init__()
    curve, point = idx
    self.curve = curve
    self.point = point

  def as_struct(self, sort_by=None):
    if sort_by is None:
      sort_by = "comment"
    group = {}
    group["type"] = self.testtype
    group["curve"] = self.curve
    group["specialPoint"] = self.point
    group["encoding"] = self.encoding
    group["tests"] = self.get_all_vectors(sort_by=sort_by)
    return group

class EcdhTimingVector(timing_test_vector.TimingTestVector):
  """A pair of points for a timing test.

     Typically one point is a special case, while the other is
     not. The labels define the properties of the public points.
  """
  test_attributes = ["private", "publicA", "publicB"]
  status = "alpha"
  schema = {
    "publicAX" : {
       "type" : AST.Der,
       "desc" : "X509 encoded public key",
    },
    "publicB" : {
       "type" : AST.Der,
       "desc" : "X509 encoded public key",
    },
    "private" : {
       "type" : AST.BigInt,
       "desc" : "the private key",
    },
  }

  def index(self):
    return self.curve, self.point

class EcdhTiming(test_vector.TestType):
  """Test vectors of type EcdhTiming are intended for
     testing an ECDH implementations against timing attacks.

     Each test vector contains two public keys.
     One of them is typically special. A secure implementation
     should not be able to select the special vector through
     timing.
  """

class EcdhTimingGroup(test_vector.TestGroup):
  testtype = EcdhTiming
  vectortype = EcdhTimingVector
  encoding = "ecpoint"
  status = "alpha"
  schema = {
     "curve" : {
         "type" : AST.EcCurve,
         "desc" : "the curve of the private key",
     },
     "specialPoint" : {
         "type" : AST.Der,
         "desc" : "the special point used for the timing attack",
     },
     "encoding" : {
         "type" : str,
         "desc" : "the encoding of the public key",
         "enum" : ["ecpoint"],
     },
  }

  def __init__(self, idx):
    super().__init__()
    curve, point = idx
    self.curve = curve
    self.point = point

  def as_struct(self, sort_by=None):
    if sort_by is None:
      sort_by = "comment"
    group = {}
    group["type"] = self.testtype
    group["curve"] = self.curve
    group["specialPoint"] = self.point
    group["encoding"] = self.encoding
    group["tests"] = self.get_all_vectors(sort_by=sort_by)
    return group


class EcdhTimingGenerator(test_vector.TestGenerator):
  algorithm = "ECDH"

  def __init__(self, encoding: str, curve: str):
    """Generates test vectors for timing checks.

    Args:
      encoding: Defines the encoding of the test vectors.
        The following values are possible:
          "asn":  public keys are using the JCE format
          "pem":  public keys are PEM encoded
          "ecpoint": the public key is just a point encoded using
                   SEC1 v2 (Section 2.3.3) format.
          "jwk": public and privare key use the jwk format
      curve: the name of the EC group. (i.e. the name defined in
             ec_groups.py)
    """
    if encoding not in ENCODINGS:
      raise ValueError("Unsupported encoding:" + encoding)
    self.encoding = encoding
    self.curve = curve
    self.group = ec_groups.named_curve(curve)
    self.test = test_vector.Test(self.algorithm)

  def new_testgroup(self, idx):
    if self.encoding == "asn":
      return EcdhTimingGroup(idx)
    elif self.encoding == "jwk":
      return EcdhJwkTimingGroup(idx)
    elif self.encoding == "pem":
      return EcdhPemTimingGroup(idx)
    elif self.encoding == "ecpoint":
      return EcdhEcpointTimingGroup(idx)
    else:
      raise ValueError("Unsupported encoding:" + self.encoding)

  def add_test_vector(self, c, special_point, priv:int, pub_a, pub_b, comment="",
                      flags=None):
    special = c.encode_uncompressed(special_point.affine()).hex()
    if self.encoding == "asn":
      tc = EcdhTimingVector(
               curve = c.name,
               point = special,
               publicA = pub_a.encode_hex(),
               publicB = pub_b.encode_hex(),
               private = AST.BigInt(priv),
               flags = flags)
    elif self.encoding == "pem":
      tc = EcdhPemTimingVector(
               curve = c.name,
               point = special,
               publicA = pub_a.pem(),
               publicB = pub_b.pem(),
               private = AST.BigInt(priv),
               flags = flags)
    elif self.encoding == "ecpoint":
      pub_point_a = pub_a.encode_pub_point()
      pub_point_b = pub_b.encode_pub_point()
      tc = EcdhEcpointTimingVector(
               curve = c.name,
               point = special,
               publicA = pub_point_a.hex(),
               publicB = pub_point_b.hex(),
               private = AST.BigInt(priv),
               flags = flags)
    elif self.encoding == "jwk":
      assert c.jwk()
      privkey = ec_key.EcPrivateKey(c, priv)
      special = special_point.hex()
      pub_a_jwk = pub_a.jwk()
      pub_b_jwk = pub_b.jwk()
      priv_jwk = privkey.jwk()
      if not pub_jwk or not priv_jwk: return
      tc = EcdhWebcryptoTimingVector(
               curve = c.jwk(),
               point = special,
               public = pub_jwk,
               private = priv_jwk,
               shared = sharedbytes,
               flags = flags)
    tc.comment = comment
    self.add_test(tc)

  def public_groups(self) -> list[ec_groups.EcGroup]:
    """Returns the list of groups that the public key
       can belong to. This list can be longer than
       the list of groups that are tested. We mainly
       do this to check for curve switching attacks."""
    if self.encoding == "jwk":
      return ec_groups.jwk_curves
    elif self.encoding == "amd_sev":
      return amd_sev_ec.amd_sev_curves
    else:
      return ec_groups.predefined_curves

  def groups(self):
    """The list of groups being tested."""
    if self.curve == "":
      return self.public_groups()
    else:
      return [ec_groups.named_curve(self.curve)]

  def generate_left_to_right(
          self,
          point: EcPoint,
          bits = None,
          flags_a = None,
          flags_b = None,
          comment = ""):
    n = self.group.n
    label = b"%d" % point.affine_x()
    priv = prand.randrange(n // 2, n, ";1kl24j;oiq2", label)
    priv |= 1

    if bits==None:
      bits = list(range(priv.bit_length()))
    if flags_a is None:
      flags_a = [self.footnote("PublicAIsRight",
                  "PublicA contains a correct guess for the private key")]
    if flags_b is None:
      flags_b = [self.footnote("PublicBIsRight",
                  "PublicB contains a correct guess for the private key")]
    for b in sorted(bits)[::-1]:
      right_guess = priv >> b
      guesses = sorted([right_guess, right_guess ^ 1])
      if 0 in guesses:
        # Can"t compute the inverse:
        continue
      if guesses[0] == right_guess:
        flags = flags_a
      else:
        flags = flags_b
      pubs = [None] * 2
      for i, guess in enumerate(guesses):
        rinv = pow(guess, -1, n)
        Y = (point*rinv).affine()
        pubs[i] = ec_key.EcPublicKey(self.group, Y)
      self.add_test_vector(self.group, point, priv, *pubs, comment, flags)

  def generate_all(self, short_test=False):
    for p, cmt, flats in special_values_ec.special_ec_points_doubling(self.group):
      point = self.group.get_point(*p)
      self.generate_left_to_right(point)


class EcdhTimingProducer(producer.Producer):

  def parser(self):
    res = self.default_parser()
    res.add_argument(
        "--curve",
        type=str,
        default="secp256r1",
        help="the name of the curve of the private key")
    res.add_argument(
        "--encoding",
        type=str,
        choices=ENCODINGS,
        default="asn",
        help="the encoding of public and private keys")
    return res

  def generate_test_vectors(self, namespace):
    tv = EcdhTimingGenerator(namespace.encoding, namespace.curve)
    tv.generate_all()
    return tv.test


# DEPRECATED: Use Producer.produce() instead
def main(namespace):
  EcdhTimingProducer().produce(namespace)


if __name__ == "__main__":
  EcdhTimingProducer().produce_with_args()
