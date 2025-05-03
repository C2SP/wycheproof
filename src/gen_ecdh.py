# Copyright 2016 Google Inc. All Rights Reserved.
# Author: bleichen@google.com (Daniel Bleichenbacher)
#
# Generating test cases for ECDH.
# The main focus here is to generate test cases with special values
# such as 0,1 etc. The motivation for testing with these values is that
# 0 is frequently used in encodings of the point at infinity. Careless
# parsing could lead to easily forgeable signatures.
# So far I've only seen DSA implementations that fall for such signatures.
# Though some implementations do have minor flaws.

# SP800-56a rev 3 specifies ECDH.
# Section 5.6.2.3.3 specifies a full validation of public keys and ephemeral
# keys. Section 5.6.2.3.4 specifies a partial validation of public keys.
# NIST comments that using a partial validation may be acceptable for ephemeral
# keys.
# Full validation includes checking that the ephemeral key is not the point
# at infinity, that the point is on the curve and that the point is in the
# subgroup of order n. I.e. by verifying that P*n == infty.
# Partial validation checks that the ephemeral key is not the point at infinity
# and that the point is on the curve. I'm unsure whether an additional check
# is required for the ECDH result.

# References:
# -----------
# Invalid curve attack:
#
# I. Biehl, B. Meyer and V. Muller ¨ , “Differential fault analysis on elliptic
# curve cryptosystems”, Advances in Cryptology—CRYPTO 2000, Lecture Notes
# in Computer Science, vol. 1880 (2000), 131-146. 215, 216
#
# Validation of Elliptic Curve Public Keys
# Adrian Antipa, Daniel Brown, Alfred Menezes,
# Rene Struik, and Scott Vanstone
# https://www.iacr.org/archive/pkc2003/25670211/25670211.pdf
#
# CVEs:
# CVE-2020-28498
# CVE-2019-6486
# CVE-2019-9155
# CVE-2017-16007
# CVE-2015-7940
# CVE-2015-7511
# ...

# TODO:
#   - add test vectors for ECDH variants with cofactor (i.e. ECDHE and ECDHC)

import amd_sev_ec
import asn
import asn_fuzzing
import asn_parser
import AST
import base64
import collections
import ec
import ec_groups
import ec_key
import flag
import gen_eckey
import math
import mod_arith
import producer
import pem_util
import special_values_ec
import test_vector
import util
import prand
from collections.abc import Iterator
from typing import Optional

def repeat_bits(bits, length, mod):
  res = bits
  while res < mod:
    res = (res << length) | bits
  res &= 2 ** mod.bit_length() - 1
  if res >= mod:
    res &= 2 ** (mod.bit_length() - 1) - 1
  return res


ENCODINGS = ("asn", "pem", "ecpoint", "webcrypto", "amd_sev")

# ---- Generally used flags
distinct_curves = flag.Flag(
    label="WrongCurve",
    bug_type=flag.BugType.CONFIDENTIALITY,
    description="The public key and private key use distinct curves. "
    "Implementations are expected to reject such parameters.",
    effect="Computing an ECDH key exchange with public and private keys "
    "can in the worst case lead to an invalid curve attack. Hence, it is "
    "important that ECDH implementations check the input parameters. "
    "The severity of such bugs is typically smaller if an implementation "
    "ensures that the point is on the curve and that the ECDH computation "
    "is performed on the curve of the private key. "
    "Some of the test vectors with modified public key contain shared "
    "ECDH secrets, that were computed over the curve of the private key.",
    links=["https://link.springer.com/content/pdf/10.1007/3-540-44598-6_8.pdf",
    "https://www.iacr.org/archive/pkc2003/25670211/25670211.pdf"])
# Used for typical situation of an invalid curve attack:
# Namely the situation where the point on the public key is wrong.
invalid_curve_attack = flag.Flag(
    label="InvalidCurveAttack",
    bug_type=flag.BugType.CONFIDENTIALITY,
    description="The point of the public key is not on the curve. ",
    effect="If an implementation does not check whether a point is on the "
    "curve then it is likely that the implementation is susceptible to "
    "an invalid curve attack. Many implementations compute the shared "
    "ECDH secret over a curve defined by the point on the public key. "
    "This curve can be weak and hence leak information about the private "
    "key.",
    links=["https://link.springer.com/content/pdf/10.1007/3-540-44598-6_8.pdf",
    "https://www.iacr.org/archive/pkc2003/25670211/25670211.pdf"])


@util.type_check
def ecdh(ec_group: ec_groups.EcGroup, priv: int,
         pub: ec_key.EcPublicKey) -> bytes:
  """Computes an ECDH exchange.

  Compute an ECDH exchange over ec_group using a private key priv and
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

  Args:
    ec_group: the group for the ECDH exchange
    priv: the private key
    pub: the public key
  Returns: the x-coordinate of the shared secret point as an encoded field
    element.
  """
  # Convert the public key into a point from the given group.
  # TODO: The situation where priv and pub are not on the
  #   same curve, but isomorphic curves is not defined.
  #   ECDH implementations would have to agree on which curve to use.
  #   As long as we have no definition, the test vectors will be
  #   invalid, and the shared key included in the test vector will be
  #   the shared key computed on the curve from the private key.
  Y = ec_group.get_point(pub.w[0], pub.w[1])
  s = priv * Y
  return ec_group.encode_field_element(s.affine_x())

class EcdhTestVector(test_vector.TestVector):
  test_attributes = ["public", "private", "shared"]
  schema = {
      "public": {
          "type": AST.Asn,
          "short": "X509 encoded public key",
          "desc": "X509 encoded public key. "
                  "The encoding of the public key contains the type of "
                  "the public key, the curve and possibly the curve "
                  "parameters. The test vectors contain cases where these "
                  "fields do not match the curve in the testGroup. ",
      },
      "private": {
          "type": AST.BigInt,
          "desc": "the private key",
      },
      "shared": {
          "type": AST.HexBytes,
          "short": "The shared secret key",
          "desc": "The shared secret key. Some invalid test vectors "
                  "contain a shared secret, which is computed using "
                  "the curve of the private key. This allows to distinguish "
                  "between implementations ignoring public key schema and "
                  "implementations using the curve of the public key."
      }
  }

  @util.type_check
  def index(self) -> str:
    return self.curve


class EcdhWebcryptoTestVector(test_vector.TestVector):
  test_attributes = ["public", "private", "shared"]

  schema = {
      "public": {
          "type": "Json",
          "desc": "Valid or invalid public key in webcrypto format",
      },
      "private": {
          "type": ec_key.JwkEcPrivateKey,
          "desc": "Private key in webcrypto format",
      },
      "shared": {
          "type": AST.HexBytes,
          "desc": "The shared secret key"
      }
  }

  @util.type_check
  def index(self) -> str:
    return self.curve

class EcdhPemTestVector(test_vector.TestVector):
  test_attributes = ["public", "private", "shared"]

  schema = {
      "public": {
          "type": AST.Pem,
          "short": "Pem encoded public key",
          "desc":
              "Pem encoded public key. "
              "The test vectors check against invalid curve attacks. "
              "Hence some test vectors contain keys that are not on the curve, "
              "test vectors that use different curve or even public keys from "
              "different primitives. ",
      },
      "private": {
          "type": AST.Pem,
          "short": "Pem encoded private key",
          "desc": "Pem encoded private key. The key is always valid.",
      },
      "shared": {
          "type": AST.HexBytes,
          "desc": "The shared secret key"
      },
  }

  @util.type_check
  def index(self) -> str:
    return self.curve

class EcdhEcpointTestVector(test_vector.TestVector):
  test_attributes = ["public", "private", "shared"]

  schema = {
      "public": {
          "type": AST.Asn,
          "desc": "ASN encoded public point",
          "ref": "X9.62, Section 4.3.6",
      },
      "private": {
          "type": AST.BigInt,
          "desc": "The private exponent",
      },
      "shared": {
          "type": AST.HexBytes,
          "desc": "The shared secret key"
      },
  }

  @util.type_check
  def index(self) -> str:
    return self.curve


class EcdhTest(test_vector.TestType):
  """Test vectors of type EcdhTest are intended for
     testing an ECDH implementations using X509 encoded
     public keys and integers for private keys.
     Test vectors of this format are useful for testing
     Java providers.
  """

class EcdhTestGroup(test_vector.TestGroup):
  testtype = EcdhTest
  vectortype = EcdhTestVector
  encoding = "asn"
  schema = {
      "curve": {
          "type": AST.EcCurve,
          "desc": "the curve of the private key",
      },
      "encoding": {
          "type": str,
          "short": "the encoding of the public key",
          "desc": "the encoding of the keys. There are test vector "
                  "files for a number of encodings (raw, asn, pem, ...) "
                  "to simplify testing libraries that only allow keys with "
                  "certain encodings. This field however, has become "
                  "somewhat redundant, since the schema defines the format.",
          "enum": ["asn"],
          "optional": True,
      },
  }

  @util.type_check
  def __init__(self, curve: str):
    super().__init__()
    self.curve = curve

  def as_struct(self, sort_by=None):
    if sort_by is None:
      sort_by = "comment"
    group = {}
    group["type"] = self.testtype
    group["curve"] = self.curve
    group["encoding"] = self.encoding
    group["tests"] = self.get_all_vectors(sort_by=sort_by)
    return group

class EcdhWebcryptoTest(test_vector.TestType):
  """Test vectors of type EcdhWebTest are intended for
     testing an ECDH implementations using jwk encoded
     public and private keys.
  """

class EcdhWebcryptoTestGroup(test_vector.TestGroup):
  testtype = EcdhWebcryptoTest
  vectortype = EcdhWebcryptoTestVector
  encoding = "webcrypto"
  schema = {
      "curve": {
          "type": AST.EcCurve,
          "desc": "the curve of the private key",
      },
      "encoding": {
          "type": str,
          "desc": "the encoding of the keys",
          "enum": ["webcrypto"],
          "optional": True,
      },
  }

  @util.type_check
  def __init__(self, curve: str):
    super().__init__()
    self.curve = curve

  def as_struct(self, sort_by: Optional[str] = None) -> dict:
    if sort_by is None:
      sort_by = "comment"
    group = {}
    group["type"] = self.testtype
    group["curve"] = self.curve
    group["encoding"] = self.encoding
    group["tests"] = self.get_all_vectors(sort_by=sort_by)
    return group

class EcdhPemTest(test_vector.TestType):
  """Test vectors of type EcdhWebTest are intended for
     testing an ECDH implementations using PEM encoded
     public and private keys.
  """

class EcdhPemTestGroup(test_vector.TestGroup):
  testtype = EcdhPemTest
  vectortype = EcdhPemTestVector
  encoding = "pem"
  schema = {
      "curve": {
          "type": AST.EcCurve,
          "desc": "the curve of the private key",
      },
      "encoding": {
          "type": str,
          "desc": "the encoding of the keys",
          "enum": ["pem"],
          "optional": True,
      },
  }

  @util.type_check
  def __init__(self, curve: str):
    super().__init__()
    self.curve = curve

  def as_struct(self, sort_by: Optional[str] = None) -> dict:
    if sort_by is None:
      sort_by = "comment"
    group = {}
    group["type"] = self.testtype
    group["curve"] = self.curve
    group["encoding"] = self.encoding
    group["tests"] = self.get_all_vectors(sort_by=sort_by)
    return group

class EcdhEcpointTest(test_vector.TestType):
  """Test vectors of type EcdhWebTest are intended for
     testing an ECDH implementations where the public key
     is just an ASN encoded point.
  """

class EcdhEcpointTestGroup(test_vector.TestGroup):
  testtype = EcdhEcpointTest
  vectortype = EcdhEcpointTestVector
  encoding = "ecpoint"
  schema = {
      "curve": {
          "type": AST.EcCurve,
          "desc": "the curve of the private key",
      },
      "encoding": {
          "type": str,
          "desc": "the encoding of the public key",
          "enum": ["ecpoint"],
          "optional": True,
      },
  }

  @util.type_check
  def __init__(self, curve: str):
    super().__init__()
    self.curve = curve

  def as_struct(self, sort_by: Optional[str] = None) -> dict:
    if sort_by is None:
      sort_by = "comment"
    group = {}
    group["type"] = self.testtype
    group["curve"] = self.curve
    group["encoding"] = self.encoding
    group["tests"] = self.get_all_vectors(sort_by=sort_by)
    return group


class EcdhAmdSevTestVector(test_vector.TestVector):
  test_attributes = ["public", "private", "shared"]
  status = "alpha"
  schema = {
      "public": {
          "type": AST.HexBytes,
          "short": "ECDH public key",
          "desc":
              "ECDH public key."
              "The encoding of the public key is described in Section C.3.3 "
              "of AMD\'s Secure encrypted Virtualization API (Version 0.17)",
      },
      "private": {
          "type": AST.HexBytes,
          "desc": "the private key using little endian encoding",
      },
      "shared": {
          "type": AST.HexBytes,
          "short": "The shared secret key",
          "desc": "The shared secret key. Some invalid test vectors "
                  "contain a shared secret, which is computed using "
                  "the curve of the private key. This allows to distinguish "
                  "between implementations ignoring public key info and "
                  "implementations using the curve of the public key."
      }
  }

  @util.type_check
  def index(self) -> str:
    return self.curve

class EcdhAmdSevTest(test_vector.TestType):
  """Test vectors of type EcdhAmdSevTest are intended for
     testing an ECDH implementations of AMD's
     Secure Encrypted Viratlization API.
  """
  status = "alpha"

class EcdhAmdSevTestGroup(test_vector.TestGroup):
  testtype = EcdhAmdSevTest
  vectortype = EcdhAmdSevTestVector
  encoding = "amd_sev"
  status = "alpha"
  info = {
      "curve": {
          "type": AST.EcCurve,
          "desc": "the curve of the private key",
      },
      "encoding": {
          "type": str,
          "short": "the encoding of the keys",
          "desc": "the enconding of the keys."
                  " The field has become redundant, since the encoding"
                  " is already implied by the schema.",
          "enum": ["amd_sev"],
          "optional": True,
      },
  }

  def __init__(self, curve: str):
    super().__init__()
    self.curve = curve

  def as_struct(self, sort_by: Optional[str] = None) -> dict:
    if sort_by is None:
      sort_by = "comment"
    group = {}
    group["type"] = self.testtype
    group["curve"] = self.curve
    group["encoding"] = self.encoding
    group["tests"] = self.get_all_vectors(sort_by=sort_by)
    return group


class EcdhTestGenerator(test_vector.TestGenerator):
  algorithm = "ECDH"

  def __init__(self, encoding: str, curve: str):
    """
       Args:
          encoding: defines the encoding of the test vectors.
              asn:  public keys are using the JCE format
              pem:  public keys are PEM encoded
              ecpoint: the public key is just a point encoded using
                       SEC1 v2 (Section 2.3.3) format.
              webcrypto: public and privare key use the jwk format
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
      return EcdhTestGroup(idx)
    elif self.encoding == "webcrypto":
      return EcdhWebcryptoTestGroup(idx)
    elif self.encoding == "pem":
      return EcdhPemTestGroup(idx)
    elif self.encoding == "ecpoint":
      return EcdhEcpointTestGroup(idx)
    elif self.encoding == "amd_sev":
      return EcdhAmdSevTestGroup(idx)
    else:
      raise ValueError("Unsupported encoding:" + self.encoding)

  def test_compressed(self):
    return self.encoding != "webcrypto" and self.encoding != "amd_sev"

  @util.type_check
  def add_test_vector(self,
                      c: ec_groups.EcGroup,
                      validity: str,
                      priv: int,
                      pub: ec_key.EcPublicKey,
                      shared: Optional[bytes] = None,
                      comment: str = "",
                      flags: Optional[list[flag.Flag]] = None):
    flags = self.test.footnotes().add_flags(flags)
    if shared is None:
      try:
        shared = ecdh(c, priv, pub)
      except Exception:
        shared = b""
    if flags is None:
      flags = []
    flags = flags + pub.flags(self.footnotes())
    sharedbytes = shared.hex()
    if self.encoding == "asn":
      tc = EcdhTestVector(
               curve = c.name,
               public = pub.encode_hex(),
               private = AST.BigInt(priv),
               shared = sharedbytes,
               flags = flags)
    elif self.encoding == "pem":
      tc = EcdhPemTestVector(
          curve=c.name,
          public=pub.pem(),
          private=ec_key.EcPrivateKey(c, priv).pem(),
          shared=sharedbytes,
          flags=flags)
    elif self.encoding == "ecpoint":
      # Test vectors with modified parameters can"t be used here.
      if not pub.verify_named_curve():
        return
      pub_point = pub.encode_pub_point()
      tc = EcdhEcpointTestVector(
               curve = c.name,
               public = pub_point.hex(),
               private = AST.BigInt(priv),
               shared = sharedbytes,
               flags = flags)
    elif self.encoding == "webcrypto":
      assert c.jwk()
      privkey = ec_key.EcPrivateKey(c, priv)
      pub_jwk = pub.jwk()
      priv_jwk = privkey.jwk()
      if not pub_jwk or not priv_jwk: return
      tc = EcdhWebcryptoTestVector(
               curve = c.jwk(),
               public = pub_jwk,
               private = priv_jwk,
               shared = sharedbytes,
               flags = flags)
    elif self.encoding == "amd_sev":
      try:
        encoded = amd_sev_ec.encode_ec_public(pub)
        encoded_priv = amd_sev_ec.encode_ec_private(priv)
      except ValueError:
        return
      tc = EcdhAmdSevTestVector(
               curve = c.name,
               public = encoded,
               private = encoded_priv,
               shared = sharedbytes,
               flags = flags)
    tc.result = validity
    tc.comment = comment
    self.add_test(tc)

  def public_groups(self):
    """Returns the list of groups that the public key
       can belong to. This list can be longer than
       the list of groups that are tested. We mainly
       do this to check for curve switching attacks."""
    if self.encoding == "webcrypto":
      return ec_groups.jwk_curves
    elif self.encoding == "amd_sev":
      return amd_sev_ec.amd_sev_curves
    else:
      return ec_groups.predefined_curves


  def generate_special_private_key(self):
    g = self.group
    spec_keys = collections.defaultdict(list)
    n = g.n
    for k in [
        3,
        2**(n.bit_length() - 1),
        2**(n.bit_length() - 1) - 1,
        2**(n.bit_length() - 8),
        2**(n.bit_length() - 32) - 1,
        n - 3,
        n - 2**32,
        n - 2**51,
        n - 2**52,
        n - 2**64,
    ]:
      spec_keys[k] = []
    flag_addsubchain = flag.Flag(
        label="AddSubChain",
        bug_type=flag.BugType.KNOWN_BUG,
        description="The private key has been constructed to test "
        "for arithmetic errors. "
        "Implementations using addition subtraction chains for the "
        "point multiplication may get the point at infinity as "
        "an intermediate result. ",
        cves=["CVE_2017_10176"])
    flag_addchain = flag.Flag(
        label="AdditionChain",
        bug_type=flag.BugType.KNOWN_BUG,
        description="The private key has an unusual bit pattern, "
        "such as high or low Hamming weight. "
        "The goal is to test edge cases for addition chain "
        "implementations.")
    k2 = prand.randrange(1, n, seed=b"1;2kl3j12h", label=g.name)
    pub = ec_key.EcPrivateKey(g, k2).public()
    for k in set(n - 2 * (-n % 2**i) for i in range(8)):
      if k < n:
        spec_keys[k] += [flag_addchain]
    for k in sorted(spec_keys):
      flags = spec_keys[k] or [flag_addchain]
      self.add_test_vector(g, "valid", k, pub, None,
                               "edge case private key", flags)

  def generate_shared_point_on_two_curves(self):
    """Generates test vectors with a point shared by two curves."""
    priv_group = self.group
    for pub_group in self.public_groups():
      if not isinstance(priv_group, ec_groups.EcPrimeGroup):
        continue
      if not isinstance(pub_group, ec_groups.EcPrimeGroup):
        continue
      if priv_group == pub_group:
        continue
      for x, y in special_values_ec.shared_points(priv_group, pub_group):
        priv = prand.randrange(
            1, priv_group.n, seed=b"j12;4jsdf23e4", label=pub_group.name)
        comment = ("public key uses %s with a point shared with %s" %
                   (pub_group.name, priv_group.name))
        pub = ec_key.EcPublicKeyOnNamedCurve(pub_group, (x, y))
        self.add_test_vector(
            priv_group,
            "invalid",
            priv,
            pub,
            None,
            comment=comment,
            flags=[distinct_curves])

  def generate_low_order_invalid_public_key(self):
    g = self.group
    for pt, g2_name, order in special_values_ec.special_ec_points_alt_group(g):
      g2 = ec_groups.named_curve(g2_name)
      pub = ec_key.EcPublicKeyOnNamedCurve(g2, pt)
      comment = ("public key is a low order invalid point on %s. " % g2_name +
                 " The point of the public key is a valid on %s." % g.name)
      priv0 = prand.randrange(order, g.n, seed=b"lk12j4ac3t5", label=g2_name)
      # Choose the private key such that the ECDH secret is either the point at
      # infinitiy or on g assuming that ECDH is computed on an invalid curve.
      priv1 = priv0 - priv0 % order
      for priv in [priv1, priv1 - 1]:
        self.add_test_vector(
            g, "invalid", priv, pub, comment=comment, flags=[distinct_curves])

  def generate_special_case_invalid_public_key(self):
    """Generates test vectors with invalid special case public keys.

    This function generates test vectors where private and public keys
    use different groups and where the point of the public key is a point on
    the curve of the private key. The public point has a y-coordinate
    congruent to 0 on the curve of the public key. Hence it is not on the
    public curve and would have order 2 if no point validation is done.
    """
    g_priv = self.group
    for g_pub in self.public_groups():
      if not isinstance(g_priv, ec_groups.EcPrimeGroup):
        continue
      if not isinstance(g_pub, ec_groups.EcPrimeGroup):
        continue
      p_priv = g_priv.p
      p_pub = g_pub.p
      if p_priv == p_pub:
        # Tested in generate_low_order_invalid_public_key
        continue
      if p_priv.bit_length() != p_pub.bit_length():
        continue
      for x in [p_pub]:
        y = g_priv.get_y(p_pub)
        if y is not None:
          priv = prand.randrange(
              1, g_priv.n, seed=b"j12;4jsdf23e4", label=g_pub.name)
          comment = (
              f"public key has invalid point of order 2 on {g_pub.name}. "
              f"The point of the public key is a valid on {g_priv.name}.")
          pub = ec_key.EcPublicKeyOnNamedCurve(g_pub, (x, y))
          if g_priv == g_pub:
            flags = [invalid_curve_attack]
          else:
            flags = [distinct_curves]
          self.add_test_vector(
              g_priv, "invalid", priv, pub, None, comment=comment, flags=flags)

  def generate_pseudorandom_test_vectors(self, compressed: bool) -> None:
    """Generate some normal test vectors pseudorandomly.

    Args:
      compressed: if True then the public keys used compressed points.
    """
    flag_compressed = flag.Flag(
        label="CompressedPublic",
        bug_type=flag.BugType.FUNCTIONALITY,
        description="The public key in the test vector is compressed. "
        "Some implementations do not support compressed points.")
    g = self.group
    k1 = prand.randrange(1, g.n, seed=b"1283718adfa31", label=g.name)
    k2 = prand.randrange(1, g.n, seed=b"91902371k123a", label=g.name)
    pub = ec_key.EcPrivateKey(g, k2).public()
    if compressed:
      pub.compressed = True
      self.add_test_vector(
          g,
          "acceptable",
          k1,
          pub,
          None,
          "compressed public key",
          flags=[flag_compressed])
    else:
      self.add_test_vector(
          g, "valid", k1, pub, None, "normal case", flags=[flag.NORMAL])

  @util.type_check
  def low_order_points_on_curve(self,
                                ec_group: ec_groups.EcGroup):
    """Yields points points of low order on the curve, but not in the group.
    
    These are the points on the curve with an order that divides the cofactor.
    
    Args:
      ec_group: the group
    """
    if hasattr(ec_group, "low_order_points"):
      yield from ec_group.low_order_points()

  @util.type_check
  def low_order_points_on_twist(self,
                                ec_group: ec_groups.EcPrimeGroup,
                                max_order: int = 11):
    """Returns points of low order on the twist of a curve.

    There is no guarantee that all points of low order will be found.
    In particular, if the group of points on the twist is not cyclic, then
    points will be missing.

    Args:
      ec_group: the EC group
      max_order: the maximal order of a point on the twist
    """
    p = ec_group.p
    order = ec_group.n * ec_group.h
    assert -1 <= p.bit_length() - order.bit_length() <= 1
    if p % 4 == 3:
      twist = ec_group.curve.twist()
      order_twist = 2*(p+1) - ec_group.n * ec_group.h
      x = 1
      S = set()
      for order in range(2, max_order + 1):
        m = order_twist
        exp = 0
        # find m, exp such that exp maximal and m * order^exp = order_twist.
        while m % order == 0:
          exp += 1
          m //= order
        if exp == 0:
          continue
        x = 0
        while x < 32:
          x += 1
          P = twist.point_from_x(x)
          if not P:
            continue
          # find point of order m
          Q = P * m
          if not Q:
            continue
          for i in range(exp):
            R = Q * order
            if not R:
              break
            Q = R
          else:
            raise Exception("Invalid order of twist")
          found = True
          for j in range(1, order):
            if math.gcd(j, order) != 1 and not j * Q:
              found = False
              break
          if found:
            for j in range(1, order):
              if math.gcd(j, order) == 1:
                yield j * Q, order
          break

  # TODO: use in other places too.
  def special_points_ec_prime_group(
      self, ec_group: ec_groups.EcPrimeGroup,
      pt_name: str) -> Iterator[tuple[tuple[int, int], str, list[flag.Flag]]]:
    p = ec_group.p
    S = collections.OrderedDict()
    # x is special
    for x in (0, 1, 2, 3):
      y = ec_group.get_y(x)
      if y:
        S[x, y] = f"{pt_name} has x-coordinate {x}"
    for x in (1, 2, 3):
      y = ec_group.get_y(p - x)
      if y:
        S[p - x, y] = f"{pt_name} has x-coordinate p-{x}"
    for exp in [16, 32, 64, 96]:
      x = 2**exp
      i = 0
      while (y := ec_group.get_y(x + i)) is None:
        i += 1
      S[x + i, y] = f"{pt_name} has x-coordinate 2**{exp} + {i}"
    # x^2 + a is special
    a = ec_group.a
    for i in range(-8, 10):
      x = mod_arith.modsqrt(i - a, p)
      if x is None:
        continue
      y = ec_group.get_y(x)
      if y is None:
        continue
      if (a + 3) % p == 0:
        x2 = x**2 % p
        if 2 * x2 > p:
          x2 -= p
        comment = f"{pt_name} has x-coordinate that satisfies x**2 = {x2}"
      else:
        comment = f"{pt_name} has x-coordinate that satisfies x**2 + a = {i}"
      S[x, y] = comment
    # Adds a few more coordinates to check for arithmetic errors.
    for a in (-2, -1, 1, 2):
      for exp in (32, 48, 64, 96):
        s = 2**exp + a
        if s < 0:
          txt = f"2**{exp} - {-a}"
        else:
          txt = f"2**{exp} + {a}"
      x = mod_arith.modsqrt(s, p)
      if x is None:
        continue
      y = ec_group.get_y(x)
      if y is None:
        continue
      comment = f"{pt_name} has x-coordinate that satisfies x**2 = {txt}"
      S[x, y] = comment

    # x has a bit pattern
    for limb_length in 2, 4, 8, 16, 30, 32, 51, 52, 60, 62, 64, 112, 128:
      b0 = 2**((limb_length + 1) // 2) - 1
      b1 = b0 << (limb_length // 2)
      for b in (b0, b1):
        x = repeat_bits(b, limb_length, p)
        while True:
          y = ec_group.get_y(x)
          if y:
            S[x, y] = (f"{pt_name} has x-coordinate with repeating bit-pattern"
                       f" of size {limb_length}")
            break
          x = (x - 1) % p
    # try some fractions, since openjdk's secp256k1 curve fails with x approx p/3
    for q in range(3, 10, 2):
      x = p // q
      while True:
        y = ec_group.get_y(x)
        if y:
          S[x, y] = f"{pt_name} has an x-coordinate of approx p//{q}"
          break
        x = (x + 1) % p
    for p in S:
      yield p, S[p], []
    # This is a list of precomputed points, where both x and y have
    # some special pattern.
    yield from special_values_ec.special_ec_points(ec_group)

  # TODO: Maybe compute isomorphisms over all these points.
  # TODO: Extend to more polynomials (like XDH does)
  @util.type_check
  def special_points(
      self, ec_group: ec_groups.EcGroup, point_name: str
  ) -> Iterator[tuple[tuple[int, int], str, list[flag.Flag]]]:
    if isinstance(ec_group, ec_groups.EcPrimeGroup):
      yield from self.special_points_ec_prime_group(ec_group, point_name)


  def generate_low_order_public_key_on_twist(self):
    c = self.group
    if not isinstance(c, ec_groups.EcPrimeGroup):
      return
    for p, order in self.low_order_points_on_twist(c):
      priv = prand.randrange(1, c.n, seed=b";lk21j4;wqoier%d" % p.affine_x())
      priv -= priv % order
      px, py = p.affine()
      if py % 2 == 0:
        priv += 1
      # Use negative value of x.
      # p is a point on the curve y^2 = x^3 + a x - b.
      # However we need points on a curve Dy^2 = x^3 + a x + b,
      # where D is a quadratic non-residue. The compressed point
      # then has an invalid x-coordinate, with the property that
      # an implementation using the x-coordinate only would likely
      # perform a multiplication in a low order group.
      # TODO: Maybe add a quadratic non-residue to each field
      x = -px % c.p
      if c.curve.point_from_x(x) is None:
        pub = ec_key.EcPublicKey(c, (x, py), compressed=True)
        self.add_test_vector(
            c,
            "invalid",
            priv,
            pub,
            None,
            "public key is a low order point on twist",
            flags=[distinct_curves])

  def generate_low_order_public_key_on_curve(self):
    low_order_public = flag.Flag(
        label="LowOrderPublic",
        bug_type=flag.BugType.WEAK_PARAMS,
        description="The public key is a point with low order an hence invalid. "
        "Such keys should be rejected if the ECDH primitive does a full public key"
        " validation. It may be accepted if only a partial key validation"
        " is performed.")
    c = self.group
    for pt in self.low_order_points_on_curve(c):
      pub = ec_key.EcPublicKey(c, pt.affine())
      s = prand.randrange(1, c.n, seed=b";akdfe%d" % pt.affine_x())
      s -= s % c.h
      self.add_test_vector(
          c, "invalid", s, pub, None,
          "public key is low order point and shared "
          "secret is point at infinity", [low_order_public])
      for j in range(c.h):
        if math.gcd(j, c.h) == 1:
          priv = s + j
          self.add_test_vector(
              c, "acceptable", priv, pub, None,
              "public key is a low order point on the curve",
              [low_order_public])

  def generate_special_points(self):
    """Generates test vectors where the shared secret is an edge case."""
    edge_case_shared = flag.Flag(
        label="EdgeCaseSharedSecret",
        bug_type=flag.BugType.EDGE_CASE,
        description="The test vector contains a public key and private key "
        "such that the shared ECDH secret is a special case. The goal of "
        "this test vector is to detect arithmetic errors.",
        effect="The seriousness of an arithmetic error is unclear. "
        "It requires further analysis to determine if the bug is "
        "exploitable.")
    c = self.group
    for pt, comment, flags in self.special_points(c, "shared secret"):
      x, y = pt
      if comment is None:
        comment = "edge case for shared secret"
      priv = prand.randrange(1, c.n, seed=b";jlk3214h1uj4")
      k = pow(priv, -1, c.n)
      pubpoint = k * c.get_point(x, y)
      pub = ec_key.EcPublicKey(c, pubpoint.affine())
      self.add_test_vector(c, "valid", priv, pub, None, comment,
                               [edge_case_shared])

  def generate_invalid_points(self):
    c = self.group
    if isinstance(c, ec_groups.EcPrimeGroup):
      p = c.p
      special_values = [0, 1, p - 1, p]
    else:
      return
    priv = prand.randrange(1, c.n, seed=b"asdfk12kl44d")
    for x in special_values:
      for y in special_values:
        if c.is_on_curve(x, y):
          continue
        pub = ec_key.EcPublicKey(c, (x, y))
        self.add_test_vector(c, "invalid", priv, pub, None,
                                 "point is not on curve",
                                 [invalid_curve_attack])

  def generate_invalid_point_encodings(self):
    invalid_encoding = flag.Flag(
        label="InvalidEncoding",
        bug_type=flag.BugType.MODIFIED_PARAMETER,
        description="The test vector contains a public key with an invalid "
        "encoding.")
    c = self.group
    priv = prand.randrange(1, c.n, seed=b"asdfk12kl44d")
    for enc in [b""]:
      pub = ec_key.EcPublicKey(c, encoded_point=enc)
      self.add_test_vector(c, "invalid", priv, pub, None, "",
                               [invalid_encoding])

  def generate_special_public_key(self):
    """Generates test vectors where the public key is an edge case."""
    edge_case_ephemeral = flag.Flag(
        label="EdgeCaseEphemeralKey",
        bug_type=flag.BugType.EDGE_CASE,
        description="The test vector contains an ephemeral public key "
        "that is an edge case.")
    c = self.group
    for pt, cmt, flags in self.special_points(c, "ephemeral key"):
      if cmt is None:
        cmt = "edge cases for ephemeral key"
      priv = prand.randrange(1, c.n, "19i12y4pafewr")
      pub = ec_key.EcPublicKey(c, pt)
      self.add_test_vector(c, "valid", priv, pub, None, cmt,
                               flags + [edge_case_ephemeral])

  def generate_special_case_doublings(self):
    g = self.group
    # Generates private keys with msb and lsb set.
    priv = prand.randrange(g.n // 2, g.n, "12835jk1h3jk1")
    priv |= 1
    for p, cmt, flags in special_values_ec.special_ec_points_doubling(g):
      # Generates special cases for left to right addition chains.
      x, y = p
      pt = g.get_point(x, y)
      n = g.n.bit_length()
      bits = {1, 2, 8, 48, 49, 50, 63, 64, 127, 128, 254, 255, 256, 257}
      bits |= {n - x for x in bits if x < n}
      ml2r = set(priv >> b for b in bits)
      for r in sorted(ml2r):
        if r:
          comment = cmt
          # Add comment if triggering the special case likely indicates
          # that left to right addition chains are used.
          if r.bit_length() > 32:
            comment += " in left to right addition chain"
          rinv = pow(r, -1, g.n)
          Y = (pt*rinv).affine()
          pub = ec_key.EcPublicKey(g, Y)
          self.add_test_vector(g, "valid", priv, pub, None, comment, flags)
      # Generates special cases, where the special point occurs
      # after a number of doublings. Situations where the ephemeral key
      # is multiplied by a power of two occur in right to left addition
      # chains and addition chains with precomputation.
      priv = prand.randrange(g.n // 2, g.n, "1l12j312341")
      priv |= 1
      exponents = [3, 4, 5, 6, 7, 8, 32, 60, 127, 128, 210]
      for e in exponents:
        r = 2**e
        if r > g.n:
          continue
        rinv = pow(r, -1, g.n)
        Y = (pt * rinv).affine()
        pub = ec_key.EcPublicKey(g, Y)
        comment = cmt
        # Small exponents test precomputation in windowed addition chains
        # and right to left addition chains. Large exponents test just
        # right to left addition chains.
        if e <= 8:
          comment += " in precomputation or right to left addition chain"
        else:
          comment += " in right to left addition chain"
        self.add_test_vector(g, "valid", priv, pub, None, comment, flags)

  def generate_third_party_cases(self):
    """Generates test vectors for known vulnerabilities.

       Typically these are published test vectors that failed some
       implementations.
    """
    # CVE-2017-10176
    c = ec_groups.curveP521
    if c == self.group:
      gx = int("26617408020502170632287687167233609607298591687569"
               "73147706671368418802944996427808491545080627771902"
               "35209424122506555866215711354557091681416163731589"
               "5999846")
      gy = int("37571800257700204635455072244911836035944551347697"
               "62486694567779615544477440556316691234405012945539"
               "56214444453728942852258566672919658081012434427757"
               "8376784")
      sk = int("68647976601306097149819007990813932172694353001433"
               "05409394463459185543183397655394245057746333217197"
               "53296399637136332111386476861244038034037280889270"
               "7005431")
      pub = ec_key.EcPublicKey(c, (gx, gy))
      comment = "CVE-2017-10176: Issue with elliptic curve addition"
      cve_2017_10176 = flag.Cve(
          "CVE_2017_10176",
          "This test vector leads to an EC point multiplication where "
          "an intermediate result can be the point at infinity, if "
          "addition-subtraction chains are used to speed up the point "
          "multiplication.")
      self.add_test_vector(c, "valid", sk, pub, None, comment,
                               [cve_2017_10176])

    # TODO: this is supposed to be a test vector for CVE-2015-8804:
    #   Unfortunately, (gx, gy) is not on the curve and it is unclear where the
    #   error is.
    # c = ec_groups.curveP384
    # gx = int(
    #     "23000000000000000000000000000000000000000000000000110011C2DD0000"
    #     "000000000000000", 16)
    # gy = int(
    #     "46BE3FEF75FCA4BD52CE28EC3F1483A05EE154965B05282F9029E14277409908"
    #     "C0EBAAD2CA5449FFA61FEC78473816BC", 16)
    # sk = int("23000000000000C1DD3FF800E83E2CACA1010A21", 16)
    # pub = ec_key.EcPublicKey(c, (gx, gy))
    # self.add_test_vector(c, "valid", sk, pub, None, flags.cve("CVE-2015-8804",
    #     "Fixed carry folding bug in x86_64 ecc_384_modp")

    c = ec_groups.curveP256
    if c == self.group:
      cve_2017_8932 = flag.Cve(
          "CVE-2017-8932",
          description="A bug in the standard library ScalarMult implementation "
          "of curve P-256 for amd64 architectures in Go before 1.7.6 and 1.8.x "
          "before 1.8.2 causes incorrect results to be generated for specific "
          "input points.",
          effect="An adaptive attack can be mounted to progressively "
          "extract the scalar input to ScalarMult by submitting crafted points "
          "and observing failures to the derive correct output.")
      for k, x, y, s in [
        ("2a265f8bcbdcaf94d58519141e578124cb40d64a501fba9c11847b28965bc737",
         "023819813ac969847059028ea88a1f30dfbcde03fc791d3a252c6b41211882ea",
         "f93e4ae433cc12cf2a43fc0ef26400c0e125508224cdb649380f25479148a4ad",
         "4d4de80f1534850d261075997e3049321a0864082d24a917863366c0724f5ae3"),
        ("313f72ff9fe811bf573176231b286a3bdb6f1b14e05c40146590727a71c3bccd",
         "cc11887b2d66cbae8f4d306627192522932146b42f01d3c6f92bd5c8ba739b06",
         "a2f08a029cd06b46183085bae9248b0ed15b70280c7ef13a457f5af382426031",
         "831c3f6b5f762d2f461901577af41354ac5f228c2591f84f8a6e51e2e3f17991")]:
        sk = int(k, 16)
        pk = ec_key.EcPublicKey(c, (int(x, 16), int(y, 16)))
        sh = bytes.fromhex(s)
        self.add_test_vector(
            c, "valid", sk, pk, sh, "CVE-2017-8932", flags=[cve_2017_8932])

  def generate_modified_public_key(self):
    """Generates test vectors with modified public keys."""
    unused_param = flag.Flag(
        label="UnusedParam",
        bug_type=flag.BugType.MALLEABILITY,
        description="A parameter that is typically not used for ECDH has "
        "been modified. Sometimes libraries ignore small differences between "
        "public and private key. For example, a library might ignore an "
        "incorrect cofactor in the public key. We consider ignoring such "
        "changes as acceptable as long as these differences do not change "
        "the outcome of the ECDH computation, i.e. as long as the computation "
        "is done on the curve from the private key.")
    invalid_pub = flag.Flag(
        label="InvalidPublic",
        bug_type=flag.BugType.CAN_OF_WORMS,
        description="The public key has been modified and is invalid. An "
        "implementation should always check whether the public key is valid "
        "and on the same curve as the private key. The test vector includes "
        "the shared secret computed with the original public key if the public "
        "point is on the curve of the private key.",
        effect="Generating a shared secret other than the one with the original "
        "key likely indicates that the bug is exploitable.")
    c = self.group
    if isinstance(c, ec_groups.EcPrimeGroup):
      priv = prand.randrange(1, c.n, "19i12y123123ewr", label=c.name)
      k2 = prand.randrange(1, c.n, "91123441123a", label=c.name)
      pub = ec_key.EcPrivateKey(c, k2).public()
      shared = ecdh(c, priv, pub)
      for validKey, txt, key, flags in gen_eckey.modify_key(pub):
        # Note: validKey == False indicates that the key is so badly broken
        #   that reading the key itself already must throw an exception.
        #   Hence, we have to check if ECDH works.
        try:
          s2 = ecdh(c, priv, key)
          if s2 != shared:
            validKey = False
        except Exception:
          s2 = b""
          validKey = False
        if validKey:
          self.add_test_vector(c, "acceptable", priv, key, s2, txt,
                                   flags + [unused_param])
        else:
          self.add_test_vector(c, "invalid", priv, key, s2, txt,
                                   flags + [invalid_pub])

  def generate_invalid_compressed_public(self):
    invalid_compressed = flag.Flag(
        label="InvalidCompressedPublic",
        bug_type=flag.BugType.MODIFIED_PARAMETER,
        description="The test vector contains a compressed public key that "
        "does not exist. I.e., it contains an x-coordinate that does not "
        "correspond to any points on the curve. Such keys should be rejected ")
    g = self.group
    n = g.n
    priv = prand.randrange(1, n, ";kl2hk3432", label=g.name)
    cnt = 0
    while cnt < 100:
      cnt += 1
      x = prand.randrange(1, n, ";kl234j;s3", label=g.name + str(cnt))
      if g.curve.point_from_x(x) is None:
        pub = ec_key.EcPublicKey(g, (x, 0), compressed=True)
        self.add_test_vector(
            g,
            "invalid",
            priv,
            pub,
            b"",
            "invalid public key",
            flags=[invalid_compressed])
        break

  # TODO: gen_eckey also generates public keys on distinct curves.
  # TODO: Should we add automatic conversion between brainpool r1 and t1
  #    curves
  def generate_distinct_groups(self):
    """Generates test vectors where the private and public keys are

       on distinct curves. All test vectors are using named curves.
      """
    c1 = self.group
    priv = prand.randrange(1, c1.n, "13123714123", label=c1.name)
    for c2 in self.public_groups():
      if c1 == c2:
        continue
      pubk = prand.randrange(1, c2.n, "876214872163", label=c1.name)
      pub = ec_key.EcPrivateKey(c2, pubk).public()
      self.add_test_vector(
          c1,
          "invalid",
          priv,
          pub,
          b"",
          "Public key uses wrong curve: " + c2.name,
          flags=[distinct_curves])

  def generate_modified_asn(self, use_name: bool):
    """Generates test vectors where the public key has modified ASN.

      Args:
        use_name: determines whether the public key structure that is modified
          uses OIDs or long form encoding.
    """
    c = self.group
    priv = prand.randrange(1, c.n, "1312lkajsdf41", label=c.name)
    pubk = prand.randrange(1, c.n, "876214872163", label=c.name)
    pub = ec_key.EcPrivateKey(c, pubk).public()
    struct = pub.asn_struct(use_name)
    shared = ecdh(c, priv, pub)
    for comment, asn in asn_fuzzing.generate(struct):
      if comment is None or "composition" in comment:
        continue
      # TODO: The parser still needs to support this.
      result = None
      # TODO: We need to decide whether the key is valid or not.
      #   The ASN fuzzer generates some valid keys.
      #   Hence we have to parse back and only add the test vector that are
      #   really invalid.
      try:
        modified_pub = asn_parser.parse(asn)
        if (not isinstance(modified_pub, list) or len(modified_pub) != struct or
            not isinstance(modified_pub[0], list) or
            len(modified_pub[0]) != len(struct[0])):
          result = "acceptable"
      except:
        result = "acceptable"
      if result in ("acceptable", "invalid"):
        if self.encoding == "asn":
          invalid_asn = self.footnote(
              "InvalidAsn",
              """The public key in this test uses an invalid ASN encoding.
                 Some cases where the ASN parser is not strictly checking the
                 ASN format are benign as long as the ECDH computation still
                 returns the correct shared value.""")
          pubkey = asn
          tc = EcdhTestVector(
              curve=c.name,
              public=pubkey,
              private=AST.BigInt(priv),
              shared=shared.hex(),
              result=result,
              comment=comment,
              flags=[invalid_asn])
        elif self.encoding == "pem":
          invalid_pem = self.footnote(
              "InvalidPem",
              """The PEM public key in this test uses an invalid ASN encoding.
                 Some cases where the ASN parser is not strictly checking the
                 ASN format are benign as long as the ECDH computation still
                 returns the correct shared value.""")
          pubkey = pem_util.public_key_pem(asn)
          tc = EcdhPemTestVector(
              curve=c.name,
              public=pubkey,
              private=ec_key.EcPrivateKey(c, priv).pem(),
              shared=shared.hex(),
              result=result,
              comment=comment,
              flags=[invalid_pem])
        else:
          raise Exception("Unsupported encoding" + self.encoding)
        self.add_test(tc)

  def generate_all(self):
    self.generate_pseudorandom_test_vectors(compressed=False)
    if self.test_compressed():
      self.generate_pseudorandom_test_vectors(compressed=True)
    self.generate_special_points()
    self.generate_special_public_key()
    self.generate_special_case_doublings()
    self.generate_special_private_key()
    self.generate_third_party_cases()
    self.generate_invalid_points()
    self.generate_shared_point_on_two_curves()
    self.generate_low_order_public_key_on_curve()
    if self.encoding != "webcrypto":
      self.generate_invalid_point_encodings()
    if self.encoding != "ecpoint":
      self.generate_special_case_invalid_public_key()
      self.generate_low_order_invalid_public_key()
      self.generate_modified_public_key()
      self.generate_distinct_groups()
    if self.test_compressed():
      self.generate_invalid_compressed_public()
      self.generate_low_order_public_key_on_twist()
    if self.encoding in ("pem", "asn"):
      self.generate_modified_asn(use_name=True)
      # This generates a lot of test vectors.
      # self.generate_modified_asn(use_name=False)

def test():
  T = EcdhTestGenerator("asn")
  for c in ec_groups.predefined_curves:
    print(c.name)
    for p,o in T.low_order_points_on_twist(c):
      print(p,o)
  print("done")


class EcdhProducer(producer.Producer):
  """Generates test vectors for ECDH.

    The tests performed
    depends a lot on the encoding of the keys. Private keys
    are always valid keys. Public keys may be invalid or use
    a different curve (assuming the curve is part of the encoding).
    Currently the following encodings are supported:

    asn: the public key is ASN encode, the private key is an integer.
    pem: public and private key use PEM format.
    webcrypto: public and private key use the jwk format.
    ecpoint: the public key is an X509 encoding of the public key
    point.
    """

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
    tv = EcdhTestGenerator(namespace.encoding, namespace.curve)
    if namespace.curve == "":
      raise ValueError("Curve not specified")
    tv.generate_all()
    return tv.test


# DEPRECATED: Use Producer.produce() instead
def main(namespace):
  EcdhProducer().produce(namespace)


if __name__ == "__main__":
  EcdhProducer().produce_with_args()
