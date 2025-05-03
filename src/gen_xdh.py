# Copyright 2017 Google Inc. All Rights Reserved.
# Author: bleichen@google.com (Daniel Bleichenbacher)
#
# Generating test cases for XDH.
# The main focus here is to generate test cases with special values
# such as 0,1 etc. The motivation for testing with these values is that
# 0 is frequently used in encodings of the point at infinity.

# Things to test:
# privateKey bits cleared so that the key has an order divisible by 8.
#
# TODO: X25519 with raw encoding has no invalid test vectors.
#   Possible additions are: public key too long, public key too short.
#   Check if public key==0 is invalid.
import asn
import asn_fuzzing
import AST
import ec_groups
import ec_key
import flag
import producer
import prand
import test_vector
import util
import xdh
import xdh_special
from typing import Optional, Union

ALGORITHMS = ["x25519", "x448"]
def repeat_bits(bits: int, length: int, mod: int) -> int:
  """Returns an integer with a repeating bit pattern.

  Args:
    bits: the pattern
    length: the length of the pattern.
    mod: the upper bound for the result.

  Returns:
    an integer with a repeating bit pattern in the range
    0 .. mod-1
  """
  res = bits
  while res < mod:
    res = (res << length) | bits
  res &= 2 ** mod.bit_length() - 1
  if res >= mod:
    res &= 2 ** (mod.bit_length() - 1) - 1
  return res

class XdhTestVector(test_vector.TestVector):
  """A test vector for a key exchange using XDH.

     XDH is a Diffie-Hellman key exchange defined in
     RFC 7748.

     Both public and private key in this test vector
     are just raw bytes. That is valid public keys and
     valid private keys are 32 bytes each for X25519 and
     56 bytes for X448.
  """
  test_attributes = ["public", "private", "shared"]
  group_attributes = ["curve"]
  schema = {
      "public": {
          "type": AST.HexBytes,
          "desc": "the raw bytes of the public key"
      },
      "private": {
          "type": AST.HexBytes,
          "desc": "the raw bytes of private key"
      },
      "shared": {
          "type": AST.HexBytes,
          "desc": "the shared secret",
      }
  }
  def index(self):
    return self.curve

class XdhComp(test_vector.TestType):
  """Test vectors of type XdhComp are intended for tests that verify the
     computation of an Xdh key exchange.

     Both public and private key in the test vectors
     are just raw bytes. There are separate files, where the keys are
     ASN.1 encoded or use the webcrypto encoding.
  """

class XdhTestGroup(test_vector.TestGroup):
  algorithm = "XDH"
  vectortype = XdhTestVector
  testtype = XdhComp
  schema = {
      "curve": {
          "type":
              AST.EcCurve,
          "short":
              "the name of the curve",
          "desc":
              """The name of the curve. If test vectors encode the curve
                    as part of the public and private key then this field
                    describes the curve of the private key. Test vectors with
                    such encoding can contain distinct curves. Such test vectors
                    are of course invalid and an attempt to compute a shared
                    secret is expected to fail."""
      }
  }

  def __init__(self, curve):
    super().__init__()
    self.curve = curve

  def as_struct(self, sort_by: Optional[str] = None):
    if sort_by is None:
      sort_by = "comment"
    group = {}
    group["type"] = self.testtype
    group["curve"] = self.curve
    group["tests"] = self.get_all_vectors(sort_by=sort_by)
    return group

class XdhAsnTestVector(test_vector.TestVector):
  """A test vector for a key exchange using XDH.

     Public and private keys are ASN encoded.
  """
  test_attributes = ["public", "private", "shared"]
  group_attributes = ["curve"]
  schema = {
      "public": {
          "type": AST.Asn,
          "desc": "X.509 encoded the public key"
      },
      "private": {
          "type": AST.Der,
          "desc": "PKCS #8 encoded private key"
      },
      "shared": {
          "type": AST.HexBytes,
          "desc": "the shared secret",
      }
  }
  def index(self):
    return self.curve

class XdhAsnComp(test_vector.TestType):
  """Test vectors of type XdhComp are intended for tests that verify the
     computation of an Xdh key exchange.

     Public and private keys are ASN encoded.
  """

class XdhAsnTestGroup(test_vector.TestGroup):
  algorithm = "XDH"
  vectortype = XdhAsnTestVector
  testtype = XdhAsnComp
  schema = {
      "curve": {
          "type":
              AST.EcCurve,
          "short":
              "the name of the curve",
          "desc":
              """The name of the curve. If test vectors encode the curve
                    as part of the public and private key then this field
                    describes the curve of the private key. Test vectors with
                    such encoding can contain distinct curves. Such test vectors
                    are of course invalid and an attempt to compute a shared
                    secret is expected to fail."""
      }
  }

  def __init__(self, curve: str):
    super().__init__()
    self.curve = curve

  def as_struct(self, sort_by: Optional[str] = None):
    if sort_by is None:
      sort_by = "comment"
    group = {}
    group["type"] = self.testtype
    group["curve"] = self.curve
    group["tests"] = self.get_all_vectors(sort_by=sort_by)
    return group

class XdhPemTestVector(test_vector.TestVector):
  """A test vector for a key exchange using XDH.

     Public and private keys are pem encoded.
  """
  test_attributes = ["public", "private", "shared"]
  group_attributes = ["curve"]
  schema = {
      "public": {
          "type": AST.Pem,
          "desc": "PEM encoded public key"
      },
      "private": {
          "type": AST.Pem,
          "desc": "PEM encoded private key"
      },
      "shared": {
          "type": AST.HexBytes,
          "desc": "the shared secret",
      }
  }
  def index(self):
    return self.curve

class XdhPemComp(test_vector.TestType):
  """Test vectors of type XdhPemComp are intended for verifying XDH.

     Public and private keys are PEM encoded.
     The tests inlcude vectors generated for edge cases, arithmetic
     overflows, points on twists and public keys for the wrong curve.
     The tests do not include invalid PEM formats, though such tests
     may be added in the future.
  """

class XdhPemTestGroup(test_vector.TestGroup):
  algorithm = "XDH"
  vectortype = XdhPemTestVector
  testtype = XdhPemComp
  schema = {
      "curve": {
          "type":
              AST.EcCurve,
          "short":
              "the name of the curve",
          "desc":
              """The name of the curve. If test vectors encode the curve
                    as part of the public and private key then this field
                    describes the curve of the private key. Test vectors with
                    such encoding can contain distinct curves. Such test vectors
                    are of course invalid and an attempt to compute a shared
                    secret is expected to fail."""
      }
  }

  def __init__(self, curve):
    super().__init__()
    self.curve = curve

  def as_struct(self, sort_by: Optional[str] = None):
    if sort_by is None:
      sort_by = "comment"
    group = {}
    group["type"] = self.testtype
    group["curve"] = self.curve
    group["tests"] = self.get_all_vectors(sort_by=sort_by)
    return group

class XdhJwkTestVector(test_vector.TestVector):
  """A test vector for a key exchange using XDH.

     XDH is a Diffie-Hellman key exchange defined in
     RFC 7748.

     Both public and private key in this test vector
     are using the jwk format.
  """
  test_attributes = ["public", "private", "shared"]
  group_attributes = ["curve"]
  since = "0.7"
  schema = {
      "public": {
          "type": "JSON",
          "desc": "valid or invalid public key in jwk format",
          "ref": "RFC 8037",
      },
      "private": {
          "type": xdh.JwkXdhPrivateKey,
          "desc": "the private key in jwk format",
          "ref": "RFC 8037",
      },
      "shared": {
          "type": AST.HexBytes,
          "desc": "the shared secret",
      }
  }
  def index(self):
    return self.curve

class XdhJwkComp(test_vector.TestType):
  """Test vectors of type XdhComp are intended for tests that verify the
     computation of an Xdh key exchange.

     The public and private keys in these test vectors use the webcrypto
     encoding.
  """

class XdhJwkTestGroup(test_vector.TestGroup):
  algorithm = "XDH"
  vectortype = XdhJwkTestVector
  testtype = XdhJwkComp
  schema = {
      "curve": {
          "type":
              AST.EcCurve,
          "short":
              "the name of the curve",
          "desc":
              """The name of the curve. If test vectors encode the curve
                    as part of the public and private key then this field
                    describes the curve of the private key. Test vectors with
                    such encoding can contain distinct curves. Such test vectors
                    are of course invalid and an attempt to compute a shared
                    secret is expected to fail."""
      }
  }

  def __init__(self, curve):
    super().__init__()
    self.curve = curve

  def as_struct(self, sort_by: Optional[str] = None):
    if sort_by is None:
      sort_by = "comment"
    group = {}
    group["type"] = self.testtype
    group["curve"] = self.curve
    group["tests"] = self.get_all_vectors(sort_by=sort_by)
    return group

ENCODINGS = ("raw", "asn", "jwk", "pem")
class XdhTestGenerator(test_vector.TestGenerator):
  algorithm = "XDH"

  def __init__(self, group: xdh.Xdh, args):
    super().__init__()
    encoding = args.encoding
    if encoding not in ENCODINGS:
      raise ValueError("Unsupported encoding:" + encoding)
    self.args = args
    self.group = group
    self.encoding = encoding
    self.test = test_vector.Test(self.algorithm, args)

  flag_twist = flag.Flag(
      label="Twist",
      bug_type=flag.BugType.DEFINED,
      description="Public keys are either points on a given curve or points on "
      "its twist. The functions X25519 and X448 are defined for points on a "
      "twist with the goal that the output of computations do not leak private "
      "keys. Implementations may accept or reject points on a twist. "
      "If a point multiplication is performed then it is important that "
      "the result is correct, since otherwise attacks with invalid keys are "
      "possible.")
  flag_loworder = flag.Flag(
      label="LowOrderPublic",
      bug_type=flag.BugType.DEFINED,
      description="The curves and its twists contain some points of low order. "
      "This test vector contains a public key with such a point. "
      "While many libraries reject such public keys, doing so is "
      "not a strict requirement according to RFC 7748.")
  flag_noncanonical_pub = flag.Flag(
      label="NonCanonicalPublic",
      bug_type=flag.BugType.DEFINED,
      description="The public key is in non-canonical form. "
      "RFC 7748, section 5 defines the value that this public key represents. "
      "Section 7 of the same RFC recommends accepting such keys. "
      "If a non-canonical key is accepted then it must follow the RFC.")
  flag_public_too_long = flag.Flag(
      label="PublicKeyTooLong",
      bug_type=flag.BugType.MODIFIED_PARAMETER,
      description="The public key is too long")
  flag_small_public = flag.Flag(
      label="SmallPublicKey",
      bug_type=flag.BugType.DEFINED,
      description="The public key is insecure and does not belong to a "
      "valid private key. Some libraries reject such keys.")
  flag_zero_shared_secret = flag.Flag(
      label="ZeroSharedSecret",
      bug_type=flag.BugType.DEFINED,
      description="Some libraries include a check that the shared secret is "
      "not all-zero. This check is described in Section 6.1 of RFC 7748.")

  def new_testgroup(self, idx):
    if self.encoding == "raw":
      return XdhTestGroup(idx)
    elif self.encoding == "asn":
      return XdhAsnTestGroup(idx)
    elif self.encoding == "jwk":
      return XdhJwkTestGroup(idx)
    elif self.encoding == "pem":
      return XdhPemTestGroup(idx)
    else:
      raise ValueError("Unsupported encoding:" + self.encoding)

  def validity_of_public_key(self, x:int):
    assert isinstance(x, int)
    flags = []
    if x.bit_length() > self.group.bytes * 8:
      comment = f"public key too large:{x.bit_length()} bits"
      return "invalid", comment, [self.flag_public_too_long]
    x_reduced = self.group.reduce_public(x)
    c = None
    rejectable = False
    if x_reduced < 2:
      rejectable = True
      if x == x_reduced:
        c = "public key = %d" % x
      else:
        c = "public key == %d" % x_reduced

      flags.append(self.flag_small_public)
    if x_reduced in self.group.low_order_points:
      rejectable = True
      c = c or "public key with low order"
      flags.append(self.flag_loworder)
    if x > self.group.p:
      rejectable = True
      c = c or "non-canonical public key"
      flags.append(self.flag_noncanonical_pub)
    if not self.group.is_on_curve(x):
      rejectable = True
      flags.append(self.flag_twist)
      c = c or "public key on twist"
    if rejectable:
      v = "acceptable"
    else:
      v = "valid"
    return v, c, flags

  @util.type_check
  def addTestVector(self,
                    validity: str,
                    priv: Union[int, bytes],
                    pub: Union[int, bytes],
                    shared: Optional[bytes] = b"",
                    comment: str = "",
                    flags: Optional[list[flag.Flag]] = None):
    if flags is None:
      flags = []
    else:
      flags = flags[:]
    if isinstance(priv, int):
      priv = self.group.encode_scalar(priv)
    if isinstance(pub, int):
      if pub < self.group.p:
        pub = self.group.encode_u_coordinate(pub)
      else:
        if 8 * self.group.bytes < pub.bit_length():
          pub = xdh.encode_little_endian(pub, pub.bit_length())
          validity = "invalid"
          if self.flag_public_too_long not in flags:
            flags += [self.flag_public_too_long]
        else:
          pub = xdh.encode_little_endian(pub, 8 * self.group.bytes)
          if validity == "valid":
            validity = "acceptable"
            if self.flag_noncanonical_pub not in flags:
              flags += [self.flag_noncanonical_pub]

    # Sanity checks
    if validity in ("valid", "acceptable"):
      res = self.group.shared_secret(priv, pub)
      if shared:
        if res != shared:
          print("priv:", priv.hex(), self.group.jwk_private_key(priv))
          print("pub:", pub.hex(), self.group.jwk_public_key(pub))
          print("res:", res.hex())
          print("shared:", shared.hex())
          raise ValueError("test vector is wrong")
      else:
        shared = res
    if not shared:
      shared = b""
    if len(shared) > 0 and all(b == 0 for b in shared):
      flags.append(self.flag_zero_shared_secret)
      if validity == "valid":
        validity == "acceptable"

    flags = self.add_flags(flags)
    if self.encoding == "raw":
      ast = XdhTestVector(
                curve = self.group.curve,
                public = pub,
                private = priv,
                shared = shared,
                result = validity,
                comment = comment,
                flags = flags)
    elif self.encoding == "asn":
      ast = XdhAsnTestVector(
                curve = self.group.curve,
                public = self.group.asn_encode_pub(pub),
                private = self.group.asn_encode_priv(priv),
                shared = shared,
                result = validity,
                comment = comment,
                flags = flags)
    elif self.encoding == "pem":
      ast = XdhPemTestVector(
                curve = self.group.curve,
                public = self.group.pem_encode_pub(pub),
                private = self.group.pem_encode_priv(priv),
                shared = shared,
                result = validity,
                comment = comment,
                flags = flags)
    elif self.encoding == "jwk":
      ast = XdhJwkTestVector(
                curve = self.group.curve,
                public = self.group.jwk_public_key(pub),
                private = self.group.jwk_private_key(priv),
                shared = shared,
                result = validity,
                comment = comment,
                flags = flags)
    self.add_test(ast)

  def pseudorandom_priv_key(self, seed: bytes, label: bytes = b"") -> bytes:
    """Generates a pseudorandom private key.

    Args:
      seed: the seed for the pseudorandom number generator
      label: an additional argument for the pseudorandom number generator"

    Returns:
      the encoded private key
    """
    s = prand.randrange(0, 2**self.group.bits, seed=seed, label=label)
    s = self.group.reduce_private(s)
    return self.group.encode_scalar(s)

  def pseudorandom_pub_key(self, seed: bytes, label: bytes = b"") -> bytes:
    priv = self.pseudorandom_priv_key(seed, label)
    return self.group.public_key(priv)

  def pseudorandom_pub_key_on_twist(self, seed: bytes, label: bytes = b""):
    s = prand.randrange(1, self.group.p, seed=seed, label=label)
    while self.group.is_on_curve(s):
      s += 1
    s = self.group.point_mult(s, 4)
    return self.group.encode_u_coordinate(s)

  @util.type_check
  def generate_test_vector_from_shared(self,
                                       encoded_priv: bytes,
                                       shared: int,
                                       comment: Optional[str] = None,
                                       flags: Optional[list[flag.Flag]] = None):
    if flags is None:
      flags = []
    priv = self.group.decode_scalar(encoded_priv)
    ontwist = not self.group.is_on_curve(shared)
    if ontwist:
      order = self.group.order_twist
    else:
      order = self.group.order
    assert self.group.point_mult(shared, order, infinity="inf") == "inf"
    inv_priv = pow(priv, -1, order)
    pub = self.group.point_mult(shared, inv_priv)
    v, c, pub_flags = self.validity_of_public_key(pub)
    comment = comment or c or "constructed public key"
    self.addTestVector(v, priv, pub, None, comment, flags + pub_flags)

  def generate_edge_case_shared(self):
    g = self.group
    p = g.p
    priv = self.pseudorandom_priv_key(seed=b"kja;lkj;ewr2")
    if g.name == "x25519":
      points_with_odd_order = [
          2, 9, 16, 2**254 - 2, 2**254 - 4, 2**254 - 7, 2**254 - 13, 2**250 - 1,
          p - 8, p - 10, p - 16, p - 18, 2**249, 2**247
      ]
    else:
      points_with_odd_order = []
      for u in range(2, 20):
        if g.order_u(u) % 2 == 1:
          points_with_odd_order.append(u)
        if g.order_u(p - u) % 2 == 1:
          points_with_odd_order.append(p - u)
        if g.order_u(2**(g.bits-1) - u) % 2 == 1:
          points_with_odd_order.append(2**(g.bits-1) - u)
      points_with_odd_order = sorted(points_with_odd_order)
    edge_case_shared = flag.Flag(
        label="EdgeCaseShared",
        bug_type=flag.BugType.EDGE_CASE,
        description="The values in this test case have been constructed "
        "such that the shared secret is an edge case. The goal is to "
        "detect errors in the integer arithmetic.")
    for s in points_with_odd_order:
      self.generate_test_vector_from_shared(
          priv, s, "edge case for shared secret", flags=[edge_case_shared])

  def generate_special_case_private_key(self):
    edge_case_private = flag.Flag(
        label="EdgeCasePrivateKey",
        bug_type=flag.BugType.EDGE_CASE,
        description="The private key in this test vector contains a special "
        "case value. The goal of the test vector is to check for edge case "
        "behaviour.")
    s = 5 * self.group.order - 1
    priv = self.group.encode_scalar(s)
    pub = self.pseudorandom_pub_key(seed=b"12kj31lk321")
    self.addTestVector(
        "valid",
        priv,
        pub,
        None,
        "private key == -1 (mod order)",
        flags=[edge_case_private])

    s = 3 * (self.group.order_twist) + 1
    priv = self.group.encode_scalar(s)
    pub = self.pseudorandom_pub_key_on_twist(seed=b"lakjsfd;a")
    self.addTestVector(
        "acceptable",
        priv,
        pub,
        None,
        "private key == 1 (mod order) on twist",
        flags=[self.flag_twist])

    a = (self.group.p // 3) * 2
    for x in [a, -a % 2**self.group.bits]:
      s = self.group.reduce_private(x)
      priv = self.group.encode_scalar(s)
      for i in range(3):
        pub = self.pseudorandom_pub_key(seed=b"1k24jpa324", label=str(i))
        self.addTestVector(
            "valid",
            priv,
            pub,
            None,
            "special case private key",
            flags=[edge_case_private])

  def generate_pseudorandom_test_vectors(self):
    c = self.group.name
    priv = self.pseudorandom_priv_key(seed=b"12831lkj312313", label=c)
    pub = self.pseudorandom_pub_key(seed=b"123uoi123", label=c)
    self.addTestVector(
        "valid", priv, pub, None, "normal case", flags=[flag.NORMAL])

  def generate_public_keys_with_low_order(self):
    c = self.group.name
    priv = self.pseudorandom_priv_key(seed=b";klaj;kljerwre", label=c)
    for pub in self.group.public_keys_with_low_order():
      self.addTestVector("acceptable", priv, pub, None,
                         "public key with low order", [self.flag_loworder])

  def generate_points_on_twist(self, cnt=5):
    i = 0
    while cnt and i < 10000:
      i += 1
      k1 = self.pseudorandom_priv_key(seed=b"genTwistPriv", label=b"%d" % i)
      u = prand.randrange(1, self.group.p, seed=b"genTwistPub", label=b"%d" % i)
      if self.group.is_on_curve(u):
        continue
      self.addTestVector(
          "acceptable",
          k1,
          u,
          None,
          "public key on twist",
          flags=[self.flag_twist])
      cnt -= 1

  def generate_special_points(self):
    """Generates test vectors where the public key has some special
       form. Many of the special cases propagate into the computation.
       Hence test for arithmetic errors."""
    special_point = flag.Flag(
        label="SpecialPublicKey",
        bug_type=flag.BugType.EDGE_CASE,
        description="The test vector contains a public key that has a special "
        "form. The goal of the test vector is to check for errors in the "
        "implementation of the integer arithmetic.")
    crv = self.group.name
    p = self.group.p
    plen = p.bit_length()
    S = set()
    # small coordinates
    S |= set(range(5))
    # large coordinates
    S |= set(range(p - 3, p))
    # small order
    S |= set(self.group.low_order_points)
    # Generates public keys with coordinate larger than p
    # These public keys are non-canonical for x25519, but invalid
    # for x448.
    S |= set(x + 2**plen for x in S)
    S |= set(x + p for x in S if x + p < 2**plen)
    S |= set(range(2 * p, 2 * p + 3))
    # large Hamming-weight
    S |= {2**(plen - 1) - 1, 2**plen - 1, 2**(plen + 1)-1, 2**(plen - 5) - 1}
    # powers of two
    S |= {2**i for i in (8, 16, 28, 32, 52, 56, 64, 112, 128, 192, 224,
          plen - 2, plen-16)}
    # powers of two - 1
    S |= {2**i - 1 for i in (8, 16, 28, 32, 52, 56, 64, 112, 128, 192, 224,
          plen-2, plen-16)}
    # negative powers
    S |= {-2**i % p for i in (8, 16, 28, 32, 52, 56, 64, 112, 128, 192, 224,
          plen-2, plen-16)}
    # Public key with patterns:
    S |= {repeat_bits(2**32 - 1, 64, p),
          repeat_bits(2**64 - 2**32, 64, p),
          repeat_bits(2**63 - 2**32 - 1, 64, p),
          repeat_bits(2**51 - 2**26, 51, p),
          repeat_bits(2**28 - 1, 56, p),
          repeat_bits(2**26 - 1, 51, p),
          repeat_bits(2**50 - 2**26, 51, p),
          repeat_bits(2**56 - 1, 112, p)}
    for x in sorted(S):
      priv = self.pseudorandom_priv_key(seed=b"198236189421", label=b"0x%x" % x)
      v, c, flags = self.validity_of_public_key(x)
      c = c or "edge case public key"
      self.addTestVector(v, priv, x, None, c, flags + [special_point])

  def generate_third_party_cases(self):
    if self.group.name == "x25519":
      testcases = [
          [
              "valid",
              int("3102984249211504090489556045186308965647277260467826026553122103"
                  "6453811406496"),
              int("3442643403391959445115510778118882165131616721530663157499622662"
                  "1102155684838"),
              "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552",
              "RFC 7748"
          ],
          [
              "valid",
              int("3515689181567481726673421275450363374712861401611956476326901531"
                  "5466259359304"),
              int("8883857351183929894090759386610649319417338800022198945255395922"
                  "347792736741"),
              "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957",
              "RFC 7748"
          ],
          [
              "valid",
              bytes.fromhex(
                  "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
              ),
              bytes.fromhex(
                  "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
              ),
              "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742",
              "RFC 8037, Section A.6"
          ],
      ]
    elif self.group.name == "x448":
      testcases = [
        ["valid",
         bytes.fromhex(
           "9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28dd9c9baf5"
           "74a9419744897391006382a6f127ab1d9ac2d8c0a598726b"),
         bytes.fromhex(
           "3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b43027d8b972"
           "fc3e34fb4232a13ca706dcb57aec3dae07bdc1c67bf33609"),
         "07fff4181ac6cc95ec1c16a94a0f74d12da232ce40a77552281d282bb60c0b56"
         "fd2464c335543936521c24403085d59a449a5037514a879d",
         "RFC 8037, Section A.7"],
       ]
    else:
      testcases = []
    ktv = flag.Flag(
        label="Ktv",
        bug_type=flag.BugType.BASIC,
        description="Known test vector from RFC. We assume that these test "
        "cases have been checked before. Hence, if such a test vector "
        "fails then we may reasonably assume that there is an error "
        "in the setup.")
    for val, priv, pub, res_hex, comment in testcases:
      res = bytes.fromhex(res_hex)
      self.addTestVector(val, priv, pub, res, comment, flags=[ktv])

  def generate_edge_case_public(self):
    """Generates test vectors from a list of edge cases for multiplications
       by a small k. I.e. these are cases where one of the coordinates x or z
       have values such as -1, 0 or 1.
    """
    edge_case_mult = flag.Flag(
        label="EdgeCaseMultiplication",
        bug_type=flag.BugType.CONFIDENTIALITY,
        description="The public key in this test vector has been constructed, "
        "so that an edge case during the multiplication with a small k occurs. "
        "I.e., these are cases where during the multiplication one of the "
        "internal variables has a values such as -1, 0 or 1. This checks "
        "for errors in the integer arithmetic.",
        effect="The effect of arithmetic errors in the multiplication "
        "is that information about the private key is leaked. In the worst "
        "case such an error could be exploited to find the private key.")
    if self.group.name == "x25519":
      pub_list = xdh_special.EDGE_CASE_X25519
    elif self.group.name == "x448":
      pub_list = xdh_special.EDGE_CASE_X448
    else:
      raise ValueError("Unsupported group")
    for k, L in pub_list.items():
      for pub, description in L:
        priv0 = prand.randrange(
            0, 2**self.group.bits, label=str(pub), seed="l1j3l1faui23")
        priv0 = self.group.reduce_private(priv0)
        bits = self.group.bits
        b = bits - k.bit_length()
        priv = (k << b) + priv0 % 2**b
        assert priv == self.group.reduce_private(priv)
        priv = self.group.encode_scalar(priv)
        if k == 1:
          comment = "special case public key"
        else:
          comment = "%s in multiplication by %d" % (description, k)
        v, c, flags = self.validity_of_public_key(pub)
        self.addTestVector(
            v, priv, pub, None, comment, flags=[edge_case_mult] + flags)

  def generate_wrong_public_key_asn(self):
    """Generates test vectors where private key and public key
       do not use the same curve. This is possible since the ASN encoding
       includes the OID of the curve."""
    assert self.encoding == "asn"
    invalid_public = flag.Flag(
        label="InvalidPublic",
        bug_type=flag.BugType.MODIFIED_PARAMETER,
        description="The private key and the public key do not use the same "
        "underlying group.")
    for ec_group in ec_groups.predefined_curves:
      priv = self.pseudorandom_priv_key(
          seed=b"1l2k3123", label=bytes(ec_group.name, "ascii"))
      x = prand.randrange(1, ec_group.p, b"1j98sa67d8y214",
                          ec_group.name.encode("ascii"))
      pub = ec_key.EcPrivateKey(ec_group, x).public()
      pub_asn = pub.encode()
      ast = XdhAsnTestVector(
          curve=self.group.curve,
          public=pub_asn,
          private=self.group.asn_encode_priv(priv),
          shared="",
          result="invalid",
          comment="uses public key for " + ec_group.name,
          flags=self.add_flags([invalid_public]))
      self.add_test(ast)
    for xdh_group in xdh.XDH_GROUPS:
      if xdh_group.name == self.group.name:
        continue
      label = bytes(self.group.name + xdh_group.name, "ascii")
      priv = self.pseudorandom_priv_key(seed=b"1982askweq21", label=label)
      pub = xdh_group.pseudorandom_pub_key(seed=b"1kl23j13", label=label)
      ast = XdhAsnTestVector(
          curve=self.group.curve,
          public=xdh_group.asn_encode_pub(pub),
          private=self.group.asn_encode_priv(priv),
          shared="",
          result="invalid",
          comment="uses public key for " + ec_group.name,
          flags=self.add_flags([invalid_public]))
      self.add_test(ast)

  def generate_wrong_private_key_asn(self):
    """Generates test vectors where the private key is invalid."""
    priv = self.pseudorandom_priv_key(seed=b"12l3kj1s")
    pub = self.pseudorandom_pub_key(seed=b"oiyp;23k4jh")
    invalid_asn_struct = [0, [self.group.oid], asn.OctetString(priv)]
    shared = self.group.shared_secret(priv, pub)
    invalid_private = flag.Flag(
        label="MissingOctetString",
        bug_type=flag.BugType.KNOWN_BUG,
        description="The correct ASN encoding of a private key contains an "
        "octet string of an octet string. The reason is that the key material "
        "itself is an octet string and the ASN encoding of the private key "
        "contains an octet string of the ASN encoded key material. "
        "This test vector contains a test vector where the ASN encoding of "
        "the private key contains just an octet string and hence is "
        "malformed. Implementations that accept the private key as valid "
        "may be misinterpreting the RFC.",
        links=["RFC 8410, Section 7 and Section 10",
               "https://bugs.openjdk.org/browse/JDK-8213363"])
    ast = XdhAsnTestVector(
          curve=self.group.curve,
          public=self.group.asn_encode_pub(pub),
          private=asn.encode(invalid_asn_struct),
          shared=shared,
          result="invalid",
          comment="private key should be an octet string of octet string",
          flags=self.add_flags([invalid_private]))
    self.add_test(ast)


  def generate_wrong_public_key_jwk(self):
    """Generates test vectors where private key and public key
       do not use the same curve. This is possible since the JWK format
       includes the curve."""
    assert self.encoding == "jwk"
    invalid_public = flag.Flag(
        label="InvalidPublic",
        bug_type=flag.BugType.MODIFIED_PARAMETER,
        description="The private key and the public key do not use the same "
        "underlying group.")
    for ec_group in ec_groups.jwk_curves:
      priv = self.pseudorandom_priv_key(seed=b"1l2k3123", label=ec_group.name)
      x = prand.randrange(1, ec_group.p, b"1j98sa67d8y214", ec_group.name)
      pub = ec_key.EcPrivateKey(ec_group, x).public()
      ast = XdhJwkTestVector(
          curve=self.group.curve,
          public=pub.jwk(),
          private=self.group.jwk_private_key(priv),
          shared="",
          result="invalid",
          comment="uses public key for " + ec_group.jwk_name,
          flags=self.add_flags([invalid_public]))
      self.add_test(ast)
    for xdh_group in xdh.XDH_GROUPS:
      if xdh_group.name == self.group.name:
        continue
      label = self.group.name + xdh_group.name
      priv = self.pseudorandom_priv_key(seed=b"1982askweq21", label=label)
      pub = xdh_group.pseudorandom_pub_key(seed=b"1kl23j13", label=label)
      ast = XdhJwkTestVector(
          curve=self.group.curve,
          public=xdh_group.jwk_public_key(pub),
          private=self.group.jwk_private_key(priv),
          shared="",
          result="invalid",
          comment="uses public key for " + ec_group.name,
          flags=self.add_flags([invalid_public]))
      self.add_test(ast)
    # Generate test vectors with wrong kty value:
    for kty_value in ["", "EC", "RSA", "oct"]:
      priv = self.pseudorandom_priv_key(seed=b"1123141123", label=kty_value)
      pub = self.pseudorandom_pub_key(seed=b"klj234lkios234", label=kty_value)
      modified_pub = self.group.jwk_public_key(pub)
      modified_pub["kty"] = kty_value
      ast = XdhJwkTestVector(
          curve=self.group.curve,
          public=modified_pub,
          private=self.group.jwk_private_key(priv),
          shared="",
          result="invalid",
          comment="uses invalid value for kty",
          flags=self.add_flags([invalid_public]))
      self.add_test(ast)
    # Incomplete public key
    priv = self.pseudorandom_priv_key(seed=b"jhhg234234")
    pub = self.pseudorandom_pub_key(seed=b"lsjklk423")
    valid = self.group.jwk_public_key(pub)
    for field in ["", "kty", "crv", "x"]:
      if field:
        modified = valid.copy()
        del modified[field]
        comment = "missing field " + field
      else:
        modified = {}
        comment = "empty key"
      ast = XdhJwkTestVector(
          curve=self.group.curve,
          public=modified,
          private=self.group.jwk_private_key(priv),
          shared="",
          result="invalid",
          comment=comment,
          flags=self.add_flags([invalid_public]))
      self.add_test(ast)

  def generate_asn_fuzzing(self):
    """Generates test vectors with modified ASN.

         TODO: At the moment this generates some false positives.
         Additionally it is unclear whether adding some stuff at the end
         should be counted as bug, since the ASN encoding allows some additional
         arguments with unspecified parameters. I.e. the implementation
         in jdk11 is quite forgiving and accepts many keys with modified
         elements and additional fields. None of the accepted keys modifies
         the result, hence the modifications are difficult to exploit.
         They just make testing harder. There are a few that throw unexpected
         exceptions:

         Test vector with
         tcId:300 comment:dropping value of bit string
         throws:java.lang.ArrayIndexOutOfBoundsException:
             Index 0 out of bounds for length 0

         Test vector with
         tcId:234 comment:indefinite length with truncated delimiter
         throws:java.lang.ArrayIndexOutOfBoundsException:
             Index 47 out of bounds for length 47
      """
    priv = self.pseudorandom_priv_key(seed=b"kwtozfi34")
    pub = self.pseudorandom_pub_key(seed=b"l2k4j2342")
    pub_struct = self.group.public_key_struct(pub)
    fuzzed_key = flag.Flag(
        label="FuzzedPublicKey",
        bug_type=flag.BugType.MODIFIED_PARAMETER,
        description="The public key is the result of modifying a valid public "
        "key. Since fuzzing can generate valid public keys, it is possible "
        "that the test vectors contain false positives even though we "
        "are trying to remove all such false positives.")
    for comment, asn in asn_fuzzing.generate(pub_struct):
      if comment is None:
        continue
      ast = XdhAsnTestVector(
          curve=self.group.curve,
          public=asn,
          private=self.group.asn_encode_priv(priv),
          shared=b"",
          result="invalid",
          comment=comment,
          flags=self.add_flags([fuzzed_key]))
      self.add_test(ast)

  def generate_all(self):
    self.generate_pseudorandom_test_vectors()
    self.generate_points_on_twist()
    self.generate_special_points()
    self.generate_third_party_cases()
    self.generate_edge_case_shared()
    self.generate_edge_case_public()
    self.generate_special_case_private_key()
    self.generate_public_keys_with_low_order()
    if self.encoding == "asn":
      self.generate_wrong_public_key_asn()
      self.generate_wrong_private_key_asn()
      # Test vectors from ASN fuzzing are not released, since
      # there are too many false positives in jdk11.
      # This may hide real bugs.
      if getattr(self.args, "alpha", False):
        self.generate_asn_fuzzing()
    if self.encoding == "jwk":
      self.generate_wrong_public_key_jwk()


class XdhProducer(producer.Producer):
  def parser(self):
    res = self.default_parser()
    res.add_argument(
        "--encoding",
        type=str,
        choices=ENCODINGS,
        default="asn",
        help="the encoding of the keys")
    res.add_argument(
        "--algorithm",
        type=str,
        choices=ALGORITHMS,
        default="x25519",
        help="the DH function that is tested")
    return res

  def generate_test_vectors(self, namespace):
    if namespace.algorithm == "x25519":
      group = xdh.x25519
    elif namespace.algorithm == "x448":
      group = xdh.x448
    tv = XdhTestGenerator(group, namespace)
    tv.generate_all()
    return tv.test

# DEPRECATED: Use Producer.produce() instead
def main(namespace):
  XdhProducer().produce(namespace)

if __name__ == "__main__":
  XdhProducer().produce_with_args()
