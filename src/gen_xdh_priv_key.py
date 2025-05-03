# Copyright 2020 Google Inc. All Rights Reserved.
# Author: bleichen@google.com (Daniel Bleichenbacher)
#
# Generating test cases for XDH private keys.

import asn
import asn_fuzzing
import asn_parser
import AST
import base64
import flag
import producer
import prand
import pem_util
import test_vector
import typing
import util
import modify
import gen_ec_priv_key
import xdh
from typing import Optional

ENCODINGS = ["asn", "pem"]
CURVES = ["curve25519", "curve448"]


def pem(struct: asn.AsnStructure) -> str:
  """Coverts an ASN structure into the PEM format.

  Args:
    struct: the ASN structure
  """
  return pem_util.private_key_pem(asn.encode(struct))


def is_octet_string(val: asn.AsnStructure) -> bool:
  """Returns True if val is an OctetString"""
  return asn.is_element_type(val, asn.OCTET_STRING)


def is_bit_string(val: asn.AsnStructure) -> bool:
  """Returns True if val is a BitString"""
  return asn.is_element_type(val, asn.BIT_STRING)


def type_of(val: asn.AsnStructure) -> str:
  """Describes the type of val.

  The result is more descriptive than type() if val is
  an ASN element.
  """
  if isinstance(val, asn.Element):
    return asn.describe_tag(val.get_tag())
  else:
    return type(val).__name__


class XdhPrivateKeyTestGenerator(test_vector.TestGenerator):
  # TODO: Some parts can be merged with EcPrivateKeyTest.
  #   The biggest difference is the method get_flags.
  #   Xdh keys and EC keys have different structure and hence
  #   this part needs two implementations.
  algorithm = "EcPrivateKeyTest"

  def __init__(self,
               curve: str,
               encoding: str,
               public_key_validation: bool = True):
    """Generator for XDH private keys.

    Args:
      curve: the name of the curve (e.g. "curve25519")
      encoding: the encoding ("asn" or "pem")
      public_key_validation: if true then the test vectors contain samples with
        faulty public keys to check the validation of public keys.
    """
    assert encoding in ENCODINGS
    self.encoding = encoding
    self.curve = curve
    self.public_key_validation=public_key_validation
    if curve == "curve25519":
      self.xdh_group = xdh.x25519
    elif curve == "curve448":
      self.xdh_group = xdh.x448
    else:
      raise ValueError("Unknown curve:" + curve)
    self.test = test_vector.Test(self.algorithm)
    self.encodings = set()

  def new_testgroup(self, idx) -> test_vector.TestGroup:
    if self.encoding == "asn":
      return gen_ec_priv_key.EcPrivateKeyAsnTestGroup(idx)
    elif self.encoding == "pem":
      return gen_ec_priv_key.EcPrivateKeyPemTestGroup(idx)
    else:
      print(self.encoding)
      raise ValueError("Unsupported encoding")

  @util.type_check
  def add_encoding(self, s: int, asn: bytes, validity: str, comment: str,
                   flags: typing.List[flag.Flag]) -> None:
    """Adds a test vector with an already encoded private key.

    Args:
      s: the private key as integer
      asn: the encoded private key,
      validity: "valid", "invalid" or "acceptable",
      flags: a list of flags describing the nature of the test vector.
    """
    flags = self.add_flags(flags)
    if self.encoding == "asn":
      test = gen_ec_priv_key.EcPrivateKeyAsnTestVector(
          curve=self.curve,
          encodedKey=asn,
          s=AST.BigInt(s),
          result=validity,
          comment=comment,
          flags=flags)
    elif self.encoding == "pem":
      pem = pem_util.private_key_pem(asn)
      test = gen_ec_priv_key.EcPrivateKeyPemTestVector(
          curve=self.curve,
          encodedKey=pem,
          s=AST.BigInt(s),
          result=validity,
          comment=comment,
          flags=flags)
    else:
      raise ValueError("Unknown encoding")
    self.add_test(test)

  @util.type_check
  def get_flags(self, priv: bytes, pub: bytes,
                encoding: bytes) -> Optional[tuple[str, list[flag.Flag], str]]:
    """Gets flags for an encoded private key.

    Args:
      priv: the private key that is supposed to be encoded.
      pub: the public key derived from priv
      encoding: the encoding to check

    Returns:
      Returns None if the test vector should be skipped.
      This happens when the encoded key is valid, but does not encode
      priv.
      A tuple containing the validity of the encoding and a list of flags.
    """
    flags = []
    validity = None
    comment = ""
    flag_ber = flag.Flag(
        label="BER",
        bug_type=flag.BugType.BER_ENCODING,
        description="The test vector contains a valid key. Its encoding "
        "is valid but uses alternative BER encoding. Some libraries may "
        "not fully implement the ASN.1 standard or may simply expect "
        "only DER encoded keys.")
    flag_public = flag.Flag(
        label="HasPublic",
        bug_type=flag.BugType.FUNCTIONALITY,
        description="The test vector contains a valid private key. "
        "Private keys may include the corresponding public key. "
        "This test vector does include the public key.")
    der_without_public = self.xdh_group.asn_encode_priv(priv)
    der_with_public = self.xdh_group.asn_encode_priv(priv, pub)
    if encoding == der_without_public:
      return "valid", [flag.NORMAL], "Valid key without public key"
    if encoding == der_with_public:
      return "valid", [flag_public], "Valid key with public key"
    flag_wrong_type = flag.Flag(
        label="WrongType",
        bug_type=flag.BugType.MISSING_STEP,
        description="The encoded key uses wrong data types.")
    flag_wrong_params = flag.Flag(
        label="WrongParameters",
        bug_type=flag.BugType.MISSING_STEP,
        description="The encoded key uses incorrect parameters.")
    flag_unexpected_value = flag.Flag(
        label="UnexpectedValue",
        bug_type=flag.BugType.MISSING_STEP,
        description="The encoded key uses an incorrect value.")
    try:
      struct = asn_parser.parse(encoding)
      #
      # OneAsymmetricKey ::= SEQUENCE {
      #   version Version,
      #   privateKeyAlgorithm PrivateKeyAlgorithmIdentifier,
      #   privateKey PrivateKey,
      #   attributes [0] IMPLICIT Attributes OPTIONAL,
      #   ...,
      #   [[2: publicKey [1] IMPLICIT PublicKey OPTIONAL ]],
      # }
      if not isinstance(struct, list):
        return ("invalid", [flag_wrong_type],
                f"The ASN sequence oneAsymmeticKey has invalid type: "
                f"{type_of(struct)}")
      if len(struct) < 3:
        return ("invalid", [flag_wrong_params],
                "The ASN sequence oneAsymmeticKey should contain "
                "version, algorithm and private key")
      if len(struct) == 3:
        version, params, priv_key = struct
        pub_key = None
      elif len(struct) == 4:
        version, params, priv_key, pub_key = struct
      else:
        return ("invalid", [flag_wrong_params],
                "The ASN sequence oneAsymmeticKey contains additional "
                "elements.")
      if not isinstance(version, int):
        return ("invalid", [flag_wrong_type],
                f"The version has the wrong type: {type_of(version)}")
      if version not in (0, 1):
        return ("invalid", [flag_unexpected_value],
                f"Version={version}. Only version 0 and 1 are valid.")
      expected_params = [self.xdh_group.oid]
      if not isinstance(params, list):
        return ("invalid", [flag_wrong_type],
                f"The privateKeyAlgorithm should be a list but has type: "
                f"{type_of(version)}")
      if len(params) != 1:
        return ("invalid", [flag_wrong_params],
                f"The privateKeyAlgorithm should be a list containing only "
                f"the OID of the algorithm, but has length {len(params)}.")
      if str(params) != str(expected_params):
        return ("invalid", [flag_wrong_params],
                f"The privateKeyAlgorithm is incorrect.")
      if not is_octet_string(priv_key):
        return ("invalid", [flag_wrong_type],
                f"The privateKey should be an octet string, but has type: "
                f"{type_of(priv_key)}")
      # Adds an extra check to detect the bug in older jdk versions.
      if len(priv_key.val) == self.xdh_group.bytes:
        return ("invalid", [flag_unexpected_value],
                "The encoding of the private key is too short. "
                "Note that the encoding should be an octet string "
                "of an octet string.")
      key_struct = asn_parser.parse(priv_key.val)
      if not is_octet_string(key_struct):
        return ("invalid", [flag_wrong_type],
                f"The privateKey must be an octet string of an octet string "
                f"but is an octet string of {type_of(priv_key)}")
      if len(key_struct.val) != self.xdh_group.bytes:
        return ("invalid", [flag_wrong_params],
                f"The private key has a wrong length: {len(key_struct.val)} "
                f"instead of {self.xdh_group.bytes}.")
      if key_struct.val != priv:
        # Everything is OK, so far but the wrong key has been encoded.
        # Hence this is a test vector that is skipped.
        return None
      # Check the public key first ...
      if pub_key is not None:
        if not isinstance(pub_key, asn.Element):
          return ("invalid", [flag_wrong_params],
                  f"The key contains a public key, but has type: "
                  f"{type_of(pub_key)}.")
        tag = pub_key.get_tag()
        if tag != asn.Tag(1, asn.CONTEXT_SPECIFIC, True):
          return ("invalid", [flag_wrong_params],
                  f"Unexpected element with tag {tag}")
        pub_key_struct = pub_key.val
        if not is_bit_string(pub_key_struct):
          return ("invalid", [flag_wrong_params],
                  "The public key should be a bit string")
        if pub_key_struct != asn.BitString(pub):
          return ("invalid", [flag_wrong_params], "Changed public key")
      # ... then check the version.
      if version == 0:
        if pub_key is not None:
          unexpected_public_key = flag.Flag(
              label="Version0WithPublicKey",
              bug_type=flag.Bugtype.MISSING_STEP,
              description="If the public key is included then the version "
              "should be 1.")
          return ("invalid", [unexpected_public_key], "wrong version")
      elif version == 1:
        if pub_key is None:
          missing_public_key = flag.Flag(
              label="Version1withoutPublicKey",
              bug_type=flag.BugType.MISSING_STEP,
              description="The test vector contains a key with version 1, but "
              "no public key.")
        return ("invalid", [missing_public_key], "wrong version")


      # Check for BER encoding
      if asn.encode(struct) != encoding:
        flags.append(flag_ber)
        validity = "acceptable"
      elif validity == "acceptable":
        pass
      elif flags:
        pass
      else:
        # TODO: Needs more work. These are test cases for which
        #   no flags has been assigned. The following cases get here:
        #   - modified key.:x
        #   - using ASN composition.
        #   - modified OID
        validity = "acceptable"
        comment = "[TODO: check if this is acceptable]"
    except asn.AsnError as ex:
      flag_invalid_asn = flag.Flag(
          label="InvalidAsn",
          bug_type=flag.BugType.MISSING_STEP,
          description="The ASN encoding is invalid")
      return "invalid", [flag_invalid_asn], str(ex)
    assert validity is not None
    return validity, flags, comment

  @util.type_check
  def add_key(self,
              s: int,
              priv: bytes,
              pub: bytes,
              encoding: bytes,
              comment: str,
              validity: Optional[str] = None) -> None:
    """Adds an encoded key to the test vectors.

    Args:
      s: the private key as an integer
      priv: the raw encoded private key
      pub: the raw encdoded public key
      encoding: the ASN encoding of the key (this is used for the test vector)
      comment: a comment describing encoding
      validity: "valid", "invalid", "acceptable" or None
    """
    if encoding in self.encodings:
      return
    self.encodings.add(encoding)
    res = self.get_flags(priv, pub, encoding)
    if res is None:
      return
    validity_asn, flags, msg = res
    assert validity in (None, "valid", "acceptable", "invalid")
    assert validity_asn in ("valid", "acceptable", "invalid")
    if validity is None:
      validity = validity_asn
    elif validity != validity_asn:
      assert validity == "invalid" or validity_asn == "valid"
    # comment is returned by the fuzzer. This just describes the modification,
    # but cannot predict the effect it has on the resulting encoding.
    # msg is returned by get_flags, which analyzes the resulting encoding.
    if comment:
      if msg:
        comment = comment + ": " + msg
    else:
      comment = msg
    self.add_encoding(s, encoding, validity, comment, flags)

  def fuzz_key(self, s: int, include_public: bool = True):
    """Takes an XDH key and generates modified keys.

    Args:
      priv: the private key
      include_public: True if the public key is included in the key.
    """
    s = self.xdh_group.reduce_private(s)
    priv = self.xdh_group.encode_scalar(s)
    pub = self.xdh_group.public_key(priv)
    if include_public:
      struct = self.xdh_group.private_key_struct(priv, pub)
    else:
      struct = self.xdh_group.private_key_struct(priv)
    original_der = asn.encode(struct)
    for txt, der in asn_fuzzing.generate(struct):
      if der == original_der:
        txt = "DER encoded key"
      self.add_key(s, priv, pub, der, comment=txt)

  def generate_all(self):
    """Generates all test vectors for a given curve."""
    s = prand.randrange(
        1, self.xdh_group.order, seed="k3h4osd", label=self.xdh_group.name)
    self.fuzz_key(s, include_public=self.public_key_validation)


class XdhPrivateKeyProducer(producer.Producer):

  def parser(self):
    res = self.default_parser()
    res.add_argument(
        "--curve",
        type=str,
        choices=CURVES,
        default="curve25519",
        help="the name of the curve")
    res.add_argument(
        "--encoding",
        type=str,
        choices=ENCODINGS,
        default="pem",
        help="the encoding of the private keys")
    res.add_argument(
        "--public_key_validation",
        help="include test_vectors for a public key validation."
        " XDH private keys in ASN or PEM format have optional public keys."
        " If True then the test vectors expect that such public keys are"
        " validated",
        action="store_true")
    return res

  def generate_test_vectors(self, namespace):
    public_key_validation = getattr(namespace, "public_key_validation", True)
    tv = XdhPrivateKeyTestGenerator(namespace.curve, namespace.encoding,
                                    public_key_validation)
    tv.generate_all()
    return tv.test


# DEPRECATED: Use Producer.produce() instead
def main(namespace):
  XdhPrivateKeyProducer().produce(namespace)


if __name__ == "__main__":
  XdhPrivateKeyProducer().produce_with_args()
