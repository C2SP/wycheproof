# Copyright 2020 Google Inc. All Rights Reserved.
# Author: bleichen@google.com (Daniel Bleichenbacher)
#
# Generating test cases for EC private keys.

# TODO:
#   - add better checking of the generated ASN
#   - add more flags
#     * public key modified only
#   - check PEM parsing:
#     (see RFC 7468)
#     * does not allow headers (unlike RFC 1421)
#     * lines can be divided by CRLF, CR or LF
#     * There is a strict format.

import asn
import asn_fuzzing
import asn_parser
import AST
import base64
import ec_key
import ec
import ec_groups
import flag
import pem_util
import producer
import test_vector
import util
import prand
import modify
from typing import Optional

ECKEY_ENCODINGS = ["asn", "pem"]


class EcPrivateKeyAsnTestVector(test_vector.TestVector):
  """Test vectors that test importing of EC private keys from PEM

     The test vectors contain modified EC private keys.
     The goal of the test is to recognize if importing the EC private keys
     notices inconsistencies and bad formatting.
  """
  test_attributes = ["encodedKey"]
  group_attributes = ["curve"]
  schema = {
      "encodedKey": {
          "type": AST.Asn,
          "desc": "ASN encoded EC private key to test.",
      },
      "privateKey": {
          "type": AST.BigInt,
          "desc": "the private key in the PEM",
      },
  }

  def index(self):
    return self.curve


class EcPrivateKeyPemTestVector(test_vector.TestVector):
  """Test vectors that test importing of EC private keys from PEM

     The test vectors contain modified EC private keys.
     The goal of the test is to recognize if importing the EC private keys
     notices inconsistencies and bad formatting.
  """
  test_attributes = ["encodedKey"]
  group_attributes = ["curve"]
  schema = {
      "encodedKey": {
          "type": AST.Pem,
          "desc": "PEM encoded EC private key to test",
      },
      "privateKey": {
          "type": AST.BigInt,
          "desc": "the private key in the PEM",
      },
  }

  def index(self):
    return self.curve


class EcPrivateKeyAsnVerify(test_vector.TestType):
  """Test vectors for importing EC private keys in ASN format.

  Test vectors of type EcPrivateKeyAsnVerify are intended for testing
  the import of ASN encoded private keys. The assumption here is that
  the importing library performs a key validation. Hence if the encoding
  includes the public key, then the test expects that public keys not matching
  the private key are rejected.

  Some applications may not need a public key validation or make other
  assumptions about the encoded keys, since private keys frequently come from
  trusted sources. In such cases the main purpose of the test vectors is to
  check that misformed keys do not crash the application and that valid
  keys are accepted.

  The keys have the following validities:
    valid:  valid key with correct DER encoding
    acceptable:  valid key with alternative BER encoding.
    invalid: invalid key, incorrect public key or invalid ASN encoding.
  """

class EcPrivateKeyPemVerify(test_vector.TestType):
  """Test vectors for importing EC private keys in PEM format.

  Test vectors of type EcPrivateKeyPemVerify are intended for testing
  the import of PEM encoded private keys. The assumption here is that
  the importing library performs a key validation. Hence if the encoding
  includes the public key, then the test expects that public keys not matching
  the private key are rejected.

  Some applications may not need a public key validation or make other
  assumptions about the encoded keys, since private keys frequently come from
  trusted sources. In such cases the main purpose of the test vectors is to
  check that misformed keys do not crash the application and that valid
  keys are accepted.

  The keys have the following validities:
    valid:  valid key with correct PEM and DER encoding
    acceptable:  valid key with alternative PEM or BER encoding.
    invalid: invalid key, incorrect public key or invalid ASN encoding.
  """


class EcPrivateKeyTestGroup(test_vector.TestGroup):
  schema = {
      "curve": {
          "type": str,
          "desc": "the curve of the private key",
      },
  }

  def __init__(self, curve: str):
    """Constructs a test group for EC private keys.
    
    Args:
      curve: the name of a curve (e.g. "secp256r1")
    """
    super().__init__()
    self.curve = curve

  def as_struct(self, sort_by: str = None):
    """See base class."""
    if sort_by is None:
      sort_by = "comment"
    group = {}
    group["type"] = self.testtype
    group["curve"] = self.curve
    group["tests"] = self.get_all_vectors(sort_by=sort_by)
    return group


class EcPrivateKeyAsnTestGroup(EcPrivateKeyTestGroup):
  testtype = EcPrivateKeyAsnVerify
  vectortype = EcPrivateKeyAsnTestVector


class EcPrivateKeyPemTestGroup(EcPrivateKeyTestGroup):
  testtype = EcPrivateKeyPemVerify
  vectortype = EcPrivateKeyPemTestVector


def pem(struct: asn.AsnStructure) -> str:
  """Coverts an ASN structure into the PEM format.
  
  Args:
    struct: the ASN structure of a private key
  Returns:
    the PEM encoded private key
  """
  return pem_util.private_key_pem(asn.encode(struct))


def is_octet_string(val: asn.AsnStructure):
  """Returns True if val is an OctetString"""
  return isinstance(val, asn.Element) and val.get_tag() == asn.OCTET_STRING

def is_bit_string(val: asn.AsnStructure):
  """Returns True if val is a BitString"""
  return isinstance(val, asn.Element) and val.get_tag() == asn.BIT_STRING


class EcPrivateKeyTestGenerator(test_vector.TestGenerator):
  algorithm = "EcPrivateKeyTest"

  def __init__(self, encoding: str):
    assert encoding in ECKEY_ENCODINGS
    self.encoding = encoding
    self.test = test_vector.Test(self.algorithm)
    self.encodings = set()

  def new_testgroup(self, idx):
    if self.encoding == "asn":
      return EcPrivateKeyAsnTestGroup(idx)
    elif self.encoding == "pem":
      return EcPrivateKeyPemTestGroup(idx)
    else:
      print(self.encoding)
      raise ValueError("Unsupported encoding")

  @util.type_check
  def add_encoding(self, key: ec_key.EcPrivateKey, asn: bytes, validity: str,
                   comment: str, flags: list[flag.Flag]):
    """Adds a test vector.

    Args:
      key: the key
      asn: the encoded key,
      validity: "valid", "invalid" or "acceptable"
      comment: a comment describing the key
      flags: flags describing the goal of the test vector
    """

    c = key.group
    s = key.s
    flags = self.add_flags(flags)
    if self.encoding == "asn":
      test = EcPrivateKeyAsnTestVector(
          curve=c.name,
          encodedKey=asn,
          s=AST.BigInt(s),
          result=validity,
          comment=comment,
          flags=flags)
    elif self.encoding == "pem":
      pem = pem_util.private_key_pem(asn)
      test = EcPrivateKeyPemTestVector(
          curve=c.name,
          encodedKey=pem,
          s=AST.BigInt(s),
          result=validity,
          comment=comment,
          flags=flags)
    else:
      raise ValueError("Unknown encoding")
    self.add_test(test)

  @util.type_check
  def get_flags(self, priv: ec_key.EcPrivateKey,
                encoding: bytes) -> tuple[str, list[flag.Flag], str]:
    """Gets flags for an encoded private key.

    Args:
      priv: the private key that is supposed to be encoded.
      encoding: the encoding to check

    Returns:
      A tuple containing the validity of the encoding and a list of flags.
    """
    # TODO: Add more flags
    flags = []
    validity = None
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
    der_without_public = priv.encode(include_public=False)
    der_with_public = priv.encode(include_public=True)
    if encoding == der_without_public:
      return "valid", [flag.NORMAL], "Valid key without public key"
    if encoding == der_with_public:
      return "valid", [flag_public], "Valid key with public key"
    group = priv.group
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
      if not isinstance(struct, list):
        return ("invalid", [flag_wrong_type],
                "Expecting a list [version, params, key]")
      if len(struct) != 3:
        return ("invalid", [flag_wrong_params],
                "Expecting a list [version, params, key]")
      version, params, key = struct
      if version != 0:
        return "invalid", [flag_unexpected_value], "Expecting version 0"
      oid_ec_public_key = asn.Oid([1, 2, 840, 10045, 2, 1])
      oid_group = group.asn_struct(True)
      expected_params = [oid_ec_public_key, oid_group]
      if str(params) != str(expected_params):
        return "invalid", [flag_wrong_params], "Parameters are incorrect"
      if not is_octet_string(key):
        return "invalid", [flag_wrong_type], "Key should be an octetstring."
      key_struct = asn_parser.parse(key.val)
      if not isinstance(key_struct, list):
        return "invalid", [flag_wrong_type], "Key should be a list"
      if len(key_struct) < 2:
        return "invalid", [flag_wrong_params], "Key has too few parameters"
      version = key_struct[0]
      privkey = key_struct[1]
      key_params = None
      pubkey = None
      for f in key_struct[2:]:
        if not isinstance(f, asn.Element):
          return ("invalid", [flag_wrong_type],
                  "Unrecognized elemement in key " + str(type(f)))
        tag = f.get_tag()
        if tag == asn.Tag(0, asn.CONTEXT_SPECIFIC, True):
          if key_params is None:
            key_params = f.val
          else:
            return ("invalid", [flag_wrong_params], "Duplicate parameters")
        elif tag == asn.Tag(1, asn.CONTEXT_SPECIFIC, True):
          if pubkey is None:
            pubkey = f.val
          else:
            return ("invalid", [flag_wrong_params], "Duplicate public key")
        else:
          return ("invalid", [flag_wrong_params],
                  "Unrecognized tag:" + str(tag))
      if version != 1:
        return ("invalid", [flag_unexpected_value], "Unexpected version")
      if not is_octet_string(privkey):
        return ("invalid", [flag_wrong_type],
                "Expecting private key to be an OctetString")
      if len(privkey.val) != group.encoding_length:
        flag_wrong_length = flag.Flag(
            label="WrongPrivateKeyLength",
            bug_type=flag.BugType.MISSING_STEP,
            description="The size of the private key is incorrect")
        validity = "acceptable"
        flags.append(flag_wrong_length)
      s = int.from_bytes(privkey.val, "big")
      if s == 0:
        return ("invalid", [flag_unexpected_value], "Private key is 0")
      if key_params is not None:
        if str(key_params) == str(oid_group):
          validity = "acceptable"
        else:
          return ("invalid", [flag_wrong_params
                             ], f"Key contains {str(key_params)} instead of " +
                  f"{str(oid_group)}")
      if pubkey is not None:
        flags.append(flag_public)
        if not is_bit_string(pubkey):
          return ("invalid", [flag_wrong_type], "public key has wrong type")
        pub = ec_key.EcPrivateKey(group, s).public()
        compressed = group.encode_compressed(pub.w)
        uncompressed = group.encode_uncompressed(pub.w)
        if pubkey.val == bytes(1) + compressed:
          flag_compressed = flag.Flag(
              label="CompressedPublic",
              bug_type=flag.BugType.FUNCTIONALITY,
              description="The key contains a compressed public key.")
          flags.append(flag_compressed)
          validity = "acceptable"
        elif pubkey.val == bytes(1) + uncompressed:
          pass
        else:
          incorrect_public = flag.Flag(
              label="IncorrectPublic",
              bug_type=flag.BugType.MISSING_STEP,
              description="The public key does not match the private key. "
              "Accepting such keys mainly means that the library "
              "does not perform a key validation. Whether this "
              "is a potential vulnerability depends on the use "
              "case.")
          return ("invalid", [incorrect_public], "public key is incorrect")
      # Check for BER encoding
      if asn.encode(key_struct) != key.val:
        flags.append(flag_ber)
        validity = "acceptable"
      elif asn.encode(struct) != encoding:
        flags.append(flag_ber)
        validity = "acceptable"
      elif validity == "acceptable":
        pass
      else:
        # TODO: Cases here may be undefined.
        flags.append(
            flag.Flag(
                label="Undefined",
                bug_type=flag.BugType.FUNCTIONALITY,
                description="This is a case with potentially undefined behavior"
            ))
        validity = "acceptable"
      comment = ""
    except asn.AsnError as ex:
      flag_invalid_asn = flag.Flag(
          label="InvalidAsn",
          bug_type=flag.BugType.MISSING_STEP,
          description="The ASN encoding is invalid")
      return "invalid", [flag_invalid_asn], str(ex)
    except ValueError as ex:
      validity = "invalid"
      comment = str(ex)
    assert validity is not None
    return validity, flags, comment

  @util.type_check
  def add_key(self,
              key: ec_key.EcPrivateKey,
              encoding: bytes,
              comment: Optional[str],
              validity=None,
              flags: Optional[list[flag.Flag]] = None):
    """Adds an encoded key to the test vectors.
    
    Args:
      key: the key that is encoded
      encoding: the ASN encoding of the key (this is used for the test vector)
      comment: a comment describing encoding
      validity: "valid", "invalid", "acceptable" or None
      flags: flags for the test vector.
    """
    if comment is None:
      comment = ""
    if flags is None:
      flags = []
    if encoding in self.encodings:
      return
    self.encodings.add(encoding)
    validity_asn, more_flags, msg = self.get_flags(key, encoding)
    assert validity in (None, "valid", "acceptable", "invalid")
    assert validity_asn in ("valid", "acceptable", "invalid")
    if validity is None:
      validity = validity_asn
    elif validity != validity_asn:
      if not (validity == "invalid" or validity_asn == "valid"):
        print("Inconsistent validity", validity, validity_asn)
        print(flags, comment, msg)
        print(encoding.hex())
        return
        raise ValueError("inconsistent validity")
    flags = flags + more_flags
    # comment is returned by the fuzzer. This just describes the modification,
    # but cannot predict the effect it has on the resulting encoding.
    # msg is returned by get_flags, which analyzes the resulting encoding.
    if comment:
      if msg:
        comment = comment + ": " + msg
    else:
      comment = msg
    self.add_encoding(key, encoding, validity, comment, flags)

  def fuzz_key(self, priv: ec_key.EcPrivateKey, include_public: bool = True):
    """Takes an EC key and generates modified keys.

    Args:
      priv: the private key
      include_public: True if the public key is included in the key.
    """
    struct = priv.asn_struct(include_public=include_public)
    original_der = asn.encode(struct)
    keymat_key = asn.encode(struct[2])
    for txt, der in asn_fuzzing.generate(struct):
      if der == original_der:
        comment = "DER encoded key"
      self.add_key(priv, der, comment=txt)

  @util.type_check
  def add_priv_asn(self,
                   priv: ec_key.EcPrivateKey,
                   priv_asn,
                   validity: Optional[str] = None,
                   comment: Optional[str] = None):
    group = priv.group
    oid = asn.Oid("2a8648ce3d0201")
    ecparams = group.asn_struct(True)
    priv_key_struct = [0, [oid, ecparams], priv_asn]
    self.add_key(
        priv, asn.encode(priv_key_struct), validity=validity, comment=comment)

  def modify_params(self,
                    priv: ec_key.EcPrivateKey,
                    include_public: bool = True):
    """Takes an EC key and generates keys with redundant curve specs.

    Args:
      priv: the private key.
      include_public: includes the public key if True
    """
    group = priv.group
    public = priv.public()
    bytes = group.encoding_length
    # ECPrivateKey from Section A of RFC 5915
    priv_bytes = asn.OctetString(asn.encode_bigint_fixedlength(priv.s, bytes))
    parameters = asn.Explicit(0, group.asn_struct(True), asn.CONTEXT_SPECIFIC,
                              True)
    if include_public:
      pub_point = asn.BitString(public.encode_pub_point())
      pub_key = asn.Explicit(1, pub_point, asn.CONTEXT_SPECIFIC, True)
      priv_struct = asn.Sequence(
          version=1,
          privateKey=priv_bytes,
          parameters=parameters,
          publicKey=pub_key)
      priv_asn = asn.OctetStringFromStruct(priv_struct)
      self.add_priv_asn(
          priv,
          priv_asn,
          validity="acceptable",
          comment="Including ecparams in key")
      priv_struct2 = asn.Sequence(
          version=1,
          privateKey=priv_bytes,
          publicKey=pub_key,
          parameters=parameters)
      priv_asn = asn.OctetStringFromStruct(priv_struct2)
      self.add_priv_asn(
          priv,
          priv_asn,
          validity="acceptable",
          comment="Reversed order of ecparams and public key")
    else:
      priv_struct = asn.Sequence(
          version=1,
          privateKey=priv_bytes,
          parameters=parameters)
      priv_asn = asn.OctetStringFromStruct(priv_struct)
      self.add_priv_asn(
          priv,
          priv_asn,
          validity="acceptable",
          comment="Including ecparams in key")

    for other_group in ec_groups.jwk_curves:
      if group == other_group:
        continue
      other_parameters = asn.Explicit(0, other_group.asn_struct(True),
                                      asn.CONTEXT_SPECIFIC, True)
      if include_public:
        pub_point = asn.BitString(public.encode_pub_point())
        pub_key = asn.Explicit(1, pub_point, asn.CONTEXT_SPECIFIC, True)
        priv_struct = asn.Sequence(
            version=1,
            privateKey=priv_bytes,
            parameters=other_parameters,
            publicKey=pub_key)
      else:
        priv_struct = asn.Sequence(
            version=1,
            privateKey=priv_bytes,
            parameters=other_parameters)
      priv_asn = asn.OctetStringFromStruct(priv_struct)
      self.add_priv_asn(
          priv, priv_asn, comment="ecparams in key uses " + other_group.name)
      if include_public:
        other_priv = ec_key.EcPrivateKey(other_group, priv.s)
        other_pub = other_priv.public()
        other_pub_point = asn.BitString(other_pub.encode_pub_point())
        other_pub_key = asn.Explicit(1, other_pub_point, asn.CONTEXT_SPECIFIC,
                                     True)
        other_priv_struct = asn.Sequence(
            version=1,
            privateKey=priv_bytes,
            parameters=other_parameters,
            publicKey=other_pub_key)
        other_priv_asn = asn.OctetStringFromStruct(other_priv_struct)
        self.add_priv_asn(
            priv,
            other_priv_asn,
            validity="invalid",
            comment="Parameters and public key on wrong curve")

  def generate_all(self, curve: str, public_key_validation: bool):
    """Generates all test vectors for a given curve.
    
    Args:
      curve: the name of the curve (e.g. "secp256r1")
      public_key_validation: if True then test vectors with faulty
          public keys are included. The test expects that a public key
          validation is performed and hence that faulty public keys are
          rejected.
    """
    group = ec_groups.named_curve(curve)
    s = prand.randrange(1, group.n, seed=b"12lk3j123", label=group.name)
    p = ec_key.EcPrivateKey(group, s)
    if public_key_validation:
      self.fuzz_key(p, include_public=True)
      self.modify_params(p, include_public=True)
    else:
      self.fuzz_key(p, include_public=False)
      self.modify_params(p, include_public=False)

  def generate_valid(self):
    """Generates valid keys for all the known curves."""
    for group in ec_groups.all_curves:
      if not hasattr(group, "oid"):
        pass
      s = prand.randrange(1, group.n, seed=b"12lk3j123", label=group.name)
      priv = ec_key.EcPrivateKey(group, s)
      for include_public in [True, False]:
        encoding = priv.encode(include_public=include_public)
        self.add_key(priv, encoding, "valid")


class EcPrivateKeyProducer(producer.Producer):

  def parser(self):
    res = self.default_parser()
    res.add_argument(
        "--curve",
        type=str,
        default="secp256r1",
        help="the name of the curve. If no curve is given then the result"
        " is a test vector file with valid keys for each known curve.")
    res.add_argument(
        "--encoding",
        type=str,
        choices=ECKEY_ENCODINGS,
        default="pem",
        help="the encoding of the EC keys")
    res.add_argument(
        "--public_key_validation",
        help="include test_vectors for a public key validation."
        " EC private keys in ASN or PEM format have optional public keys."
        " If True then the test vectors expect that such public keys are"
        " validated",
        action="store_true")
    return res

  def generate_test_vectors(self, namespace):
    tv = EcPrivateKeyTestGenerator(namespace.encoding)
    curve = getattr(namespace, "curve", "")
    public_key_validation = getattr(namespace, "public_key_validation", True)
    if curve:
      tv.generate_all(curve, public_key_validation)
    else:
      tv.generate_valid()
    return tv.test


# DEPRECATED: Use Producer.produce() instead
def main(namespace):
  EcPrivateKeyProducer().produce(namespace)


if __name__ == "__main__":
  EcPrivateKeyProducer().produce_with_args()
