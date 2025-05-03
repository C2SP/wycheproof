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

# TODO: ec_key has public keys without hash, since this is used
#  both for ECDSA and ECDH.
# TODO: Implement ECDSA-Signer.
# TODO: Extending to SHA-3/SHAKE:
#  There are more options using SHA-3 than when using SHA-2.
#  tools.ietf.org/id/draft-turner-lamps-adding-sha3-to-pkix-01.html
#  defines SHA-3 related identifiers
#  https://csrc.nist.rip/groups/ST/crypto_apps_infra/csor/algorithms.html
#  does the same.
#  RFC 8692 extends ECDSA with shake.
# TODO: Add special cases for binary curves:
#  - binary curves often have a cofactor > 1. There may be some special cases.
#  - binary curves allow new types of optimizations:
#    e.g. eprint/iacr.org/2013/741.pdf
#  - compute special points for binary curves
#  - extreme points: x=0 e.g. Koblitz curves have (0,1) as points.
#  - test vector generation for binary curves takes up to 15 minutes.

import AST
import amd_sev_ec
import asn
import asn_fuzzing
import asn_parser
import group as gp
import ec
import ec_key
import ec_groups
import flag
import prand
import producer
import special_values
import special_values_ec
import special_int
import sig_test_vector
import test_vector
from typing import Any, Callable, Optional, Union
import util

SIGNATURE_ENCODINGS = ["asn", "bitcoin", "webcrypto", "p1363", "amd_sev"]

HASHES = ["SHA-224", "SHA-256", "SHA-384", "SHA-512",
          "SHA3-224", "SHA3-256", "SHA3-384", "SHA3-512",
          "SHAKE128", "SHAKE256"]

def truncated_hash(group: ec_groups.EcGroup, digest: bytes) -> int:
  """Truncates a message digest and coverts it into an integer.

  If the bit length of the message digest is larger than the bit length of the
  order of the multiplicative group then the message digest is truncated to
  the most significant bits of the digest. The result is converted to an
  integer using bigendian byte order. The result h can still be bigger than
  the order of the multiplicative group, but it cannot have more bits.

  Args:
    group: the EC group
    digest: the output of the hash function

  Returns:
    the truncated digest converted to an integer
  """
  h = int.from_bytes(digest, "big")
  truncate_bits = len(digest) * 8 - group.n.bit_length()
  if truncate_bits > 0:
    h >>= truncate_bits
  return h


def p1363_sig(r: int, s: int, mod: int) -> bytes:
  """Generates a P1363 encoded signature.

  P1363 encodes ECDSA signature as a concatenation
  of two fixed length unsigned integers using bigendian
  byte order.

  Args:
    r: the parameter r of a raw signature (r,s)
    s: the parameter s of a raw signature (r,s)
    mod: the modulus (i.e. the parameter n of a key)

  Returns:
    a P3163 encoded signature.
  """
  length = (mod.bit_length() + 7) // 8
  rbytes = r.to_bytes(length, "big")
  sbytes = s.to_bytes(length, "big")
  return rbytes + sbytes

@util.type_check
def verify_digest(group: ec_groups.EcGroup, pub: ec.EcPoint, r: int, s: int,
                  digest: bytes) -> bool:
  """Verifies an ECDSA signatures given the hash of the message.

  Args:
    group: the EC group used for the signature scheme
    pub:  the point of the public key
    r:  the r value of the signature
    s:  the s value of the signature
    digest: the (untruncated) hash of the message
  Returns:
    True if the signature is valid, False otherwise
  """
  n = group.n
  if r <= 0 or r >= n or s <= 0 or s >= n:
    return False
  h = truncated_hash(group, digest)
  w = pow(s, -1, n)
  u1 = h * w % n
  u2 = r * w % n
  pt = u1 * group.generator() + u2 * pub
  if not pt:
    return False
  return int(pt.affine_x()) % n == r


def get_hash_for_group(group: ec_groups.EcGroup) -> str:
  """Returns a suitable hash for an EC group.

  This function is used when the hash function is undefined.
  The hash function should have a digest length that is at least
  of comparable length as field elements.

  Args:
    group: the EC group for which a hash function is selected
  Returns:
    the name of a hash function suitable for the EC group.
    (e.g. "SHA-256")
  """
  bits = group.n.bit_length()
  if bits <= 256: return "SHA-256"
  elif bits <= 384: return "SHA-384"
  return "SHA-512"

class EcdsaVerify(test_vector.TestType):
  """Test vectors of type EcdsaVerify are meant for the verification
     of ASN encoded ECDSA signatures.

     Test vectors with "result" : "valid" are valid signatures.
     Test vectors with "result" : "invalid" are invalid.
     Test vectors with "result" : "acceptable" are signatures that may
     or may not be rejected. The reasons for potential rejection are
     described with labels. There are now less test vectors with
     result "acceptable" than in previous versions. E.g.,
     test vectors with weak paramaters are now simply "valid".
     Flags with BugType.WEAK_PARAMETER now indicate weak parameters.
     Test vectors using BER instead of DER encoding are now "invalid".
     Flags with BugType.
  """

class EcdsaTestGroup(test_vector.TestGroup):
  """A test group for ECDSA signatures.
     The test vectors in this group are meant for signature verification.

     The test group contains the same public key for the signatures in
     multiple representations. The public keys are valid with the sole
     exception that they may use short keys and weak hash functions
     such as SHA-1.
  """

  algorithm = "ECDSA"
  testtype = EcdsaVerify
  vectortype = sig_test_vector.AsnSignatureTestVector
  allow_acceptable = False
  schema = {
      "publicKey": {
          "type": ec_key.EcPublicKey,
          "desc": "unencoded EC public key",
      },
      "publicKeyDer": {
          "type": AST.Der,
          "desc": "DER encoded public key",
      },
      "publicKeyPem": {
          "type": AST.Pem,
          "desc": "Pem encoded public key",
      },
      "sha": {
          "type": AST.MdName,
          "desc": "the hash function used for ECDSA",
      }
  }

  @util.type_check
  def __init__(self, pubkey: ec_key.EcPublicKey, md: str):
    super().__init__()
    self.pubkey = pubkey
    self.md = md
    self.encoding = "asn"

  def as_struct(self, sort_by: Optional[str] = None) -> dict[str, Any]:
    """Returns the test groups as as a dictionary.
    
    Args:
      sort_by: The field that is used to sort the test vectors.
          By default the test vectors are sorted by comment.
          Sorting means that test vectors with the same comment
          are grouped together. Test vectors with different comments
          are sorted in the order in which they were generated.
    """
    if sort_by is None:
      sort_by = "comment"
    group = {}
    group["type"] = self.testtype
    group["publicKey"] = self.pubkey.as_struct()
    group["publicKeyDer"] = self.pubkey.encode_hex()
    group["publicKeyPem"] = self.pubkey.pem()
    group["sha"] = self.md
    group["tests"] = self.get_all_vectors(sort_by=sort_by)
    return group


# Other things to try:
#   Generate a signature with s=1 and encode as boolean True.
#   Generate a signature with a small s an encode it as float.
class EcdsaBitcoinVerify(test_vector.TestType):
  """Test vectors of type EcdsaBitcoinVerify are meant for the verification
     of a ECDSA variant used for bitcoin, that add signature non-malleability.

     The bitcoin protocol requires that the signature scheme is non-malleable.
     It must not be possible to format the same signature in multiple ways. 
     This variant is described in
     https://github.com/bitcoin/bips/blob/master/bip-0066.mediawiki

     Test vectors with "result" : "valid" are valid signatures.
     Test vectors with "result" : "invalid" are invalid.

     Compared to normal ECDSA signatures, all alternative BER encodings
     of the signature are invalid. The value s in the signature must
     be a positive integer smaller than n/2.
  """


class EcdsaBitcoinTestGroup(test_vector.TestGroup):
  """A test group for the bitcoin variant of ECDSA signatures.
     The test vectors in this group are meant for signature verification.

     The test group contains the same public key for the signatures in
     multiple representations. The public keys are valid.
  """

  algorithm = "ECDSA"
  testtype = EcdsaBitcoinVerify
  vectortype = sig_test_vector.AsnSignatureTestVector
  schema = {
      "publicKey": {
          "type": ec_key.EcPublicKey,
          "desc": "unencoded EC public key",
      },
      "publicKeyDer": {
          "type": AST.Der,
          "desc": "DER encoded public key",
      },
      "publicKeyPem": {
          "type": AST.Pem,
          "desc": "Pem encoded public key",
      },
      "sha": {
          "type": AST.MdName,
          "enum": ["SHA-256"],
          "desc": "the hash function used for ECDSA",
      }
  }

  @util.type_check
  def __init__(self, pubkey: ec_key.EcPublicKey, md: str = "SHA-256"):
    super().__init__()
    self.pubkey = pubkey
    self.md = md
    self.encoding = "asn"

  def as_struct(self, sort_by: str = None) -> dict[str, Any]:
    if sort_by is None:
      sort_by = "comment"
    group = {}
    group["type"] = self.testtype
    group["publicKey"] = self.pubkey.as_struct()
    group["publicKeyDer"] = self.pubkey.encode_hex()
    group["publicKeyPem"] = self.pubkey.pem()
    group["sha"] = self.md
    group["tests"] = self.get_all_vectors(sort_by=sort_by)
    return group

class EcdsaP1363Verify(test_vector.TestType):
  """Test vectors of type EcdsaVerify are meant for the verification
     of IEEE P1363 encoded ECDSA signatures.

     IEEE P1363 encoded signatures are the concatenation of the values
     r and s encoded as unsigned integers in bigendian order using a fixed
     size equal to the length of the field order.

     Test vectors with "result" : "valid" are valid signatures.
     Test vectors with "result" : "invalid" are invalid.
     Test vectors with "result" : "acceptable" are signatures that may
     or may not be rejected. The reasons for potential rejection are
     described with labels. Weak parameters such as small curves,
     hash functions weaker than the security of the curve are potential
     reasons.
  """

class EcdsaP1363TestGroup(test_vector.TestGroup):
  """A test group for ECDSA signatures using IEEE P1363 encoding.
     The test vectors in this group are meant for signature verification.

     The test group contains the same public key for the signatures in
     multiple representations. The public keys are valid with the sole
     exception that they may use short keys and weak hash functions
     such as SHA-1."""

  algorithm = "ECDSA"
  testtype = EcdsaP1363Verify
  vectortype = sig_test_vector.SignatureTestVector
  schema = {
      "publicKey": {
          "type": ec_key.EcPublicKey,
          "desc": "unencoded EC public key",
      },
      "publicKeyDer": {
          "type": AST.Der,
          "desc": "DER encoded public key",
      },
      "publicKeyPem": {
          "type": AST.Pem,
          "desc": "Pem encoded public key",
      },
      "publicKeyJwk": {
          "type": ec_key.JwkEcPublicKey,
          "desc": "the public key in webcrypto format",
          "optional": True,
      },
      "sha": {
          "type": AST.MdName,
          "desc": "the hash function used for ECDSA",
      }
  }

  @util.type_check
  def __init__(self, pubkey: ec_key.EcPublicKey, md: str):
    super().__init__()
    self.pubkey = pubkey
    self.md = md
    self.encoding = "p1363"

  def as_struct(self, sort_by: str = None) -> dict[str, Any]:
    if sort_by is None:
      sort_by = "comment"
    group = {}
    group["type"] = self.testtype
    group["publicKey"] = self.pubkey.as_struct()
    group["publicKeyDer"] = self.pubkey.encode_hex()
    group["publicKeyPem"] = self.pubkey.pem()
    group["sha"] = self.md
    group["tests"] = self.get_all_vectors(sort_by=sort_by)
    # Include jwk key if the curve has a name.
    jwk = self.pubkey.jwk()
    if (jwk):
      group["publicKeyJwk"] = jwk
    return group


class EcdsaAmdSevVerify(test_vector.TestType):
  """Test vectors of type EcdsaAmdSevVerify are meant for the verification
     of ECDSA signatures in the format defined in AMD SEV.

     Test vectors with "result" : "valid" are valid signatures.
     Test vectors with "result" : "invalid" are invalid.
     Test vectors with "result" : "acceptable" are signatures that may
     or may not be rejected. The reasons for potential rejection are
     described with labels.
  """

# TODO: EcdsaAmdSev is used only to evaluate a proprietary
#   implementation. Because of this there are no plans to publish the
#   test vectors. The naming of the fields in the test vectors are still
#   using a naming scheme that has not been unified. I.e., instead of
#   key, keyAmdSev, it would be more consistent to used publicKey,
#   publicKeyAmdSev etc.
class EcdsaAmdSevTestGroup(test_vector.TestGroup):
  """A test group for ECDSA signatures using AMD SEV encoding.
     The test vectors in this group are meant for signature verification.
  """

  algorithm = "ECDSA"
  testtype = EcdsaAmdSevVerify
  vectortype = sig_test_vector.SignatureTestVector
  schema = {
      "key": {
          "type": ec_key.EcPublicKeyOnNamedCurve,
          "desc": "unencoded EC public key",
      },
      "keyAmdSev": {
          "type": AST.HexBytes,
          "desc": "encoded public key",
      },
      "keyPrivAmdSev": {
          "type": AST.HexBytes,
          "desc": "encoded private key",
      },
      "sha": {
          "type": AST.MdName,
          "desc": "the hash function used for ECDSA",
      }
  }

  @util.type_check
  def __init__(self, privkey: ec_key.EcPrivateKey, pubkey: ec_key.EcPublicKey,
               md: str):
    super().__init__()
    self.privkey = privkey
    self.pubkey = pubkey.asEcPublicKeyOnNamedCurve()
    self.md = md
    self.encoding = "amd_sev"

  def as_struct(self, sort_by: Optional[str] = None) -> dict[str, Any]:
    if sort_by is None:
      sort_by = "comment"
    key = self.pubkey
    group = {}
    group["type"] = self.testtype
    group["key"] = key.as_struct()
    group["keyAmdSev"] = amd_sev_ec.encode_ec_public(key)
    group["keyPrivAmdSev"] = amd_sev_ec.encode_ec_private(self.privkey.s)
    group["sha"] = self.md
    group["tests"] = self.get_all_vectors(sort_by=sort_by)
    return group


class KeyPair:

  def __init__(self,
               privkey: Optional[ec_key.EcPrivateKey] = None,
               pubkey: Optional[ec_key.EcPublicKey] = None):
    self.priv = privkey
    if privkey is not None:
      assert pubkey is None
      self.pub = self.priv.public()
    else:
      self.pub = pubkey


def make_key_pair(group: ec_groups.EcGroup, s: int):
  return KeyPair(ec_key.EcPrivateKey(group, s))


valid_signature = flag.Flag(
    label="ValidSignature",
    bug_type=flag.BugType.BASIC,
    description="The test vector contains a valid signature that was "
    "generated pseudorandomly. Such signatures should not fail to verify "
    "unless some of the parameters (e.g. curve or hash function) are not "
    "supported.")


class EcdsaTestGenerator(test_vector.TestGenerator):
  algorithm = "ECDSA"
  testinput = "sig"

  def __init__(self,
               group: ec_groups.EcGroup,
               md: str,
               encoding: str = "asn",
               msgs: Optional[list[bytes]] = None,
               msgbuilder: Optional[Callable[[ec_key.EcPublicKey, str],
                                             bytes]] = None):
    """Constructs a test vector generator for ECDSA signatures.

    Args:
      encoding: the encoding of the signature (e.g. "asn", "p1363" or "jwk")
      msgs: an optional list of messages, that are being signed.
      msgbuilder: an optional function that builds a message from an a public key
        and message digest
    """
    super().__init__()
    self.test = test_vector.Test(self.algorithm)
    assert encoding in SIGNATURE_ENCODINGS
    self.group = group
    self.md = md
    self.encoding = encoding
    self.msgs = msgs
    self.msgbuilder = msgbuilder

  def hash_message(self, msg: bytes) -> int:
    digest = util.hash(self.md, msg)
    return truncated_hash(self.group, digest)

  @util.type_check
  def sign_deterministic(self,
                         priv: ec_key.EcPrivateKey,
                         msg: bytes,
                          salt: bytes = b"") -> tuple[int, int]:
    """Returns a deterministic signature for a message.

    Most of the test vectors use deterministic signatures, since
    pseudorandom signatures allows to check differences during
    code reviews.

    Args:
      priv: the private key
      digest: the hash of the message to sign
      salt: a salt that can be used to randomize the signature
    Returns:
      a signature as a pair of integers [r,s]
    """
    assert priv.group == self.group
    group = self.group
    h = self.hash_message(msg)
    digest = util.hash(self.md, msg)
    cnt = 0
    while True:
      label = digest.hex().encode("ascii") + salt + str(cnt).encode("ascii")
      cnt += 1
      k = prand.randrange(1, group.n, str(priv.s), label)
      v = k * group.generator()
      r = int(v.affine_x()) % group.n
      if r == 0:
        continue
      s = pow(k, -1, group.n) * (h + r * priv.s) % group.n
      if s == 0:
        continue
      pt = priv.public().point()
      assert verify_digest(group, pt, r, s, digest)
      return (r, s)



  def point_from_x(self, x: int) -> gp.Point:
    y = self.group.get_y(x)
    if y is not None:
      return self.group.get_point(x, y)

  def next_point_from_x(self,
                        x: int,
                        delta: int = 1,
                        in_subgroup: bool = True) -> tuple[int, gp.Point]:
    """Finds a point on the curve with x-coordinate x + k*delta

      Args:
         x: the first x-coordinate tried
         delta: the increment
         in_subgroup: point must be subgroup of order n

      Returns:
         a tuple containing the x-coordinate and corresponding point on the
         curve
      """
    if delta == 0:
      raise ValueError("delta must not be 0")
    q = self.group.field_size()
    while True:
      x %= q
      y = self.group.get_y(x)
      if y is not None:
        pt = self.group.get_point(x, y)
        if self.group.h == 1 or not in_subgroup or not pt * self.group.n:
          return x, pt
      x += delta

  def supported_groups(self) -> list[ec_groups.EcGroup]:
    if self.encoding == "webcrypto":
      return ec_groups.jwk_curves
    elif self.encoding == "amd_sev":
      return amd_sev_ec.amd_sev_curves
    else:
      return ec_groups.predefined_curves

  @util.type_check
  def new_testgroup(self, privkey: Optional[ec_key.EcPrivateKey],
                    pubkey: ec_key.EcPublicKey):
    md = self.md
    if self.encoding == "asn":
      return EcdsaTestGroup(pubkey, md)
    elif self.encoding == "bitcoin":
      return EcdsaBitcoinTestGroup(pubkey, md)
    elif self.encoding in ["p1363", "webcrypto"]:
      return EcdsaP1363TestGroup(pubkey, md)
    elif self.encoding == "amd_sev":
      if privkey is None:
        raise ValueError("Expecting a private key")
      return EcdsaAmdSevTestGroup(privkey, pubkey, md)
    else:
      raise ValueError("Unsupported encoding:" + self.encoding)

  @util.type_check
  def add(self, key_pair: KeyPair, msg: bytes, sig: bytes, result: str,
          comment: str, flags: list[flag.Flag]) -> None:
    """Adds a test vector.
    
    Args:
      key_pair: The parameters for the test case. This contains the keys, and
          hash function
      msg: the message that was signed
      sig: the encoded signature
      result: the expected result ("valid", "invalid" or "acceptable")
      comment: a comment for the signature
      flags: flags describing the test case.
    """
    flags = self.add_flags(flags)
    privkey = key_pair.priv
    pubkey = key_pair.pub
    md = self.md
    keyid = pubkey.encode_hex() + ":" + md
    if keyid not in self.test.testgroups:
      self.test.add_group(keyid, self.new_testgroup(privkey, pubkey))
    group = self.test.testgroups[keyid]
    if flags is None:
      flags = []
    tc = group.vectortype(msg = msg,
                          sig = sig,
                          comment = comment,
                          result = result,
                          flags = flags)
    group.add_test(tc)

  @util.type_check
  def add_sig_priv(self,
                   priv: ec_key.EcPrivateKey,
                   msg: bytes,
                   r: Any,
                   s: Any,
                   validity: str,
                   comment: str,
                   *,
                   flags: Optional[list[flag.Flag]] = None,
                   normalize: bool = True):
    self.add_sig(KeyPair(priv), msg, r, s, validity, comment, flags=flags)

  @util.type_check
  def add_sig(self,
              key_pair: KeyPair,
              msg: bytes,
              r: Any,
              s: Any,
              validity: str,
              comment: str,
              *,
              flags: Optional[list[flag.Flag]] = None,
              normalize: bool = True):
    """Adds a signature to the set of test vectors.

    Args:
      key_pair: a key pair, may contain a private key or just a public key
      msg: the message that was signed
      r: the value r of the signature. This is an integer if the signature
        is valid. But some encodings such as ASN allow other data types to be
        encoded. For example DSA in pycrypto accepts the signature [1, 0.5]
        for any message. If the encoding cannot encode the value r then the
        signature is simply skipped.
      s: the value s of the signature. This is typically an integer (see r).
      validity: one of "valid", "invalid", "acceptable".
      comment: a short description of the test vector
      flags: a list of flags
      normalize: determines whether the value s should be normalized. E.g.,
        for bitcoin only one of the values s or n-s is valid."""
    group = self.group
    md = self.md
    if flags is None:
      flags = []
    if self.encoding == "webcrypto" or self.encoding == "p1363":
      if not isinstance(r, int) or not isinstance(s, int):
        return
      if r < 0 or s < 0: return
      if max(r, s) > group.n:
        sig = p1363_sig(r, s, max(r, s))
        self.add(key_pair, msg, sig, validity, comment, flags)
      else:
        sig = p1363_sig(r, s, group.n)
        self.add(key_pair, msg, sig, validity, comment, flags)
        if validity == "valid" and max(r, s) < group.n // 256:
          # TODO: So far I can't find a reference that requires a
          #   length check for ECDSA signatures in P1363 format. The signature
          #   generation is well defined, but the signature verification
          #   unfortunatly isn't:
          #   https://perso.telecom-paristech.fr/guilley/recherche/cryptoprocesseurs/ieee/00891000.pdf
          #   Section 7.2.7 describes ECDSA. The result is simply the pair (r,s)
          #   Section 10.2.3 Signature verification operation describes the
          #   verification. It assumes that the integer pair (r, s) is already
          #   known.
          #
          #   RFC 7515: The JWS signature is the byte array R || S, where R, S
          #   are bigendian representations of r and s. The standard talks
          #   about the representation base64url (JWS Signature).
          #   Examples given in the standard implicitely assume that signatures
          #   have the correct length. It does not talk about verifying the
          #   length.
          #
          #   CVE: There are some CVEs about signature malleability. None
          #   (as far as I know) talks about P1363 signatures.
          #   Example: CVE-2020-13822  (which is a circular reference).
          #
          #   BUGS:
          #   https://bugs.openjdk.org/browse/JDK-8236145 (just the
          #   documentation is wrong).
          sig = p1363_sig(r, s, max(r, s))
          flag_size = flag.Flag(
              label="SignatureSize",
              bug_type=flag.BugType.LEGACY,
              description="This test vector contains valid values for r and s. "
              "But the values are encoded using a smaller number of bytes. "
              "The size of an IEEE P1363 encoded signature should "
              "always be twice the number of bytes of the size of the order. "
              "Some libraries accept signatures with less bytes. "
              "To our knowledge no standard (i.e., IEEE P1363 or RFC 7515) "
              "requires any explicit checks of the signature size during "
              "signature verification.")
          self.add(key_pair, msg, sig, "invalid", "incorrect size of signature",
                   flags + [flag_size])
    elif self.encoding == "asn":
      sig = asn.encode([r, s])
      self.add(key_pair, msg, sig, validity, comment, flags)
    elif self.encoding == "bitcoin":
      if normalize:
        s = self.normalize_s(s)
      sig = asn.encode([r, s])
      self.add(key_pair, msg, sig, validity, comment, flags)
    elif self.encoding == "amd_sev":
      if not isinstance(r, int) or not isinstance(s, int):
        return
      sig = amd_sev_ec.ecdsa_sig(r, s, allow_invalid=True)
      self.add(key_pair, msg, sig, validity, comment, flags)
    else:
      raise Exception("Encoding not implemented:" + self.encoding)

  def generate_alternative(self, key_pair: KeyPair, msg: bytes, r: int, s: int):
    """Ecdsa signatures are slightly malleable"""
    n = self.group.n
    if self.encoding == "bitcoin":
      bitcoin_sig_malleability_flag = flag.Flag(
          label="SignatureMalleabilityBitcoin",
          bug_type=flag.BugType.SIGNATURE_MALLEABILITY,
          description="\"BitCoins\"-curves are curves where signature "
          "malleability can be a serious issue. An implementation should "
          "only accept a signature s where s < n/2. If an implementation "
          "is not meant for uses cases that require signature malleability "
          "then this implemenation should be tested with another set of "
          "test vectors.",
          effect="In bitcoin exchanges, it may be used to make a double "
          "deposits or double withdrawals",
          links=[
              "https://en.bitcoin.it/wiki/Transaction_malleability",
              "https://en.bitcoinwiki.org/wiki/Transaction_Malleability"
          ],
      )
      s = n - self.normalize_s(s)
      self.add_sig(
          key_pair,
          msg,
          r,
          s,
          "invalid",
          "Signature malleability",
          flags=[bitcoin_sig_malleability_flag],
          normalize=False)
    else:
      self.add_sig(
          key_pair,
          msg,
          r,
          n - s,
          "valid",
          "signature malleability",
          flags=[valid_signature])

  def generate_legacy_asn(self, key_pair: KeyPair, msg: bytes, r: int, s: int):
    missing_zero_flag = flag.Flag(
        label="MissingZero",
        bug_type=flag.BugType.LEGACY,
        description="Some implementations of ECDSA and DSA incorrectly "
        "encode r and s by not including leading zeros in the ASN encoding of "
        "integers when necessary. Hence, some implementations (e.g. jdk) "
        "allow signatures with incorrect ASN encodings assuming that the "
        "signature is otherwise valid.",
        effect="While signatures are more malleable if such signatures are "
        "accepted, this typically leads to no vulnerability, since a badly "
        "encoded signature can be reencoded correctly.",
    )
    def twosComplement(x):
      b = x.bit_length()
      if b % 8 == 0:
        yield x - (1 << b)
    for cr in twosComplement(r):
      sig = asn.encode([cr, s])
      self.add(key_pair, msg, sig, "invalid",
               "Legacy: ASN encoding of r misses leading 0",
               [missing_zero_flag])
    for cs in twosComplement(s):
      sig = asn.encode([r, cs])
      self.add(key_pair, msg, sig, "invalid",
               "Legacy: ASN encoding of s misses leading 0",
               [missing_zero_flag])


  @util.type_check
  def generate_pseudorandom(self,
                            priv: ec_key.EcPrivateKey,
                            msg: bytes,
                            cnt: Optional[int] = None,
                            comment: Optional[str] = None,
                            valid: Optional[str] = None,
                            salt: bytes = b";lk32oilkwjr",
                            flags: Optional[list[flag.Flag]] = None):
    if cnt is None:
      cnt = 1
    if comment is None:
      comment = "pseudorandom signature"
    if valid is None:
      valid = "valid"
    for i in range(cnt):
      r, s = self.sign_deterministic(priv, msg,
                                     salt + str(i).encode("ascii"))
      self.add_sig_priv(priv, msg, r, s, valid, comment, flags=flags)

  def generate_pseudorandom_signatures(self,
                                       msg: bytes,
                                       cnt: int = 1,
                                       seed: bytes = b"1bqweq214",
                                       privkey: Optional[int] = None,
                                       comment: Optional[str] = None,
                                       flags: Optional[list[flag.Flag]] = None):
    group = self.group
    if privkey is None:
      privkey = prand.randrange(1, group.n, seed=seed, label=group.name)
    priv = ec_key.EcPrivateKey(group, privkey)
    self.generate_pseudorandom(
        priv, msg, cnt, salt=seed, comment=comment, flags=flags)

  def generate_legacy_signatures(self,
                                 msg: bytes,
                                 cnt: int = 1):
    """Generates signatures where the hash function is weaker than the EC group.

    Args:
      group: the EC group
      msg: the message to sign
      md: the hash function to use
      cnt: the number of signatures to generate
    """
    flag_weakhash = flag.Flag(
        label="WeakHash",
        bug_type=flag.BugType.WEAK_PARAMS,
        description="The security strength of the hash function used in this "
        "signature is weaker than the strength of the EC parameters. Such "
        "choices are disallowed in FIPS PUB 186-4 Section 6.1.1. Some "
        "libraries reject such parameter choices, while other libraries "
        "allow them, leaving it to the user to select the EC parameters.",
    )
    s = prand.randrange(1, self.group.n, seed="12lk3j123", label=group.name)
    priv = ec_key.EcPrivateKey(group, s)
    self.generate_pseudorandom(
        priv,
        msg,
        cnt,
        comment="Hash weaker than DL-group",
        valid="valid",
        flags=[flag_weakhash])

  def generate_edge_case_hash(self,
                              priv: ec_key.EcPrivateKey,
                              seed: bytes = b"123kjl124l2"):
    """Generates pseudorandom signatures where hash(msg) is a special case."""
    if self.msgbuilder:
      # TODO: find edge case values using msgbuilder.
      return
    # TODO: Maybe also choose special case values for (r * priv.s) to
    #   check for overflows in (h + r * priv.s)
    flag_special_hash = flag.Flag(
        label="SpecialCaseHash",
        bug_type=flag.BugType.EDGE_CASE,
        description="The test vector contains a signature where the hash of "
        "the message is a special case, e.g., contains a long run of 0 or 1 "
        "bits.")
    for msg in special_values.edge_case_msg_for_hash(self.md):
      if isinstance(msg, str):
        msg = bytes(msg, "ascii")
      if not self.msgs or msg in self.msgs:
        self.generate_pseudorandom(
            priv,
            msg,
            salt=seed,
            comment="special case hash",
            flags=[flag_special_hash])

  def generate_modified_asn(self, key_pair: KeyPair, msg: bytes, r: int,
                            s: int):
    """Generates signatures with modified ASN.
    
    It is somewhat unclear whether signatures that are BER but
    not DER encoded should be valid, acceptable or invalid:
      CVE-2020-14966:    Node.js (probably includes invalid encodings)
      CVE-2020-13822:    leading 0 bytes, integer overflows
      CVE-2019-14859:    python-ecdsa, NIST base score 9.1 is suspect
      CVE-2016-1000342:  bouncy castle
    Based on these CVEs, we think that signature malleability should
    be reduced to a minimum. Hence test vectors with valid BER encoded
    signatures are considered to be invalid. 
 
    Args:
      key_pair: key and curve
      msg: the message that is signed
      r: the value r of a correct signature
      s: the value s of a correct signature
    """
    ber_flag = flag.Flag(
        label="BerEncodedSignature",
        bug_type=flag.BugType.BER_ENCODING,
        description="ECDSA signatures are usually DER encoded. "
        "This signature contains valid values for r and s, but it "
        "uses alternative BER encoding.",
        effect="Accepting alternative BER encodings may be benign in some "
        "cases, or be an issue if protocol requires signature malleability.",
        cves=[
            "CVE-2020-14966",  # Node.js (probably includes invalid encodings)
            "CVE-2020-13822",  # leading 0 bytes, integer overflows
            "CVE-2019-14859",  # python-ecdsa, NIST base score 9.1 is suspect
            "CVE-2016-1000342",  # bouncy castle
        ])
    modified_signature_flag = flag.Flag(
        label="ModifiedSignature",
        bug_type=flag.BugType.CAN_OF_WORMS,
        description="The test vector contains an invalid signature that was "
        "generated from a valid signature by modifying it.",
        effect="Without further analysis it is unclear if the modification "
        "can be used to forge signatures.")
    invalid_encoding_flag = flag.Flag(
        label="InvalidEncoding",
        bug_type=flag.BugType.CAN_OF_WORMS,
        description="ECDSA signatures are encoded using ASN.1. "
        "This test vector contains an incorrectly encoded signature. "
        "The test vector itself was generated from a valid signature by "
        "modifying its encoding.",
        effect="Without further analysis it is unclear if the modification "
        "can be used to forge signatures.")

    sig_raw = [r, s]
    sig_struct = asn.Named(
        "sequence [r, s]",
        [asn.Named("r", r), asn.Named("s", s)])
    for bugtype, encoding in asn_fuzzing.generate(sig_struct):
      # sanity check: now all encodings must be of type bytes
      assert isinstance(encoding, bytes)
      if bugtype is None:
        result = "valid"
        bugtype = "valid"
        flags = [valid_signature]
      else:
        result = "invalid"
        # Sets flags depending on the modification. The following
        # cases that are distinguised:
        #  - valid signature with BER encoding
        #  - modified signature with BER encoding
        #  - invalid encoding
        try:
          val2 = asn_parser.parse(encoding)
          if val2 == sig_raw:
            flags = [ber_flag]
          else:
            flags = [modified_signature_flag]
        except Exception as ex:
          flags = [invalid_encoding_flag]
      self.add(key_pair, msg, encoding, result, bugtype, flags)

  def generate_modified_rs(self, key_pair: KeyPair, msg: bytes, r: int, s: int):
    """Generates signatures with modified values for r and s.

    An ECDSA signature is only valid if 0 < r < n and 0 < s < n.
    This method generates invalid signatures that might get accepted if
    the range check is omitted.

    Args:
      key_pair: a key pair (private key may be None)
      msg: the message to sign
      r: the r value of a valid signature for msg
      s: the s value of a valid signature for msg
    """

    range_check_flag = flag.Flag(
        label="RangeCheck",
        bug_type=flag.BugType.CAN_OF_WORMS,
        description="The test vector contains an r and s that has been "
        "modified. By adding or subtracting the order of the group (or "
        "other values) the test vector checks whether signature "
        "verification verifies the range of r and s.",
        effect="Without further analysis it is unclear if the modification "
        "can be used to forge signatures.")
    modified_int_flag = flag.Flag(
        label="ModifiedInteger",
        bug_type=flag.BugType.CAN_OF_WORMS,
        description="The test vector contains an r and s that has been "
        "modified. The goal is to check for arithmetic errors.",
        effect="Without further analysis it is unclear if the modification "
        "can be used to forge signatures.")
    integer_overflow_flag = flag.Flag(
        label="IntegerOverflow",
        bug_type=flag.BugType.CAN_OF_WORMS,
        description="The test vector contains an r and s that has been "
        "modified, so that the original value is restored if the "
        "implementation ignores the most significant bits.",
        effect="Without further analysis it is unclear if the modification "
        "can be used to forge signatures.")

    n = self.group.n
    bits = n.bit_length()
    for cflag, val, desc in [
        (range_check_flag, r + n, "r + n"),
        (range_check_flag, r - n, "r - n"),
        (range_check_flag, r + 256 * n, "r + 256 * n"),
        (modified_int_flag, -r, "-r"),
        (modified_int_flag, n - r, "n - r"),
        (modified_int_flag, -n - r, "-n - r"),
        (integer_overflow_flag, r + 2**bits, f"r + 2**{bits}"),
        (integer_overflow_flag, r - 2**bits, f"r - 2**{bits}"),
        (integer_overflow_flag, r + 2**(64 + bits), f"r + 2**{64 + bits}"),
    ]:
      self.add_sig(
          key_pair,
          msg,
          val,
          s,
          "invalid",
          comment=f"replaced r by {desc}",
          flags=[cflag],
          normalize=False)
    for cflag, val, desc in [
        (range_check_flag, s + n, "s + n"),
        (range_check_flag, s - n, "s - n"),
        (range_check_flag, s + 256 * n, "s + 256 * n"),
        (modified_int_flag, -s, "-s"),
        (modified_int_flag, -n - s, "-n - s"),
        (integer_overflow_flag, s + 2**bits, f"s + 2**{bits}"),
        (integer_overflow_flag, s - 2**bits, f"s - 2**{bits}"),
        (integer_overflow_flag, s + 2**(64 + bits), f"s + 2**{64 + bits}"),
    ]:
      self.add_sig(
          key_pair,
          msg,
          val,
          s,
          "invalid",
          comment=f"replaced s by {desc}",
          flags=[cflag],
          normalize=False)

  def generate_fake_sigs(self, key_pair: KeyPair, msg: bytes):
    """Generates edge case signatures with unusual values for r and s.

    This method tries silly edge cases such as r=0 and s=0. Careless coding
    such as returning 0 for the modular inverse of 0 could allow forgeries
    with such values.

    Args:
      key_pair: contains keys, EC group and hash function
      msg: the message to sign
    """
    invalid_sig_flag = flag.Flag(
        label="InvalidSignature",
        bug_type=flag.BugType.AUTH_BYPASS,
        description="The signature contains special case values such as r=0 "
        "and s=0. Buggy implementations may accept such values, if the "
        "implementation does not check boundaries and computes s^(-1) == 0.",
        effect="Accepting such signatures can have the effect that an "
        "adversary can forge signatures without even knowning the message "
        "to sign.",
        cves=[
            "CVE-2022-21449",  # psychic signatures
            "CVE-2021-43572",  # Stark Bank Crypto
            "CVE-2022-24884",  # ecdsautils
        ],
    )
    n = self.group.n
    p = self.group.field_size()
    vals = [
        (0, "0"),
        (1, "1"),
        (-1, "-1"),
        (n, "n"),
        (n - 1, "n - 1"),
        (n + 1, "n + 1"),
        (p, "p"),
        (p + 1, "p + 1"),
    ]
    for r, rtxt in vals:
      for s, stxt in vals:
        self.add_sig(
            key_pair,
            msg,
            r,
            s,
            "invalid",
            f"Signature with special case values r={rtxt} and s={stxt}",
            flags=[invalid_sig_flag],
            normalize=False)
    invalid_types_flag = flag.Flag(
        label="InvalidTypesInSignature",
        bug_type=flag.BugType.AUTH_BYPASS,
        description="The signature contains invalid types. "
        "Dynamic typed languages sometime coerce such values of different "
        "types into integers. If an implementation is careless and has "
        "additional bugs, such as not checking integer boundaries then "
        "it may be possible that such signatures are accepted.",
        effect="Accepting such signatures can have the effect that an "
        "adversary can forge signatures without even knowning the message "
        "to sign.",
        cves=[
            "CVE-2022-21449",  # psychic signatures
        ],
    )
    comment = "Signature encoding contains wrong types."
    smallSet = [
        (0, "0"),
        (1, "1"),
        (-1, "-1"),
        (n, "n"),
        (p, "p"),
    ]
    wrong_types = [
        (0.25, "0.25"),
        (float("nan"), "nan"),
        (True, "True"),
        (False, "False"),
        (asn.Null(), "Null"),
        (asn.Utf8String(""), "empyt UTF-8 string"),
        (asn.Utf8String("0"), '"0"'),
        ([], "empty list"),
        ([0], "list containing 0"),
    ]
    for r, rtxt in smallSet:
      for s, stxt in wrong_types:
        self.add_sig(
            key_pair,
            msg,
            r,
            s,
            "invalid",
            f"Signature encoding contains incorrect types: r={rtxt}, s={stxt}",
            flags=[invalid_types_flag],
            normalize=False)

    for x, xtxt in wrong_types:
      self.add_sig(
          key_pair,
          msg,
          x,
          x,
          "invalid",
          f"Signature encoding contains incorrect types: r={xtxt}, s={xtxt}",
          flags=[invalid_types_flag],
          normalize=False)

    for r, rtxt in wrong_types:
      self.add_sig(
          key_pair,
          msg,
          r,
          0,
          "invalid",
          f"Signature encoding contains incorrect types: r={rtxt}, s=0",
          flags=[invalid_types_flag],
          normalize=False)

  def normalize_s(self, s: int):
    """Returns the normalized value of s.

    ECDSA signatures are malleable. If (r, s) is a valid signature then
    (r, n-s) is also a valid signature. This is known as signature
    malleability. Typically this kind of malleability is not a big concern.
    However, some protocols require that a signature is not malleable.
    E.g., some bitcoin protocols depend on this property. To make ECDSA
    signature non-malleable it is sometimes required that only one of
    the choices s or n-s is valid. For example some bitcoint applications
    only accept signatures where s < n/2. This means that
    the value s needs to be normalized before used in a signature.

    Args:
      s: the integer to normalize

    Returns:
      the normalized integer.
    """
    if self.encoding == "bitcoin":
      return min(s, self.group.n - s)
    else:
      return s

  def generate_edge_case_shamir_mult(self, priv: ec_key.EcPrivateKey):
    """Constructs a signature, so that an intermediate point
       is the point at infinity if the signature verification
       uses Shamir multiplication."""
    group = self.group
    n = group.n
    pub = priv.public()
    md = self.md
    mod = 2 ** 8
    w1, w2 = 3, 5
    k = (w1 + w2 * priv.s) % n
    kinv = pow(k, -1, n)
    gk = k * group.generator()
    r = int(gk.affine_x()) % n
    i = 0
    while True:
      if self.msgbuilder:
        if i == 0:
          msg = self.msgbuilder(pub, md)
        else:
          break
      elif not self.msgs:
        msg = bytes(str(i+1), "ascii")
      elif i < len(self.msgs):
        msg = self.msgs[i]
      else:
        break
      i += 1
      e = self.hash_message(msg)
      s = kinv * (e + r * priv.s) % n
      if s != self.normalize_s(s):
        continue
      sinv = pow(s, -1, n)
      u1 = e * sinv % n
      u2 = r * sinv % n
      # bug_type = EDGE_CASE
      if u1 % mod == w1 and u2 % mod == w2:
        edge_case_shamir = flag.Flag(
            label="EdgeCaseShamirMultiplication",
            bug_type=flag.BugType.EDGE_CASE,
            description="Shamir proposed a fast method for computing "
            "the sum of two scalar multiplications efficiently. "
            "This test vector has been constructed so that "
            "an intermediate result is the point at infinity if "
            "Shamir's method is used.")
        self.add_sig_priv(
            priv,
            msg,
            r,
            s,
            "valid",
            "Edge case for Shamir multiplication",
            flags=[edge_case_shamir])
        break

  @util.type_check
  def gen_signature(self, pub_point: ec.EcPoint,
                      message: bytes,
                      r: int,
                      s: int,
                      comment: str,
                      is_valid: Optional[bool] = None,
                      flags: Optional[list[flag.Flag]] = None,
                      normalize: bool = True):
    group = self.group
    digest = util.hash(self.md, message)
    valid = verify_digest(self.group, pub_point, r, s, digest)
    if not normalize and 2*s > group.n and self.encoding=="bitcoin":
      valid = False
    assert is_valid in (None, valid)
    cat = ["invalid", "valid"][valid]
    pub = ec_key.EcPublicKey(group, pub_point.affine())
    key_pair = KeyPair(pubkey=pub)
    self.add_sig(
        key_pair,
        message,
        r,
        s,
        cat,
        comment,
        flags=flags,
        normalize=normalize)

  @util.type_check
  def generate_signature(self, pt: ec.EcPoint,
                           message: bytes,
                           r: int,
                           s: int,
                           comment: str,
                           *,
                           flags: Optional[list[flag.Flag]] = None,
                           normalize: bool = True):
    """Generates for a given intermediate point.

      This function generates a test case where pt = (e*w) * G + (r*w) * y,
      where y is the point of the public key. Since r and s are fixed, the test
      vectors are generated by finding a corresponding public key.

      Args:
        pt: the intermediate point
        r: first part of the signature
        s: second part fo the signature
        comment: describes pt
        normalize: determines if the signature should be normalized.
      """
    flag_last_addition = flag.Flag(
      label="PointAddition",
      bug_type=flag.BugType.EDGE_CASE,
      description="Some implementations of ECDSA do not handle duplication "
      "and points at infinity correctly. This test vector has been crafted "
      "so that the the computation of the point R is a special case.",
      cves=["CVE-2020-12607"])
    flag_arithmetic_error = flag.Flag(
      label="ArithmeticError",
      bug_type=flag.BugType.EDGE_CASE,
      description="Some implementations of ECDSA have arithmetic errors "
      "that occur when intermediate results have extreme values. "
      "This test vector has been constructed to test such occurences.",
      cves=["CVE-2017-18146"])
    group = self.group
    md = self.md
    e = self.hash_message(message)
    if flags is None:
      flags = []
    n = group.n
    assert r % n != 0
    v = pow(r, -1, n)
    if s % n == 0:
      w = 1
      u2inv = v
    else:
      w = pow(s, -1, n)
      u2inv = v * s % n
    u1 = e * w % n
    u1g = u1 * group.generator()
    u2y = pt - u1g
    pub_point = u2y * u2inv
    is_valid = (0 < r < n and 0 < s < n and bool(pt) and
                int(pt.affine_x()) % n == r)
    # assert not is_valid or pt == u1g + (r * w % n) * Y
    if not normalize and 2 * s > n and self.encoding=="bitcoin":
      is_valid = False
    # The signatures generated in this method mainly check for arithmetic
    # errors. For test vectors that can trigger a duplication bug such
    # as CVE-2015-2730, we add a comment.
    if is_valid and (u1g == u2y or u1g == -u2y or not u1g or not u2y):
      flags = flags + [flag_last_addition]
    else:
      flags = flags + [flag_arithmetic_error]
    self.gen_signature(
        pub_point,
        message,
        r,
        s,
        comment,
        is_valid,
        flags=flags,
        normalize=normalize)

  def generate_edge_case_signatures(self, message: bytes):
    """Generates edge case signatures.

    This method generates signatures that trigger an edge case during
    signature verification. Such edge cases are for example, encountering
    the point at infinity, adding two points of equal value, small or special
    case integers that could trigger arithmetic overflows. Such edge cases
    typically are constructed by selecting the public key depending on the
    values of the signature. This unfortunately prevents generating such
    edge cases for the self signed signatures used to test implementations
    of AMD_SEV.

    Args:
      group: the EC group used for the signature
      message: the message to sign
      md: the name of the hash function to use.
    """

    group = self.group
    # This function is skipped if h is large.
    # In particular this only happens for binary curves that are unimportant.
    if group.h > 4:
      return

    md = self.md

    flag_duplication = flag.Flag(
        label="PointDuplication",
        bug_type=flag.BugType.EDGE_CASE,
        description="Some implementations of ECDSA do not handle duplication "
        "and points at infinity correctly. This is a test vector "
        "that has been specially crafted to check for such an omission.",
        cves=["2020-12607", "CVE-2015-2730"])
    flag_small_rs = flag.Flag(
        label="SmallRandS",
        bug_type=flag.BugType.EDGE_CASE,
        description="The test vectors contains a signature where both r and s "
        "are small integers. Some libraries cannot verify such signatures.",
        effect="While the signature in this test vector is constructed and "
        "similar cases are unlikely to occur, it is important to determine "
        "if the underlying arithmetic error can be used to forge signatures.",
        cves=["2020-13895"])
    flag_modular_inverse = flag.Flag(
        label="ModularInverse",
        bug_type=flag.BugType.EDGE_CASE,
        description="The test vectors contains a signature where computing "
        "the modular inverse of s hits an edge case.",
        effect="While the signature in this test vector is constructed and "
        "similar cases are unlikely to occur, it is important to determine "
        "if the underlying arithmetic error can be used to forge signatures.",
        cves=["CVE-2019-0865"])
    e = self.hash_message(message)
    n = group.n
    p = group.field_size()

    s = n - 3
    x, pt = self.next_point_from_x(p - 1, -1)
    self.generate_signature(pt, message, x % n, s, "k*G has a large x-coordinate")
    # This gives the same public key as the group before and could be merged.
    self.generate_signature(pt, message, x, s, "r too large")

    r, pt = self.next_point_from_x(n - 1, -1)
    self.generate_signature(pt, message, r, r - 1, "r,s are large")

    r, pt = self.next_point_from_x(2**(n.bit_length() - 1) - 1, -1)
    for t in [r, r-1]:
      s = pow(t, -1, n)
      self.generate_signature(pt, message, r, s, "r and s^-1 have a large Hamming weight")

    # Test vectors where r and s, or s^-1 are small.
    # SunEC fails over NIST-P224 for several of the test vectors.
    # uECC fails for r=5, s=3.
    # CVE-2020-13895 Perl ECDSA fails for small r and s and s == 1
    # CVE-2020-12607 signature verification fails for extreme k and s^-1
    r = 0
    for _ in range(2):
      r, pt = self.next_point_from_x(r + 1)
      for s in sorted({1, 3, r, r + 1}):
        self.generate_signature(pt, message, r, s, "small r and s", flags=[flag_small_rs])

    self.generate_signature(pt, message, r + n, s, "r is larger than n")
    self.generate_signature(pt, message, r, 1234567 + n, "s is larger than n")
    r, pt = self.next_point_from_x(256)
    self.generate_signature(pt, message, r, pow(127, -1, n), "small r and s^-1")
    r, pt = self.next_point_from_x(12837129847132876)
    s = pow(182319823181923141, -1, n)
    self.generate_signature(pt, message, r, s, "smallish r and s^-1")

    # uECC fails for the following test vector
    r, pt = self.next_point_from_x(1283712984713287618231982313211)
    s = pow(257, -1, n)
    self.generate_signature(pt, message, r, s, "100-bit r and small s^-1")

    r, pt = self.next_point_from_x(256)
    s = pow(335576113200219857839687952955, -1, n)
    self.generate_signature(pt, message, r, s, "small r and 100 bit s^-1")

    r, pt = self.next_point_from_x(486861910918697195699085147172)
    s = pow(335576113200219857839687952955, -1, n)
    self.generate_signature(pt, message, r, s, "100-bit r and s^-1")

    r, pt = self.next_point_from_x(n - 128)
    s = pow(n - 3, -1, n)
    self.generate_signature(pt, message, r, s, "r and s^-1 are close to n")

    for r0, s in [
        (11260405065460177229, 9484249322280366187),
        (782237152301174935240475920333, 1252996219030822393373754006666),
        (183898464772630595985352006549717268090,
         176736452780547087482338089615226438847),
        (973002014391743892082692660319135235850587868127,
         1293610153025254189261438125895338053927928184761),
    ]:
      r, pt = self.next_point_from_x(r0)
      size = max(r, s).bit_length()
      self.generate_signature(pt, message, r, s, f"r and s are {size}-bit integer")

    r, pt = self.next_point_from_x(n // 3)
    self.generate_signature(pt, message, r, 1, "s == 1")
    self.generate_signature(pt, message, r, 0, "s == 0")

    for s in special_int.edge_case_inverse(n):
      self.generate_signature(
          pt, message, r, s, "edge case modular inverse", flags=[flag_modular_inverse])

    self.generate_signature(
        group.zero(),
        message,
        n // 2,
        n // 3,
        "point at infinity during verify",
        flags=[flag_duplication])

    # extreme case for signature malleability
    r, pt = self.next_point_from_x(n // 2)
    s = n // 2
    self.generate_signature(
        pt,
        message,
        r,
        s,
        comment="edge case for signature malleability",
        normalize=False)
    self.generate_signature(
        pt,
        message,
        r,
        n - s,
        comment="edge case for signature malleability",
        normalize=False)

    # extreme values for u1 and u2
    r, pt = self.next_point_from_x(n // 3, -1)
    self.generate_signature(pt, message, r, e, "u1 == 1")
    self.generate_signature(pt, message, r, -e % n, "u1 == n - 1")  # uEcc fails for this
    self.generate_signature(pt, message, r, r, "u2 == 1")
    self.generate_signature(pt, message, r, -r % n, "u2 == n - 1")  # uEcc fails for this

    # edge cases for u1 and u2
    uset = {3,
           2**n.bit_length(),
           2**(n.bit_length() - 1),
           2**(n.bit_length() - 1) - 1,
           n - 3,
           n - 2**32,
           n - 2**51,
           n - 2**52,
           n - 2**64,
           }
    for i in range(1,7):
      uset.add(n - 2 * (-n % 2**i))

    r, pt = self.next_point_from_x(2**(n.bit_length() - 1) - 3, -1)
    for u1 in sorted(uset):
      s = e * pow(u1, -1, n) % n
      self.generate_signature(pt, message, r, s, "edge case for u1")

    for u2 in sorted(uset):
      s = r * pow(u2, -1, n) % n
      self.generate_signature(pt, message, r, s, "edge case for u2")

    # Generate some edge cases to check for arithmetic errors.
    # Based on some old libtomcrypt bug: X + (-X) == 2X or X + X == inf
    k = 123456789123456789
    v = k * group.generator()
    r = int(v.affine_x()) % n
    assert r > 0
    x = e * pow(r, -1, n) % n
    pub_pt = x * group.generator()
    s = pow(k, -1, n) * (e + r * x) % n
    self.gen_signature(
        pub_pt,
        message,
        r,
        s,
        "point duplication during verification",
        True,
        flags=[flag_duplication])
    # This generates a signature that would verify if the library has a bug
    # X + (-X) == 2*X
    self.gen_signature(
        -pub_pt,
        message,
        r,
        s,
        "duplication bug",
        False,
        flags=[flag_duplication])

    # If there is a point with x-coordinate 0 on the curve then generate
    # signatures with this point as indermediate result.
    pt = self.point_from_x(0)
    if pt:
      self.generate_signature(pt, message, 1, n // 3, "point with x-coordinate 0")
      self.generate_signature(pt, message, 2**n.bit_length(), n // 5,
                         "point with x-coordinate 0")

    # Generates a signature that might be accepted if x/z == r is implemented
    # as x == r*z
    self.generate_signature(group.zero(), message, n // 3, n // 5,
                       "comparison with point at infinity ")

    # pt and hence k are edgecases.
    # The first case triggered b/74209208.
    # Additional cases are generated just to check if the edgecase s
    # is triggering the problem.
    for pt in [2 * group.generator(), -group.generator()]:
      r = int(pt.affine_x()) % n
      s = n // 3
      self.generate_signature(pt, message, r, s, "extreme value for k and edgecase s")
      for invs in (-7, -5, 5, 7):
        s = pow(invs, -1, n)
        self.generate_signature(pt, message, r, s, "extreme value for k and s^-1")
      s = prand.randrange(1, group.n, "kqjelqkwjrq")
      self.generate_signature(pt, message, r, s, "extreme value for k")

    for pub in (group.generator(), -group.generator()):
      pub = ec_key.EcPublicKey(group, pub.affine())
      key_pair = KeyPair(pubkey=pub)
      for r in (e, -e % n):
        s = n // 7
        self.add_sig(
            key_pair,
            message,
            r,
            s,
            "invalid",
            "public key shares x-coordinate with generator",
            flags=[flag_duplication])

  def generate_known_bugs(self, msg: bytes):
    group = self.group
    # This would only work if ECDSA and ECDH bug in openjdk were the same.
    # They are not.
    # if self.group.name == "secp224r1":
    #   deltas = [2**128 - 2**64]
    #   for d in deltas:
    #     s = group.n * 73 // 123
    #     r, pt = self.next_point_from_x(1)
    #     self.generate_signature(pt, msg, r + d, s, "Checking for jdk bug")


  @util.type_check
  def generate_untruncated_hash(self,
                                priv: ec_key.EcPrivateKey,
                                msg: bytes = b"123400"):
    """Generates signatures where the hash function has not been truncated.

    When the size of the hash digest is longer than the size of the order of the
    field then the hash digest has to be truncated first. Some libraries forget
    to do this truncation. This function adds an (invalid) test vector that
    simulates such a fautly library. No test vectors are generated when
    no truncation is needed.

    Args:
      priv: the private key
      msg: the message to sign
    """
    group = self.group
    n = group.n
    md = self.md
    hash_len = util.digest_size(md) * 8
    if n.bit_length() >= hash_len:
      # Nothing to do
      return
    digest = util.hash(md, msg)
    h = int.from_bytes(digest, "big")

    salt = b"1lk3123"
    label = digest.hex().encode("ascii") + salt
    k = prand.randrange(1, group.n, str(priv.s), label)
    v = k * group.generator()
    r = int(v.affine_x()) % group.n
    if r == 0:
      return
    s = pow(k, -1, group.n) * (h + r * priv.s) % group.n
    if s == 0:
      return
    untruncated_hash = flag.Flag(
        label="Untruncatedhash",
        bug_type=flag.BugType.MISSING_STEP,
        description="If the size of the digest is longer than the size of "
        "the underlying order of the multiplicative subgroup then the hash "
        "digest must be truncated during signature generation and verification. "
        "This test vector contains a signature where this step has been "
        "omitted.")
    self.add_sig_priv(
        priv,
        msg,
        r,
        s,
        "invalid",
        "Signature generated without truncating the hash",
        flags=[untruncated_hash])

  @util.type_check
  def generate_long_test(
      self,
      msg: Optional[bytes],
  ):
    group = self.group
    md = self.md
    key = prand.randrange(1, group.n, "p98i21ukajhfa")
    key_pair = make_key_pair(group, key)
    priv = key_pair.priv
    pub = key_pair.pub
    if self.msgbuilder:
      if msg:
        raise Exception("Expecting empty |msg| with non empty |msgbuilder|")
      msg = self.msgbuilder(pub, md)
    r, s = self.sign_deterministic(priv, msg)
    s = self.normalize_s(s)
    self.generate_alternative(key_pair, msg, r, s)
    if self.encoding == "asn" :
      self.generate_legacy_asn(key_pair, msg, r, s)
      self.generate_modified_asn(key_pair, msg, r, s)
    if self.encoding == "bitcoin" :
      self.generate_modified_asn(key_pair, msg, r, s)
    self.generate_modified_rs(key_pair, msg, r, s)
    self.generate_fake_sigs(key_pair, msg)
    self.generate_edge_case_shamir_mult(priv)
    self.generate_edge_case_hash(priv)
    self.generate_untruncated_hash(priv, msg)
    self.generate_known_bugs(msg)

  @util.type_check
  def generate_edge_case_public_keys(self, message: Optional[bytes] = None):
    groups = [self.group]
    for group, privkey, comment, flags in special_values_ec.edge_case_ec_keys(groups):
      priv = ec_key.EcPrivateKey(group, privkey)
      if message is not None:
        msg = message
      elif self.msgbuilder:
        pub = priv.public()
        msg = self.msgbuilder(pub, self.md)
      else:
        msg = b"Message"
      self.generate_pseudorandom_signatures(
          msg, cnt=3, privkey=privkey, comment=comment, flags=flags)


def gen_asn_signatures(namespace):
  named_curve = namespace.curve
  md = namespace.sha
  encoding = namespace.encoding
  msgs = get_msgs(namespace)
  messages = msgs or default_messages()
  msg0, msg1, msg2, msg3 = select_messages(
      msgs, [b"123400", b"Test", b"Msg", b"Message"])
  if encoding == "bitcoin":
    if not named_curve:
      named_curve = "secp256k1"
    elif named_curve != "secp256k1":
      raise ValueError("bitcoin encoding cannot use curve:" + named_curve)
    if not md:
      md = "SHA-256"
    elif md != "SHA-256":
      raise ValueError("bitcoin encoding cannot use md:" + md)

  if named_curve:
    group = ec_groups.named_curve(named_curve)
  else:
    raise ValueError("No curve specified")

  if not md:
    raise ValueError("No hash function specified")

  tv = EcdsaTestGenerator(group=group, md=md, encoding=encoding, msgs=msgs)
  for message in messages:
    tv.generate_pseudorandom_signatures(message, flags=[valid_signature])
    tv.generate_long_test(msg0)
    tv.generate_edge_case_signatures(msg0)
    tv.generate_edge_case_public_keys(msg3)
  return tv.test


def gen_bitcoin_signatures(namespace):
  named_curve = namespace.curve
  md = namespace.sha
  msgs = get_msgs(namespace)
  messages = msgs or default_messages()
  msg0, msg1 = select_messages(msgs, [b"123400", None])
  if not named_curve:
    named_curve = "secp256k1"
  elif named_curve != "secp256k1":
    raise ValueError("bitcoin encoding cannot use curve:" + named_curve)
  if not md:
    md = "SHA-256"
  elif md != "SHA-256":
    raise ValueError("bitcoin encoding cannot use md:" + md)

  group = ec_groups.named_curve(named_curve)
  tv = EcdsaTestGenerator(group=group, md=md, encoding="bitcoin", msgs=msgs)

  tv.generate_long_test(msg0)
  tv.generate_edge_case_signatures(msg0)
  for message in messages:
    tv.generate_pseudorandom_signatures(message, flags=[valid_signature])
  tv.generate_edge_case_public_keys(msg1)
  return tv.test


def gen_p1363_signatures(namespace):
  named_curve = getattr(namespace, "curve", None)
  if not named_curve:
    print(namespace.__dict__)
    raise ValueError("Curve not specified")
  md = namespace.sha
  encoding = namespace.encoding
  msgs = get_msgs(namespace)
  messages = msgs or default_messages()
  msg0, msg1, msg2, msg3 = select_messages(msgs,
      [b"123400", b"Message", b"Test", b"Hello"])
  group = ec_groups.named_curve(named_curve)
  tv = EcdsaTestGenerator(group=group, md=md, encoding=encoding, msgs=msgs)
  tv.generate_long_test(msg0)
  tv.generate_edge_case_signatures(msg0)
  for message in messages:
    tv.generate_pseudorandom_signatures(message, flags=[valid_signature])
  tv.generate_edge_case_public_keys(msg1)
  return tv.test


def get_msgs(namespace) -> Optional[list[bytes]]:
  """Returns a list of message to sign.

  Args:
    namespace: a namespace with the commandline parameters
  Returns:
    a list of messages specified as parameters or None
    if no messages were specified.
  """
  hex_msgs = getattr(namespace, "msgs", None)
  if hex_msgs:
    return [bytes.fromhex(m) for m in hex_msgs]
  else:
    return None

def default_messages():
  return [b"", b"Msg", b"123400", bytes(20)]

def select_messages(msgs: Optional[list[bytes]],
                    defaults: Optional[list[bytes]]):
  if msgs:
    return [msgs[i % len(msgs)] for i in range(len(defaults))]
  else:
    return defaults


def gen_amd_sev_signatures_raw(namespace):

  def self_signed_builder(pub: ec_key.EcPublicKey, md: str) -> bytes:
    """Returns the input of the signature for a certificate.

    The format of a certificate is described in Section C.1.
    The verification of certificates is described in Section C.5"""
    ver = b"\x01\x00\x00\x00"
    api_mj = b"\x00"
    api_mn = b"\x16"
    reserved0 = b"\x00\x00"
    usage = b"\x01\x10\x00\x00" # OCA
    # algo is described in table 114
    if md == "SHA-256":
      algo = b"\02\x00\x00\x00"
    elif md == "SHA-384":
      algo = b"\02\x01\x00\x00"
    else:
      raise Exception("Unsupported md " + md)
    pubkey = amd_sev_ec.encode_ec_public(pub)
    reserved1 = bytes(516)
    return ver + api_mj + api_mn + reserved0 + usage + algo + pubkey + reserved1

  named_curve = namespace.curve
  md = namespace.sha
  encoding = namespace.encoding
  msgs = get_msgs(namespace)
  if named_curve:
    group = ec_groups.named_curve(named_curve)
  else:
    raise ValueError("missing curve")
  tv = EcdsaTestGenerator(
      group=group,
      md=md,
      encoding=encoding,
      msgs=msgs,
      msgbuilder=self_signed_builder)
  tv.generate_long_test(None)
  tv.generate_edge_case_public_keys()
  return tv.test

class EcdsaProducer(producer.Producer):

  def parser(self):
    res = self.default_parser()
    res.add_argument(
        "--curve", type=str, default="", help="the name of the curve")
    res.add_argument("--sha", type=str, choices=[""] + HASHES, default="")
    res.add_argument(
        "--encoding",
        type=str,
        help="Encoding of the signatures",
        choices=SIGNATURE_ENCODINGS,
        default="asn")
    res.add_argument(
        "--msgs",
        type=str,
        nargs="+",
        help="Optional: a list of messages to sign. The messages are"
        " represented in hexadecimal")
    return res

  @util.type_check
  def generate_test_vectors(self, namespace) -> test_vector.Test:
    if namespace.encoding == "asn":
      return gen_asn_signatures(namespace)
    elif namespace.encoding == "bitcoin":
      return gen_bitcoin_signatures(namespace)
    elif namespace.encoding in ("p1363", "webcrypto"):
      return gen_p1363_signatures(namespace)
    elif namespace.encoding == "amd_sev":
      return gen_amd_sev_signatures_raw(namespace)
    else:
      raise ValueError("Unknown encoding:" + namespace.encoding)


# TODO: Maybe keep or replace by
#   EcdsaProducer().main
# DEPRECATED: Use Producer.produce() instead
def main(namespace):
  EcdsaProducer().produce(namespace)


# TODO: This needs to be changed:
#
# class Producer:
#  def default_parser(self) -> Parser:
#    # Change 1: use argparse_flags
#    parser = argparse_flags.ArgumentParser()
#   ...
#   # Change 2: define parse_flags
#   def parse_flags(self, argv):
#     return self.parser().parse_args(argv[1:])
#
# if __name__ == "__main__":
#   # Change 3: use app.run
#   app.run(main, flags_parser=EcdsaProducer().parse_flags)
# Also possible:
#   app.run(EcdsaProducer().produce, flags_parser=EcdsaProducer().parse_flags)
# Also possible:
#   EcdsaProducer().main()

if __name__ == "__main__":
  EcdsaProducer().produce_with_args()
