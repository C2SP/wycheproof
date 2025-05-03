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

import asn
import asn_fuzzing
import asn_parser
import AST
import base64
import hashlib
import producer
import pseudoprimes
import rsa_key
import rsa_pss
import rsa_test_keys
import rsassa_pkcs1
import sys
import sig_test_vector
import test_vector
import flag
import util
from collections.abc import Iterator
from typing import Any, Optional, Union
from util import type_check


# TODO:
# - move most functions into corresponding classes
# - generate test vectors with leading 00
# - generate special case RSA keys (i.e. it is possible to
#   generate RSA keys where half of the leading bits are
#   predetermined. Similarly half of the trailing bits
#   can be fixed. Might be helpful for testing CRT.


Flags = list[flag.Flag]

# ===== Test vector generation =====

# A structure that can be represented as Json
# This is currently just typing.Any, since it is unclear to me how to
# define such a type correctly.
JsonType = Any

# Hash functions supported by RSASSA-PKCS1
HASHES = ["MD5", "SHA-1", "SHA-224", "SHA-256", "SHA-384", "SHA-512",
          "SHA3-224", "SHA3-256", "SHA3-384", "SHA3-512", "SHA-512/224",
          "SHA-512/256"]
@type_check
def padding(message: bytes, md: str, digest:Optional[bytes]=None) -> bytes:
  """Returns the asn encoded padding of a message."""
  return asn.encode(rsassa_pkcs1.asn_padding_struct(message, md, digest))

def _bytelen(n):
  bits = n.bit_length()
  return (bits + 7) // 8

def sign_padding(ba: bytes, key) -> int:
  assert len(ba) == _bytelen(key.n)
  s = int.from_bytes(ba, "big")
  return key.private_exp(s)

@type_check
def make_rsa_sig_from_padding(ba: bytes, key) -> Optional[int]:
  l = _bytelen(key.n)
  padlen = l - len(ba) - 3
  if padlen < 0:
    return None
  p = bytes([0, 1]) + bytes([0xff]) * (l - len(ba) - 3) + bytes([0]) + ba
  return sign_padding(p, key)

@type_check
def make_rsa_sig_with_encryption_padding(ba: bytes, key) -> int:
  l = _bytelen(key.n)
  p = bytes([0, 1]) + bytes([0xff]) * (l - len(ba) - 3) + bytes([0]) + ba
  return sign_padding(p, key)

@type_check
def make_rsa_sig_with_invalid_padding(ba: bytes, key) -> int:
  l = _bytelen(key.n)
  p = bytes([0, 1]) + bytes([0xff]) * (l - len(ba) - 4) + bytes([0xee, 0]) + ba
  return sign_padding(p, key)

@type_check
def make_rsa_sig_with_short_padding(ba: bytes, key) -> int:
  l = _bytelen(key.n)
  p = bytes([0, 0, 1]) + bytes([0xff]) * (l - len(ba) - 4) + bytes([0]) + ba
  return sign_padding(p, key)

@type_check
def make_empty_rsa_sig(key) -> int:
  l =  _bytelen(key.n)
  p = bytes([0, 1] + [0xff] * (l - 2))
  return sign_padding(p, key)

# ===== Fuzzing
@type_check
def generate_paddings(message: bytes,
                      md: str) -> Iterator[tuple[Optional[str], bytes, Flags]]:
  """Generates tuples (desc, padding) for a given message and digest"""
  struct = rsassa_pkcs1.asn_padding_struct(message, md)
  named_struct = rsassa_pkcs1.named_asn_padding_struct(message, md)
  digest = util.hash(md, message)
  # Fuzzing the asn structure
  for desc, pad in asn_fuzzing.generate(named_struct):
    try:
      struct2 = asn_parser.parse(pad)
      if struct2 == struct:
        ber_flag = flag.Flag(
            label="BerEncodedPadding",
            bug_type=flag.BugType.CAN_OF_WORMS,
            description="The padding in a RSA PKCS#1 signature must be DER "
            "encoded. "
            "This signature uses an alternative BER encoded padding.",
            effect="It is unclear if accepting a small number of alternative "
            "BER encodings leads to a vulnerability. This needs to be "
            "analyzed in detail. Libraries that verify RSA signatures by "
            "using an ASN.1 parser are difficult to analyze.",
            cves=["CVE-2006-4339"],
        )
        flags = [ber_flag]
      else:
        modified_padding_flag = flag.Flag(
            label="ModifiedPadding",
            bug_type=flag.BugType.AUTH_BYPASS,
            description="The padding of this test vector has been modified. "
            "RSA PKCS#1 verification must not accept modified paddings. ",
            effect="If the verification of the padding is weak enough so that "
            "arbitrary data can be included in the ASN encoding of the padding "
            "then it may be possible to forge RSA signatures with low public "
            "exponents.",
            cves=["CVE-2006-4339"],
        )
        flags = [modified_padding_flag]
    except Exception as ex:
      invalid_padding_flag = flag.Flag(
          label="InvalidAsnInPadding",
          bug_type=flag.BugType.AUTH_BYPASS,
          description="The signature contains an invalid padding. "
          "RSA PKCS#1 verification must not accept incorrect paddings. ",
          effect="If the verification of the padding is weak enough so that "
          "arbitrary data can be included in the ASN encoding of the padding "
          "then it may be possible to forge RSA signatures with low public "
          "exponents.",
          cves=["CVE-2006-4339"],
      )
      flags = [invalid_padding_flag]
    yield desc, pad, flags

  flag_wrong_hash = flag.Flag(
      label="WrongHash",
      bug_type=flag.BugType.WRONG_PRIMITIVE,
      description="The signature uses an incorrect hash function. "
      "RSA PKCS#1 verification must not accept signatures using "
      "alternative hash functions.",
      effect="The security of the signature scheme is reduced to the "
      "security of the weakest accepted hash function. "
      "Bugs in the verification are difficult to detect.",
  )

  flag_no_hash = flag.Flag(
      label="NoHash",
      bug_type=flag.BugType.AUTH_BYPASS,
      description="The signature uses no hash function. ",
      effect="Collision resistant hash functions are essential for the "
      "security of RSA signatures. Accepting signatures without "
      "proper hashing and padding probably allows signature "
      "forgeries.",
  )

  # Modifying the hash
  for md2 in HASHES:
    if md == md2: continue
    yield (f"The algorithm encoded in the padding is {md2} instead of {md}.",
           padding(message, md2, digest), [flag_wrong_hash])
    yield (f"The message is hashed with {md2} instead of {md}.",
           padding(message, md2), [flag_wrong_hash])
  yield "The message is not hashed.", padding(message, md,
                                              message), [flag_no_hash]
  md_size = util.digest_size(md)
  if md_size > len(message):
    not_hashed = message + bytes(md_size - len(message))
    yield "The message is not hashed.", padding(message, md,
                                                not_hashed), [flag_no_hash]
  if md_size < len(message):
    yield ("The digest is the just the truncated message.",
           padding(message, md, message[:md_size]), [flag_no_hash])


@type_check
def generate_legacy_signatures(
    message: bytes, key, md: str) -> Iterator[tuple[Optional[str], int, Flags]]:
  """Generate legacy signatures.

  Args:
    message: the message to sign
    key: an RSA private key
    md: the hash function (e.g. "SHA-256")

  Yields:
    triples (comment, signature, flags)
  """
  digest = util.hash(md, message)
  oid = asn.oid_from_hash(md)
  # ASN struct with missing NULL
  asn_struct = [[oid], asn.OctetString(digest, description="digest")]
  padding = asn.encode(asn_struct)
  legacy_sig = make_rsa_sig_from_padding(padding, key)
  if legacy_sig is not None:
    flag_missing_null = flag.Flag(
        label="MissingNull",
        bug_type=flag.BugType.LEGACY,
        description="Some legacy implementations of RSA PKCS#1 signatures "
        "did omit a NULL in the ASN encoding. While such signatures are indeed "
        "invalid some libraries are accepting such signatures for "
        "compatibility.",
        effect="Accepting such legacy signatures is not a vulnerability. "
        "However, implementations often use ASN parsing to verify "
        "the signature. Faulty ASN parsing can add vulnerabilities.")
  yield ("Missing NULL in the ASN encoding", legacy_sig, [flag_missing_null])


@type_check
def generate_invalid_signatures(
    message: bytes, key: rsa_key.RsaPrivateKey,
    md: str) -> Iterator[tuple[Optional[str], Union[bytes, int], Flags]]:
  """Generates invalid signatures.
  
  Args:
    message: the message for which invalid signatures are generated.
    key: the private key for which the signatures are generated
    md: the message digest (e.g. "SHA-256")
  
  Yields tuples of the form (comment, signature, flags) where signature
     is either an integer, bytes or hexadecimal.
  """
  for desc, pad, pad_flags in generate_paddings(message, md):
    sig = make_rsa_sig_from_padding(pad, key)
    if sig is not None:
      yield desc, sig, pad_flags

  digest = util.hash(md, message)
  valid_pad = padding(message, md)
  invalid_padding = flag.Flag(
      label="InvalidPadding",
      bug_type=flag.BugType.AUTH_BYPASS,
      description="RSA PKCS#1 signature with invalid padding. "
      "The padding of RSA PKCS #1 signatures is deterministic. "
      "Only signatures with the padding specified in the standard are "
      "valid. Other paddings should be rejected.",
      effect="Signature forgeries may be possible if the RSA signature "
      "verification accepts a large number of alternative paddings.",
      cves=["CVE-2006-4339"],
  )

  # Encryption padding -> Forgery
  sig = make_rsa_sig_with_encryption_padding(valid_pad, key)
  yield ("using PKCS#1 encryption padding: 0002ff...00<asn wrapped hash>", sig,
         [invalid_padding])
  sig = make_rsa_sig_with_encryption_padding(digest, key)
  yield ("using PKCS#1 encryption padding: 0002ff...00<hash>", sig,
         [invalid_padding])
  sig = make_rsa_sig_with_encryption_padding(message, key)
  yield ("using PKCS#1 encryption padding: 0002ff...00<message>", sig,
         [invalid_padding])
  sig = make_rsa_sig_with_encryption_padding(b"", key)
  yield ("using PKCS#1 encryption padding: 0002ff...00", sig, [invalid_padding])
  sig = make_rsa_sig_with_invalid_padding(valid_pad, key)
  yield ("invalid PKCS#1 signature padding: 0001ff...ee00", sig,
         [invalid_padding])
  sig = make_empty_rsa_sig(key)
  yield ("empty padding: 000001ff...ff", sig, [invalid_padding])
  yield ("no padding", message, [invalid_padding])

  # Sloppy padding verification -> can of worms
  flag_short_padding = flag.Flag(
      label="ShortPadding",
      bug_type=flag.BugType.CAN_OF_WORMS,
      description="The signature contains a short PKCS#1 padding. "
      "One cause for accepting such signatures are libraries that "
      "parse the padding without comparing it to the length of the RSA key.",
      effect="The effect of accepting short paddings is unclear. "
      "It is usually necessary to analyze the implementation and determine "
      "the bug that allows signatures with short paddings to be accepted.",
  )
  sig = make_rsa_sig_with_short_padding(valid_pad, key)
  yield ("PKCS#1 padding too short: 000001ff...", sig, [flag_short_padding])


  flag_signature_malleability = flag.Flag(
      label="SignatureMalleability",
      bug_type=flag.BugType.SIGNATURE_MALLEABILITY,
      description="The signature uses a modified encoding. "
      "Each message has exactly one valid RSA PKCS#1 signature.",
      effect="One effect of accepting alternative encodings of a signature "
      "is signature malleability.",
  )
  # out of range -> can of worms, signature malleability
  valid_sig = make_rsa_sig_from_padding(valid_pad, key)
  yield ("the signature is not reduced", valid_sig + key.n,
         [flag_signature_malleability])
  yield ("the signature is not reduced", valid_sig + 256 * key.n,
         [flag_signature_malleability])
  yield ("the signature is 2 bytes too long", key.n << 16,
         [flag_signature_malleability])

  # invalid signature -> forgery
  # Edge case values for the signature.
  # Some libraries crash while trying to verify such values.
  flag_invalid_signature = flag.Flag(
      label="InvalidSignature",
      bug_type=flag.BugType.AUTH_BYPASS,
      description="The signature is an edge case integer. "
      "Edge cases such as a value exactly equal to the modulus "
      "are sometimes mishandled by an implementation. This can lead "
      "to simple forgeries or denial of service attacks through crashes.",
      cves=["CVE-2017-11185"],
  )
  yield "the signature is empty", b"", [flag_invalid_signature]
  yield "the signature has value 0", 0, [flag_invalid_signature]
  yield "the signature has value 1", 1, [flag_invalid_signature]
  yield "the signature has value 2", 2, [flag_invalid_signature]
  yield "the signature has value n-1", key.n - 1, [flag_invalid_signature]
  yield "the signature has value n", key.n, [flag_invalid_signature]
  yield "the signature has value n+1", key.n + 1, [flag_invalid_signature]
  yield ("the signature has value -1", 2**(key.n.bit_length()) - 1,
         [flag_invalid_signature])


def get_key_flags(key, md: str) -> Flags:
  """Returns flags for this key.

  Flags specifically indicated reasons, why a key may be weak
  when used for PKCS #1 signatures.
  """
  key_flags = []
  if key.n.bit_length() < 2048:
    key_flags.append(
        flag.Flag(
            label="SmallModulus",
            bug_type=flag.BugType.WEAK_PARAMS,
            description="The key for this test vector has a modulus of "
            "size < 2048. Standards, e.g., NIST SP 800-57 recommend "
            "against RSA keys smaller than 2048 bits. Thus, libraries "
            "may reject such key sizes.",
            effect=""))
  if md in ("MD2", "MD5", "SHA-1"):
    key_flags.append(
        flag.Flag(
            label="WeakHash",
            bug_type=flag.BugType.WEAK_PARAMS,
            description="The key for this test vector uses a weak hash "
            "function. Hash functions that are not collision resistant "
            "must not be used for RSA signatures. Thus, libraries may "
            "reject such RSA keys.",
            effect=""))
  if key.e <= 2**16:
    key_flags.append(
        flag.Flag(
            label="SmallPublicKey",
            bug_type=flag.BugType.WEAK_PARAMS,
            description="The public key of this test vector has a small public "
            "exponent.For example NIST SP 800-56B rev. 2 requires "
            "that e > 2**16. Thus, libraries may reject RSA keys with "
            "smaller exponents.",
            effect=""))
  return key_flags


class RsassaPkcs1TestGenerator(test_vector.TestGenerator):
  pass

RsassaPkcs1TestVector = sig_test_vector.SignatureTestVector

class RsassaPkcs1Verify(test_vector.TestType):
  """Test vectors of class RsassaPkcs1Verify are intended for checking the
     verification of RSA PKCS #1 v 1.5 signatures.

     RSA signature verification should generally be very strict about
     checking the padding. Because of this most RSA signatures with
     a slightly modified padding have "result" : "invalid". Only a
     small number of RSA signatures implementing legacy behaviour
     (such as a missing NULL in the encoding) have 
     "result" : "acceptable".
  """

class RsassaPkcs1TestGroup(test_vector.TestGroup):
  algorithm = "RSASSA-PKCS1-v1_5"
  testtype = RsassaPkcs1Verify
  vectortype = RsassaPkcs1TestVector
  schema = {
      "publicKey": {
          "type": rsa_key.RsaPublicKey,
          "desc": "the public key",
      },
      "sha": {
          "type": AST.MdName,
          "desc": "the hash function used for the message",
      },
      "keySize": {
          "type": int,
          "desc": "the size of the modulus in bits",
      },
      "publicKeyAsn": {
          "type": AST.Der,
          "desc": "ASN encoding of the sequence [n, e]",
      },
      "publicKeyDer": {
          "type": AST.Der,
          "desc": "ASN encoding of the public key",
      },
      "publicKeyPem": {
          "type": AST.Pem,
          "desc": "Pem encoded public key"
      },
      "publicKeyJwk": {
          "type":
              rsa_key.JwkRsaPublicKey,
          "short":
              "Public key in JWK format",
          "desc":
              """The public key in JWK format. The key is missing
                   if the signature algorithm for the given hash is not
                   defined.""",
          "ref":
              "RFC 7517",
          "since":
              "0.7",
          "optional":
              True,
      },
  }

  def __init__(self, key, md, footnotes):
    super().__init__()
    self.key = key
    self.md = md
    self.signer = rsassa_pkcs1.RsassaPkcs1(key, md)
    self.footnotes = footnotes
    self.key_flags = self.add_flags(get_key_flags(key, md))

  @util.type_check
  def add_flags(self, flags: Flags) -> list[str]:
    return self.footnotes.add_flags(flags)

  @util.type_check
  def add_valid_signature(self,
                          message: bytes,
                          comment: str = "",
                          sig_flags: Flags = []):
    flag_valid = flag.Flag(
        label="Valid",
        bug_type=flag.BugType.UNKNOWN,
        description="The test vector contains a valid signature. "
        "A frequent cause for rejecting valid signatures are "
        "implementations that restrict the parameters such as "
        "key size, or message digests.",
    )
    sig = self.signer.sign(message)
    test = RsassaPkcs1TestVector()
    test.comment = comment
    test.msg = message
    test.sig = sig
    test.flags = self.add_flags(sig_flags)
    test.flags += self.key_flags
    if not test.flags:
      test.flags = self.add_flags([flag_valid])
    test.result = "valid"
    self.add_test(test)


  @type_check
  def add_signature(self,
                    valid: str,
                    comment: Optional[str],
                    message: bytes,
                    sig: Union[bytes, int],
                    more_flags: Optional[Flags] = None):
    keysize = (self.key.n.bit_length() + 7) // 8
    if not comment:
      valid = "valid"
      comment = "valid"

    if isinstance(sig, int):
      sig %= 256**keysize
      sig = sig.to_bytes(keysize, "big")
    else:
      assert isinstance(sig, bytes)

    test = RsassaPkcs1TestVector()
    test.comment = comment
    test.msg = message
    test.sig = sig
    test.result = valid
    test.flags = self.key_flags[:]
    if more_flags:
      test.flags += self.add_flags(more_flags)
    self.add_test(test)

  @type_check
  def generate_modified(self, message: bytes):
    """Generates modified signatures for message"""
    key = self.key
    md = self.md
    for bug, sig, flags in generate_legacy_signatures(message, key, md):
      self.add_signature("acceptable", bug, message, sig, flags)
    for bug, sig, flags in generate_invalid_signatures(message, key, md):
      self.add_signature("invalid", bug, message, sig, flags)

  def generate_valid(self):
    messages = [
      b"",
      bytes(20),
      b"Test",
      b"123400",
      b"Message",
      b"a",
      bytes(range(224,256))]
    for m in messages:
      self.add_valid_signature(m)

  def generate_wrong_primitive(self, message: bytes):
    # Generates PSS signatures. Not sure if this covers:
    # https://bugzilla.redhat.com/show_bug.cgi?id=1510156
    md = self.md
    flag_pss = flag.Flag(
        label="WrongPrimitive",
        bug_type=flag.BugType.WRONG_PRIMITIVE,
        description="The signature uses RSASSA-PSS instead of RSA PKCS#1 "
        "padding. Signature verification must not accept "
        "signatures for distinct paddings.",
        effect="The security of the signature scheme is reduced to the "
        "security of the weakest padding. Bugs in the verification are "
        "difficult to detect.",
        links=["https://bugzilla.redhat.com/show_bug.cgi?id=1510156"],
    )

    for slen in sorted({0, 20, 32, util.digest_size(md)}):
      signer = rsa_pss.RsassaPss(self.key, md, "MGF1", md, slen)
      sig = signer.sign(message)
      self.add_signature("invalid", "RSASSA-PSS signature", message, sig, [flag_pss])

  @type_check
  def generate_all(self, message: bytes):
    self.generate_valid()
    self.generate_modified(message)
    self.generate_wrong_primitive(message)

  def as_struct(self, sort_by: Optional[str] = None) -> JsonType:
    """Returns the test group as a Json type.

    Args:
      sort_by: determines the field that is used to sort the
               test vectors. If None the test vectors are sorted
               by their comments.
    Returns:
      the list of test vectors in Json form. The fields are described
      in self.schema.
    """
    key = self.key
    pub = key.publicKey()
    group1 = {}
    group1["type"] = self.testtype
    group1["keySize"] = key.n.bit_length()
    group1["sha"] = self.md
    group1["tests"] = self.get_all_vectors(sort_by)
    group1["publicKey"] = pub.as_struct()
    group1["publicKeyAsn"] = asn.encode_hex([key.n, key.e])
    group1["publicKeyDer"] = asn.encode_hex(pub.publicKeyAsn())
    # Using the SSL format here.
    group1["publicKeyPem"] = pub.publicKeyPem()
    # Add jwk_key if defined
    jwk_key = pub.publicKeyJwk(use="sig", md=self.md)
    if jwk_key:
      group1["publicKeyJwk"] = jwk_key
    return group1

RsassaPkcs1GenTestVector = sig_test_vector.SignatureTestVector

class RsassaPkcs1Generate(test_vector.TestType):
  """Test vectors of class RsassaPkcs1Generate are intended for checking the
     generation of RSA PKCS #1 v 1.5 signatures.

     The test vectors only provide limited coverage for signature verification,
     since a frequent flaw in implementations is to only check the padding
     partially.
  """

class RsassaPkcs1GenTestGroup(test_vector.TestGroup):
  algorithm = "RSASSA-PKCS1-v1_5"
  testtype = RsassaPkcs1Generate
  vectortype = RsassaPkcs1GenTestVector
  schema = {
      "privateKey": {
          "type": rsa_key.RsaPrivateKey,
          "desc": "the private key",
      },
      "sha": {
          "type": AST.MdName,
          "desc": "the hash function used for the message",
      },
      "keySize": {
          "type": int,
          "desc": "the size of the modulus in bits",
      },
      "privateKeyPkcs8": {
          "type": AST.Der,
          "desc": "PKCS8 encoded private key",
      },
      "privateKeyPem": {
          "type": "Pem",
          "desc": "Pem encoded private key"
      },
      "privateKeyJwk": {
          "type": rsa_key.JwkRsaPrivateKey,
          "desc": "[Optional] Private key in JWK format",
          "ref": "RFC 7517",
          "since": "0.7",
          "optional": True,
      },
  }


  def __init__(self, key, md, footnotes):
    super().__init__()
    self.key = key
    self.md = md
    self.signer = rsassa_pkcs1.RsassaPkcs1(key, md)
    key_flags = get_key_flags(key, md)
    self.footnotes = footnotes
    self.key_flags = self.add_flags(key_flags)

  @util.type_check
  def add_flags(self, flags: Flags) -> list[str]:
    return self.footnotes.add_flags(flags)

  @util.type_check
  def add_valid_signature(self,
                          message: bytes,
                          comment:str = "",
                          sig_flags: Flags = []):
    sig = self.signer.sign(message)
    test = RsassaPkcs1GenTestVector()
    test.comment = comment
    test.msg = message
    test.sig = sig
    test.result = "valid"
    test.flags = self.add_flags(sig_flags) + self.key_flags
    self.add_test(test)

  def generate_valid(self):
    flag_valid = flag.Flag(
        label="Valid",
        bug_type=flag.BugType.UNKNOWN,
        description="The test vector contains a valid signature. "
        "A frequent cause for rejecting valid signatures are "
        "implementations that restrict the parameters such as "
        "key size, or message digests.",
        effect="",
    )
    messages = [
      b"",
      bytes(20),
      b"Test",
      b"123400",
      b"Message",
      b"a",
      bytes(range(224,256)),
      bytes(x & 0xff for x in range(1,280))]
    for m in messages:
      self.add_valid_signature(m, sig_flags=[flag_valid])

  def generate_all(self, message):
    self.generate_valid()

  def as_struct(self, sort_by: Optional[str] = None) -> JsonType:
    """Return the test vectors in this group as a Json type.

    The fields are defined in self.schema.
    """
    key = self.key
    group1 = {}
    group1["type"] = self.testtype
    group1["privateKey"] = key.as_struct()
    # So far all encodings of the keys use rsaEncoding for pkcs1algorithm.
    # We do this because some libraries reject keys otherwise.
    group1["privateKeyPem"] = key.privateKeyPem()
    group1["privateKeyPkcs8"] = asn.encode_hex(key.privateKeyPkcs8())
    jwk_private_key = key.privateKeyJwk(use="sig", md=self.md)
    if jwk_private_key:
      group1["privateKeyJwk"] = jwk_private_key
    group1["keySize"] = key.n.bit_length()
    group1["sha"] = self.md
    group1["tests"] = self.get_all_vectors(sort_by)
    return group1

def gen_rsa_sign_test(namespace):
  t = test_vector.Test("RSASSA-PKCS1-v1_5")
  size = namespace.size  # modulus size in bits
  md = namespace.sha  # the hash function
  three_primes = getattr(namespace, "three_primes", False)
  if three_primes:
    keys = rsa_test_keys.rsa_three_primes_keys
  else:
    keys = rsa_test_keys.rsa_signature_keys

  if size == 0:
    keys = [k for k in keys if k.n.bit_length() >= 1024]
  else:
    keys = [k for k in keys if k.n.bit_length() == size]

  if md and not three_primes:
    keys = [k for k in keys if k.md == md]

  if len(keys) == 0:
    if not size:
      size = 2048
    keys = [rsa_test_keys.get_test_key(size, three_primes=three_primes)]

  for key in keys:
    group_md = key.md or md or "SHA-256"
    g = RsassaPkcs1GenTestGroup(key, group_md, t.footnotes())
    g.generate_valid()
    idx = "rsa_gen_%d_%s" % (key.n.bit_length(), group_md)
    t.add_group(idx, g)

  if not three_primes:
    for i, val in enumerate(rsa_test_keys.EDGECASES):
      message, comment, flags, key, case_md = val
      if size and key.n.bit_length() != size:
        continue
      if md and md != case_md:
        continue
      g = RsassaPkcs1GenTestGroup(key, case_md, t.footnotes())
      g.add_valid_signature(message, comment, flags)
      idx = "edgecase " + str(i)
      t.add_group(idx, g)
  return t

def gen_rsa_verify_test(namespace):
  size = namespace.size  # modulus size in bits
  md = namespace.sha  # the hash function
  t = test_vector.Test("RSASSA-PKCS1-v1_5")
  if size == 0:
    # If size == 0 used some defaults
    key = rsa_test_keys.rsa_test_key2
    md = key.md
    g = RsassaPkcs1TestGroup(key, md, t.footnotes())
    g.generate_all(b"Test")
    t.add_group("g", g)
    for key in rsa_test_keys.rsa_signature_keys:
      if key.n.bit_length() < 1024:
        continue
      g = RsassaPkcs1TestGroup(key, md, t.footnotes())
      g.generate_valid()
      idx = "rsa_%d_%s" % (key.n.bit_length(), md)
      t.add_group(idx, g)
    for i, val in enumerate(rsa_test_keys.EDGECASES):
      message, comment, flags, key, case_md = val
      g = RsassaPkcs1TestGroup(key, case_md, t.footnotes())
      g.add_valid_signature(message, comment, flags)
      idx = "edgecase "+str(i)
      t.add_group(idx, g)
  else:
    # If no message digest is given choose one that is at least as
    # strong as the key size.
    if md == "":
      if size <= 3072:
        md = "SHA-256"
      else:
        md = "SHA-512"
    key = rsa_test_keys.get_test_key(size, md)
    g = RsassaPkcs1TestGroup(key, md, t.footnotes())
    g.generate_all(b"123400")
    t.add_group("g", g)
    for i, val in enumerate(rsa_test_keys.EDGECASES):
      message, comment, flags, key, case_md = val
      if key.n.bit_length() == size and case_md == md:
        g = RsassaPkcs1TestGroup(key, case_md, t.footnotes())
        g.add_valid_signature(message, comment, flags)
        idx = "edgecase " + str(i)
        t.add_group(idx, g)
  return t

# ===== Stuff used to precompute keys =====
def gen_short_signature(md:str, keysize:int):
  """Constructs an RSA key and a message such that
     the keysize is the key size of the RSA key in bits and
     such that the PKCS #1 v.1.5 is a short integer. The constructed
     RSA modulus has unbalanced sizes for p and q. The public
     exponent is 3."""
  l = (keysize + 7) // 8
  psize = (keysize + 5) // 3
  p = 0
  while p % 3 != 2:
    p = pseudoprimes.random_prime(2**(psize-1), 2**psize)
  e = 3
  dp = pow(3, -1, p-1)
  cnt = 0
  while True:
    message = str(cnt)
    cnt += 1
    pad = padding(message, md)
    header_len = l - len(pad)
    assert header_len >= 11
    pad = bytes([0,1] + [0xff]*(header_len - 3) + [0]) + pad
    t = 0
    for b in pad:
      t = t * 256 + b
    sig = pow(t, dp, p)
    diff = sig ** 3 - t
    if diff < 0: continue
    assert diff % p == 0
    q = diff // p
    for i in (2, 3, 5, 7, 11):
      while q % i == 0:
        q //= i
    n = q * p
    if n.bit_length() != keysize:
      continue
    if q % 3 != 2:
      continue
    if not pseudoprimes.is_probable_prime(q):
      continue
    return rsa_key.RsaPrivateKey(n=n, e=e, primes=[p,q]), message

def gen_extreme_signature(md: str, keysize: int):
  """Constructs an RSA key and a message such that
     the PKCS #1 v 1.5 signature of the message is an integer
     close to n. The key size of the constructed RSA key in bits
     is key size. The public exponent is 3."""
  l = (keysize + 7) // 8
  psize = (keysize + 5) // 3
  p = 0
  while p % 3 != 2:
    p = pseudoprimes.random_prime(2 ** (psize - 1), 2 ** psize)
  e = 3
  dp = pow(3, -1, p - 1)
  cnt = 0
  while True:
    message = str(cnt)
    cnt += 1
    pad = padding(message, md)
    assert isinstance(pad, bytearray)
    header_len = l - len(pad)
    assert header_len >= 11
    pad = bytearray([0, 1] + [0xff]*(header_len - 3) + [0]) + pad
    t = 0
    for b in pad:
      t = t * 256 + b
    sig = pow(-t, dp, p)
    diff = sig ** 3 + t
    if diff < 0: continue
    assert diff % p == 0
    q = diff // p
    for i in (2,3,5,7,11):
      while q % i == 0:
        q //= i
    n = q * p
    if n.bit_length() != keysize:
      continue
    if q % 3 != 2:
      continue
    if not pseudoprimes.is_probable_prime(q):
      continue
    key = rsa_key.RsaPrivateKey(n=n, e=e, primes=[p,q], md=md)
    return key, message


class RsaSignatureProducer(producer.Producer):

  def parser(self):
    res = self.default_parser()
    res.add_argument(
        "--size", type=int, default=0, help="the size of the RSA key in bits")
    res.add_argument(
        "--sha",
        type=str,
        choices=[""] + HASHES,
        default="",
        help="the hash function used for hashing the message")
    res.add_argument(
        "--op",
        type=str,
        choices=["sign", "verify"],
        default="verify",
        help="Determines whether the test vectors are used to test signature"
        " or signature verification.")
    res.add_argument(
        "--three_primes",
        action="store_true",
        help="uses three prime RSA keys if set")
    return res

  def generate_test_vectors(self, namespace):
    if namespace.op == "sign":
      return gen_rsa_sign_test(namespace)
    elif namespace.op == "verify":
      return gen_rsa_verify_test(namespace)


# DEPRECATED: Use Producer.produce() instead
def main(namespace):
  RsaSignatureProducer().produce(namespace)


if __name__ == "__main__":
  RsaSignatureProducer().produce_with_args()
