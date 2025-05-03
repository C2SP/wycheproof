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

import AST
import asn
import asn_fuzzing
import asn_parser
import dsa
import dsa_test_keys
import sig_test_vector
import special_values
import flag
import producer
import special_int
import test_vector
from typing import Optional, Union, Any
import util

# TODO:
#   check special cases:
#     0s in message

SIGNATURE_ENCODINGS = ["asn", "p1363"]

# Key types for type hints.
Flags = Optional[list[str]]

DsaTestVector = sig_test_vector.AsnSignatureTestVector

DsaAlgorithm = test_vector.Algorithm("DSA", g3doc="dsa.md")


class DsaVerify(test_vector.TestType):
  """Test vectors of test DsaVerify are intended for checking the signature

  verification of DSA signatures.

  Test vectors with "result" : "valid" are valid signatures.
  Test vectors with "result" : "invalid" are invalid.
  Test vectors with "result" : "acceptable" are signatures that may
  be rejected for a number of reasons: they can be signatures with valid
  values for r and s, but with an invalid or non-standard encoding. They
  can be signatures with weak or non-standard parameters. All the test
  vectors of this type have a label describing the abnomaly.
  """

class DsaTestGroup(test_vector.TestGroup):
  algorithm = DsaAlgorithm
  vectortype = DsaTestVector
  testtype = DsaVerify
  allow_acceptable = False
  schema = {
      "publicKey": {
          "type": dsa.DsaPublicKey,
          "desc": "unencoded DSA public key",
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
          "desc": "the hash function used for DSA",
      }
  }

  @util.type_check
  def __init__(self, pubkey: dsa.DsaPublicKey):
    super().__init__()
    self.pubkey = pubkey

  def as_struct(self, sort_by: Optional[str] = None) -> dict:
    if sort_by is None:
      sort_by = "comment"
    key = self.pubkey
    group = {}
    group["type"] = self.testtype
    group["sha"] = key.md
    group["publicKey"] = key.as_struct()
    group["publicKeyDer"] = key.encode_hex()
    group["publicKeyPem"] = key.pem()
    group["tests"] = self.get_all_vectors(sort_by=sort_by)
    return group

class DsaP1363Verify(test_vector.TestType):
  """Test vectors of type DsaP1363Verify are meant for the verification
     of IEEE P1363 encoded DSA signatures.

     IEEE P1363 encoded signatures are the concatenation of the values
     r and s encoded as unsigned integers in bigendian order using a fixed
     size equal to the length of the field order. The tests expect that
     all signatures with other sizes (e.g. additional appended bytes)
     are rejected. (Though there are not a lot of test vectors verifying
     this).

     Test vectors with "result" : "valid" are valid signatures.
     Test vectors with "result" : "invalid" are invalid.
     Test vectors with "result" : "acceptable" are signatures that may
     or may not be rejected. The reasons for potential rejection are
     described with labels.
  """

class DsaP1363TestGroup(test_vector.TestGroup):
  """A test group for DSA signatures using IEEE P1363 encoding.
     The test vectors in this group are meant for signature verification.

     The test group contains the same public key for the signatures in
     multiple representations. The public keys are valid with the sole
     exception that they may use short keys and weak hash functions
     such as SHA-1."""

  algorithm = "DSA"
  testtype = DsaP1363Verify
  vectortype = sig_test_vector.SignatureTestVector
  schema = {
     "publicKey" : {
         "type" : dsa.DsaPublicKey,
         "desc" : "unencoded EC public key",
     },
     "publicKeyDer" : {
         "type" : AST.Der,
         "desc" : "DER encoded public key",
     },
     "publicKeyPem" : {
         "type" : AST.Pem,
         "desc" : "Pem encoded public key",
     },
     "sha" : {
         "type" : AST.MdName,
         "desc" : "the hash function used for DSA",
     },
  }

  def __init__(self, pubkey: dsa.DsaPublicKey):
    super().__init__()
    self.pubkey = pubkey
    self.encoding = "p1363"

  def as_struct(self, sort_by=None) -> dict[str, Any]:
    if sort_by is None:
      sort_by = "comment"
    group = {}
    group["type"] = self.testtype
    group["sha"] = self.pubkey.md
    group["publicKey"] = self.pubkey.as_struct()
    group["publicKeyDer"] = self.pubkey.encode_hex()
    group["publicKeyPem"] = self.pubkey.pem()
    group["tests"] = self.get_all_vectors(sort_by=sort_by)
    return group

class DsaTestGenerator(test_vector.TestGenerator):
  algorithm = DsaAlgorithm
  testinput = "sig"

  def __init__(self, encoding: str):
    super().__init__()
    if encoding not in SIGNATURE_ENCODINGS:
      raise ValueError("Invalid encoding:" + encoding)
    self.test = test_vector.Test(self.algorithm)
    self.encoding = encoding

  @util.type_check
  def add_test(self, key: Union[dsa.DsaPublicKey,
                                dsa.DsaPrivateKey], msg: bytes, sig: bytes,
               result: str, comment: str, flags: list[flag.Flag]):
    flags = self.add_flags(flags)
    if isinstance(key, dsa.DsaPublicKey):
      pubkey = key
    else:
      pubkey = key.public_key()
    if flags is None:
      flags = []
    keyid = str([pubkey.md, pubkey.p, pubkey.q, pubkey.g, pubkey.y])
    if keyid not in self.test.testgroups:
      if self.encoding == "asn":
        self.test.add_group(keyid, DsaTestGroup(pubkey))
      elif self.encoding == "p1363":
        self.test.add_group(keyid, DsaP1363TestGroup(pubkey))

    group = self.test.testgroups[keyid]
    tc = DsaTestVector(msg = msg,
                       sig = sig,
                       comment = comment,
                       result = result,
                       flags = flags)
    group.add_test(tc)

  @util.type_check
  def encode(self, key:Union[dsa.DsaPrivateKey, dsa.DsaPublicKey],
             r: Any, s: Any,
             allow_invalid: bool = False) -> Optional[bytes]:
    """Tries to encode r,s as a signature.

    Args:
      r: the value r of the signature. Some of the false encodings
         try values for r that are not integers.
      s: the value s of the signature. Some of the false encodings
         try values for s that are not integers.
      allow_invalid: allows modified encodings. E.g. P1363 encoding
         returns longer signatures when the values r and s require more bytes
         than allowed. Some DSA implementations simply try to divide the
         signature in two equally long parts, but such signatures are invalid.
    Returns:
      the encoded signature or None if the encoding was not possible.
    """
    if self.encoding == "asn":
      return asn.encode([r, s])
    elif self.encoding == "p1363":
      if not isinstance(r, int) or not isinstance(s, int):
        return None
      nbits = key.q.bit_length()
      mbits = max(r, s).bit_length()
      if r < 0 or s < 0:
        return None
      if mbits > nbits:
        if allow_invalid:
          nbits = mbits
        else:
          return None
      sz = (nbits + 7) // 8
      return r.to_bytes(sz, "big") + s.to_bytes(sz, "big")
    else:
      raise ValueError("Unknown encoding:" + self.encoding)

  def add_sig(self, pubkey: dsa.DsaPublicKey, msg: bytes, r: int, s: int,
              comment: str, flags: list[flag.Flag]):
    if pubkey.verify_raw(r, s, msg):
      result = "valid"
    else:
      result = "invalid"
    sig = self.encode(pubkey, r, s, allow_invalid=True)
    if sig is not None:
      self.add_test(
          pubkey, msg, sig=sig, result=result, comment=comment, flags=flags)

  def generate_pseudorandom(self, privkey: dsa.DsaPrivateKey, msg: str,
                            comment: str, seed: bytes, cnt: int,
                            flags: list[flag.Flag]):
    for i in range(cnt):
      r, s = privkey.sign_raw(msg, seed=seed + b"%d" % i)
      encoding = self.encode(privkey, r, s)
      if encoding is not None:
        # SEVERITY: BUG
        self.add_test(
            privkey,
            msg=msg,
            sig=encoding,
            result="valid",
            comment=comment,
            flags=flags)

  def generate_edge_case_hash(self, privkey: dsa.DsaPrivateKey):
    """Generates pseudorandom signatures where hash(msg) is a special case."""
    flag_special_hash = flag.Flag(
        label="SpecialCaseHash",
        bug_type=flag.BugType.EDGE_CASE,
        description="The test vector contains a signature where the hash of "
        "the message is a special case, e.g., contains a long run of 0 or 1 "
        "bits.")

    for msg in special_values.edge_case_msg_for_hash(privkey.md):
      if isinstance(msg, str):
        msg = bytes(msg, "ascii")
      self.generate_pseudorandom(
          privkey,
          msg,
          seed=b"121j2h3",
          comment="special case hash",
          cnt=1,
          flags=[flag_special_hash])

  def generate_legacy_dsa(self, pub: dsa.DsaPublicKey, msg: bytes, r: int, s: int):
    if self.encoding != "asn":
      return
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
    # SEVERITY: LEGACY
    def twos_complement(x):
      b = x.bit_length()
      if b % 8 == 0:
        yield x - (1 << b)
    assert isinstance(msg, bytes)
    for cr in twos_complement(r):
      self.add_test(
          pub,
          msg,
          sig=asn.encode([cr, s]),
          result="invalid",
          comment="Legacy:ASN encoding of r misses leading 0",
          flags=[missing_zero_flag])
    for cs in twos_complement(s):
      self.add_test(
          pub,
          msg,
          sig=asn.encode([r, cs]),
          result="invalid",
          comment="Legacy:ASN encoding of s misses leading 0",
          flags=[missing_zero_flag])

  def generate_modified_asn(self, pub: dsa.DsaPublicKey, msg: bytes, r: int,
                            s: int):
    ber_flag = flag.Flag(
        label="BerEncodedSignature",
        bug_type=flag.BugType.BER_ENCODING,
        description="DSA signatures are usually DER encoded. "
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
        description="DSA signatures are encoded using ASN.1. "
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
        flags = [flag.NORMAL]
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
      self.add_test(
          pub, msg, sig=encoding, result=result, comment=bugtype, flags=flags)


  @util.type_check
  def generate_modified_rs(self, keymat: dsa.DsaPublicKey, msg: bytes, r: int, s:int):
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
    # Severity: SIGNATURE_MALLEABILITY
    q = keymat.q
    qbits = q.bit_length()
    p = keymat.p
    g = keymat.g
    for cflag, val, desc in [
        (range_check_flag, r + q, "r + q"),
        (range_check_flag, r - q, "r - q"),
        (range_check_flag, r + 256 * q, "r + 256 * q"),
        (modified_int_flag, -r, "-r"),
        (modified_int_flag, q - r, "q - r"),
        (modified_int_flag, -q - r, "-q - r"),
        (integer_overflow_flag, r + 2**qbits, f"r + 2**{qbits}"),
        (integer_overflow_flag, r - 2**qbits, f"r - 2**{qbits}"),
        (integer_overflow_flag, r + 2**(64 + qbits), f"r + 2**{64 + qbits}"),
    ]:
      self.add_sig(
          keymat, msg, val, s, comment=f"replaced r by {desc}", flags=[cflag])
    for cflag, val, desc in [
        (range_check_flag, s + q, "s + q"),
        (range_check_flag, s - q, "s - q"),
        (range_check_flag, s + 256 * q, "s + 256 * q"),
        (modified_int_flag, -s, "-s"),
        (modified_int_flag, -q - s, "-q - s"),
        (integer_overflow_flag, s + 2**qbits, f"s + 2**{qbits}"),
        (integer_overflow_flag, s - 2**qbits, f"s - 2**{qbits}"),
        (integer_overflow_flag, s + 2**(64 + qbits), f"s + 2**{64 + qbits}"),
    ]:
      self.add_sig(
          keymat, msg, val, s, comment=f"replaced s by {desc}", flags=[cflag])


  def generate_fake_sigs(self, keymat: dsa.DsaPublicKey, msg: bytes):
    """Generates edge case signatures with unusual values for r and s.

    This method tries silly edge cases such as r=0 and s=0. Careless coding
    such as returning 0 for the modular inverse of 0 could allow forgeries
    with such values.

    Args:
      params: contains keys, EC group and hash function
      msg: the message to sign
    """
    invalid_sig_flag = flag.Flag(
        label="InvalidSignature",
        bug_type=flag.BugType.AUTH_BYPASS,
        description="The signature contains special case values such as r=1 "
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
    q = keymat.q
    p = keymat.p
    vals = [
        (0, "0"),
        (1, "1"),
        (-1, "-1"),
        (q, "q"),
        (q - 1, "q - 1"),
        (q + 1, "q + 1"),
        (p, "p"),
        (p + 1, "p + 1"),
    ]
    for r, rtxt in vals:
      for s, stxt in vals:
        self.add_sig(
            keymat,
            msg,
            r,
            s,
            f"Signature with special case values r={rtxt} and s={stxt}",
            flags=[invalid_sig_flag])
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
            "CVE-2022-24884",  # ecdsautils
        ],
    )
    comment = "Signature encoding contains wrong types."
    smallSet = [
        (0, "0"),
        (1, "1"),
        (-1, "-1"),
        (q, "q"),
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
            keymat,
            msg,
            r,
            s,
            f"Signature encoding contains incorrect types: r={rtxt}, s={stxt}",
            flags=[invalid_types_flag])

    for x, xtxt in wrong_types:
      self.add_sig(
          keymat,
          msg,
          x,
          x,
          f"Signature encoding contains incorrect types: r={xtxt}, s={xtxt}",
          flags=[invalid_types_flag])

    for r, rtxt in wrong_types:
      self.add_sig(
          keymat,
          msg,
          r,
          0,
          f"Signature encoding contains incorrect types: r={rtxt}, s=0",
          flags=[invalid_types_flag])

  def gen_key_from_sig(self,
                       key: dsa.DsaPrivateKey,
                       message: bytes,
                       r0: int,
                       s: int,
                       descr: str,
                       *,
                       flags=list[flag.Flag],
                       check_r: bool = True):
    # key is used for parameters only
    p, q, g = key.p, key.q, key.g
    if check_r:
      assert pow(r0, q, p) == 1
    h = key.digest(message)
    w = pow(s, -1, q)
    r = r0 % q
    u1 = h * w % q
    u2 = r * w % q
    u2inv = pow(u2, -1, q)
    y = pow(r0 * pow(g, q - u1, p), u2inv, p)
    key = dsa.DsaPublicKey(key.md, p, q, g, y)
    # SEVERITY: ARITHMETIC ERROR
    self.add_test(
        key, message, self.encode(key, r, s), "valid", descr, flags=flags)

  def generate_special(self, key: dsa.DsaPublicKey):
    flag_arithmetic_error = flag.Flag(
        label="ArithmeticError",
        bug_type=flag.BugType.EDGE_CASE,
        description="Some implementations of ECDSA have arithmetic errors "
        "that occur when intermediate results have extreme values. "
        "This test vector has been constructed to test such occurences.")
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

    r0 = pow(key.g, 12441231249187294123123, key.p)
    self.gen_key_from_sig(
        key, b"Test", 1, 1, "r,s = 1,1", flags=[flag_small_rs])
    self.gen_key_from_sig(
        key, b"Test", 1, 5, "r,s = 1,5", flags=[flag_small_rs])
    self.gen_key_from_sig(
        key,
        b"Test",
        pow(key.g, 12345, key.p),
        1,
        "s = 1",
        flags=[flag_arithmetic_error])
    self.gen_key_from_sig(
        key,
        b"Test",
        1,
        pow(5, -1, key.q),
        "r = 1, u2 small",
        flags=[flag_arithmetic_error])
    self.gen_key_from_sig(
        key,
        b"Test",
        r0,
        pow(5, -1, key.q),
        "u2 small",
        flags=[flag_arithmetic_error])
    self.gen_key_from_sig(
        key,
        b"Test",
        1,
        key.q - 1,
        "r = 1, s = q-1",
        flags=[flag_arithmetic_error])
    self.gen_key_from_sig(
        key, b"Test", r0, key.q - 1, "s = q - 1", flags=[flag_arithmetic_error])
    for s in special_int.edge_case_inverse(key.q):
      self.gen_key_from_sig(
          key,
          b"Test",
          r0,
          s,
          "edge case modular inverse",
          flags=[flag_modular_inverse])

  def generate_all(self, privkey: dsa.DsaPrivateKey,
                   msg: bytes, r: int, s: int):
    pubkey = privkey.public_key()
    self.generate_legacy_dsa(pubkey, msg, r, s)
    if self.encoding == "asn":
      self.generate_modified_asn(pubkey, msg, r, s)
    self.generate_modified_rs(pubkey, msg, r, s)
    self.generate_fake_sigs(pubkey, msg)
    self.generate_pseudorandom(
        privkey,
        msg,
        seed=b"k12h41ik4",
        cnt=5,
        comment="pseudorandom signatures",
        flags=[flag.NORMAL])
    self.generate_special(pubkey)
    self.generate_edge_case_hash(privkey)


class DsaProducer(producer.Producer):

  def parser(self):
    res = self.default_parser()
    res.add_argument(
        "--sha",
        type=str,
        choices=["", "SHA-1", "SHA-224", "SHA-256", "SHA-512"],
        default="",
        help="The hash function")
    res.add_argument(
        "--sizep",
        type=int,
        choices=[0, 1024, 2048, 3072, 4096],
        default=0,
        help="The size of p in bits")
    res.add_argument(
        "--sizeq",
        type=int,
        choices=[0, 160, 224, 256],
        default=0,
        help="The size of q in bits")
    # TODO: deprecate
    res.add_argument(
        "--asnparsing",
        type=str,
        choices=["der"],
        default="der",
        help="Deprecated")
    res.add_argument(
        "--encoding",
        type=str,
        help="Encoding of the signatures",
        choices=SIGNATURE_ENCODINGS,
        default="asn")
    return res

  def generate_test_vectors(self, namespace):
    sizep = namespace.sizep
    sizeq = namespace.sizeq
    sha = namespace.sha
    tv = DsaTestGenerator(encoding=namespace.encoding)
    if not sizep and not sizeq and not sha:
      for t in dsa_test_keys.TEST_CASES:
        tv.generate_all(t.privkey, t.message, t.r, t.s)
    else:
      key = dsa_test_keys.get_test_key(sizep, sizeq, sha)
      msg = b"123400"
      r, s = key.sign_raw(msg, seed=b"1lkj31lk4j")
      tv.generate_all(key, msg, r, s)
    return tv.test


# DEPRECATED: Use Producer.produce() instead
def main(namespace):
  DsaProducer().produce(namespace)


if __name__ == "__main__":
  DsaProducer().produce_with_args()
