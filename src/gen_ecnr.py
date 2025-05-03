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
import ec_key
import ec_groups
import producer
import prand
import sig_test_vector
import test_vector
from typing import Optional
import util

# Generates test vectors for ECNR signatures as implemented by BouncyCastle.
# (At the moment I don't know if the implementation in BouncyCastle
# is compatible with any standard or other ECNR implementation.)

STATUS = "alpha"

# The encodings of the signatures.
# Only "asn" is supported. This may change if we find libraries other than
# BouncyCastle to check.
ECNR_SIGNATURE_ENCODINGS = ["asn"]

class EcnrVerify(test_vector.TestType):
  """Test vectors of type EcnrVerify are intended for testing the

     verification of ECNR signatures (as implemented by BouncyCastle).

     So far I don't have a RFC or a paper describing the signature
     scheme in BouncyCastle, hence it is unclear if this signature scheme
     is used anywhere else.
  """

# Description of the ECNR scheme in BouncyCastle:
#   n: order of the curve
#   p: characteristic of the underlying field
#   x: private key
#   G: generator
#   W = x*G: public key
#   h: hash of message
# Signature
#   choose k in [1 .. n-1]
#   V = k*G
#   r = V_x + h (mod n)
#   s = k - x*r (mod n)
# Verification:
#   V2 = s*G + r*W
#   h2 = r - V2_x (mod n)
# Justification:
#   V2 = s*G + r*W = (s + x*r)*G = k*G = V
#   r - V2_x = r - V_x = h (mod n)
# Edge cases to test:
#   s = 0:
#     s = 0 may be valid (i.e. inversion of s is not necessary)
#     Test vectors with s=0 can be generated as follows:
#     (1) choose h, k compute r, then solve for x
#     (2) choose h, r compute P, then solve for W

class EcnrTestGroup(test_vector.TestGroup):
  algorithm = "ECNR"
  vectortype = sig_test_vector.AsnSignatureTestVector
  testtype = EcnrVerify
  schema = {
      "key": {
          "type": ec_key.EcPublicKey,
          "desc": "unencoded ECDSA public key",
      },
      "keyDer": {
          "type": AST.Der,
          "desc": "DER encoded public key",
      },
      "keyPem": {
          "type": AST.Pem,
          "desc": "Pem encoded public key",
      },
      "sha": {
          "type": AST.MdName,
          "desc": "the hash function used for ECNR",
      }
  }

  def __init__(self, pubkey, md: str):
    super().__init__()
    self.pubkey = pubkey
    self.md = md

  def as_struct(self, sort_by: Optional[str] = None):
    if sort_by is None:
      sort_by = "comment"
    key = self.pubkey
    group = {}
    group["type"] = self.testtype
    group["key"] = key.as_struct()
    group["keyDer"] = key.encode_hex()
    group["keyPem"] = key.pem()
    group["sha"] = self.md
    group["tests"] = self.get_all_vectors(sort_by=sort_by)
    return group

class EcnrTestGenerator(test_vector.TestGenerator):
  algorithm = "ECNR"

  def __init__(self, encoding: str = "asn"):
    super().__init__()
    self.test = test_vector.Test(self.algorithm)
    # As long as we don't have more than one library (BouncyCastle)
    # supporting this scheme there is no reason to generate other encodings.
    if encoding not in ECNR_SIGNATURE_ENCODINGS:
      raise ValueError("Unsupported encoding" + encoding)
    self.encoding = encoding

  def encode(self, r: int, s: int) -> bytes:
    """Encodes a signature.
    
    Args:
      r: part 1 of the signature
      s: part 2 of teh signature
    Returns:
      the encoded signature
    """
    if self.encoding == "asn":
      return asn.encode([r,s])
    else:
      raise ValueError("unknown encoding:" + self.encoding)

  @util.type_check
  def add_test(self, pubkey: ec_key.EcPublicKey, md: str, msg: bytes,
               sig: bytes, result: str, comment: str,
               flags: Optional[list[str]]) -> None:
    """Adds a test to the test vectors.
    
    Args:
      pub: the public key
      md: the hash function (e.g. "SHA-256")
      msg: the message that was signed
      sig: the encoded signature
      result: "valid" if the signature is valid, "invalid" if it is invalid
         or "acceptable" if either is possible (i.e. signatures with BER
         encoding)
      comment: the description of the test vector
      flags: flags for the test vector
    """
    assert result in ["valid", "invalid", "acceptable"]
    if flags is None:
      flags = []
    keyid = pubkey.encode_hex() + ":" + md
    if keyid not in self.test.testgroups:
      self.test.add_group(keyid, EcnrTestGroup(pubkey, md))
    group = self.test.testgroups[keyid]
    tc = sig_test_vector.AsnSignatureTestVector(
             msg = msg,
             sig = sig,
             comment = comment,
             result = result,
             flags = flags)
    group.add_test(tc)

  def add_sig(self,
              test,
              validity: str,
              comment: str,
              r: int,
              s: int,
              flags=None):
    if flags is None:
      flags = []
    if self.encoding == "asn":
      sig = asn.encode([r,s])
      self.add_test(test.pub, test.md, test.message, sig, validity, comment,
                    flags)
    else:
      raise ValueError("unknown encoding:" + self.encoding)

  @util.type_check
  def sign_hash_deterministic(self,
                              priv: ec_key.EcPrivateKey,
                              digest: bytes,
                              salt: bytes = b""):
    """Returns a deterministic signature for hash of a message.

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
    group = priv.group
    h = int.from_bytes(digest, "big")
    truncate_bits = len(digest) * 8 - group.n.bit_length()
    if truncate_bits > 0:
      h >>= truncate_bits

    cnt = 0
    while True:
      label = digest + salt + cnt.to_bytes(4, "little")
      cnt += 1
      k = prand.randrange(1, group.n, str(priv.s), label)
      V = k * group.generator()
      r = (V.x + h) % group.n
      if r == 0:
        continue
      s = (k - priv.s * r) % group.n
      if s == 0:
        continue
      return [r, s]

  # TODO: Are ECNR signatures malleable?
  def generate_pseudorandom(self, test, seed: bytes, cnt: int=5):
    """Just generate other signatures to verify the test code"""
    digest = util.hash(test.md, test.message)
    for i in range(cnt):
      r, s = self.sign_hash_deterministic(test.priv, digest,
                                          seed + i.to_bytes(4, "little"))
      self.add_sig(test, "valid", "pseudorandom signature", r, s)

  def generate_from_test(self, test):
    self.generate_pseudorandom(test, b"ziuyfr34k34h", 10)
    digest = util.hash(test.md, test.message)
    r, s = self.sign_hash_deterministic(test.priv, digest, b"1k23jh1k2j3h")
    self.generate_modified_asn(test, r, s)
    self.generate_modified_rs(test, r, s)
    self.generate_fake_sigs(test)
    self.generate_modified_hash(test)
    self.generate_p_at_infinity(test)

  @util.type_check
  def generate_pseudorandom_signatures(self,
                                       curve,
                                       message: bytes,
                                       md: str,
                                       seed: bytes = b"1231323127jkh1",
                                       cnt=5):
    test = TestCase()
    test.curve = curve
    test.message = message
    test.md = md
    test.priv = ec_key.EcPrivateKey(curve,
                                    prand.randrange(1, curve.n, seed, b"12lk3"))
    test.pub = test.priv.public()
    self.generate_pseudorandom(test, seed, cnt)

  def generate_modified_hash(self, test):
    digest = util.hash(test.md, test.message)
    modified_digests = []
    for pos in (0, 1, 4, len(digest) - 2, len(digest) - 1):
      modified = bytearray(digest)
      modified[pos] ^= 1
      modified_digests.append(bytes(modified))
    modified_digests.append(bytes(len(digest)))
    modified_digests.append(bytes([255]) * len(digest))
    modified_digests.append(bytes(1) + digest[:-1])
    modified_digests.append(digest[:-1] + bytes(1))
    modified_digests.append(digest[1:] + bytes(1))
    modified_digests.append(bytes(1) + digest[1:])
    for m in modified_digests:
      if m == digest:
        continue
      r, s = self.sign_hash_deterministic(test.priv, m, b"ieyqr" + m)
      self.add_sig(test, "invalid", "modified digest in signature", r, s)

  def generate_modified_asn(self, test, r, s, suffix="BER:"):
    for bugtype, encoding in asn_fuzzing.generate([r,s]):
      result = "invalid"
      if bugtype is None:
        result = "valid"
        bugtype = "valid"
      else:
        try:
          val2 = asn_parse.parse(encoding)
          if val == val2:
            bugtype = ber_suffix + bugtype
            result = "acceptable"
        except Exception as ex:
          result = "invalid"
          pass
      flags = []
      self.add_test(test.pub, test.md, test.message, encoding, result, bugtype,
                    flags)

  def generate_modified_rs(self, test, r: int, s: int):
    bug = "Modified r or s, e.g. by adding or subtracting the order of the group"
    n = test.curve.n
    p = test.curve.p
    bits = test.curve.n.bit_length()
    for cr in (r + n, r - n, -r, n - r, -n - r, r + 2**bits, r - 2**bits,
               2**bits - r):
      self.add_sig(test, "invalid", bug, cr, s)
    for cs in (s + n, s - n, -s, n - s, -s - n, s + 2**bits, s - 2**bits,
               2**bits - s):
      self.add_sig(test, "invalid", bug, r, cs)

  def generate_fake_sigs(self, test):
    ref = self.footnote(
        "EdgeCase", """Edge case values such as r=1 and s=0 can lead to
    forgeries if the ECDSA implementation does not check boundaries and
    computes s^(-1)==0.""")
    comment = "Signature with special case values for r and s"
    n = test.curve.n
    p = test.curve.p
    rSet = (0, 1, -1, n, n-1, n+1, p, p+1)
    sSet = (0, 1, -1, n, n-1, n+1, p, p+1, 0.25)
    for i in rSet:
      for j in sSet:
        self.add_sig(test, "invalid", comment, i, j, flags=[ref])

  def generate_p_at_infinity(self, test):
    comment = """P is at infinity"""
    n = test.curve.n
    p = test.curve.p
    hex_digest = util.hash(test.md, test.message).hex()
    h = int(hex_digest, 16)
    r = h
    s = -test.priv.s*r % n
    self.add_sig(test, "invalid", comment, r, s)

class TestCase:
  pass


def pseudorandom_test_case(curve, md, seed: bytes = "1k23j1l23"):
  ecnr = TestCase()
  ecnr.md = md
  ecnr.message = b"123400"
  ecnr.curve = curve
  s = prand.randrange(1, curve.n, seed, curve.name)
  ecnr.priv = ec_key.EcPrivateKey(curve, s)
  ecnr.pub = ecnr.priv.public()
  return ecnr


ecnrTest = pseudorandom_test_case(ec_groups.curveP256, "SHA-256")
ecnrTest2 = pseudorandom_test_case(ec_groups.brainpoolP256r1, "SHA-256")

class EcnrProducer(producer.Producer):

  # TODO: Add curve and hash to arguments
  def parser(self):
    res = self.default_parser()
    res.add_argument(
        "--encoding",
        type=str,
        choices=ECNR_SIGNATURE_ENCODINGS,
        default="asn",
        help="the encoding of the signatures")
    return res

  def generate_test_vectors(self, namespace):
    tv = EcnrTestGenerator()
    tv.generate_from_test(ecnrTest)
    tv.generate_from_test(ecnrTest2)

    cnt = 5
    # For ECNR the signature and the hash need to be equally long.
    tv.generate_pseudorandom_signatures(ec_groups.curveP256, bytes(16),
                                        "SHA-256", b"8917313kjh134", cnt)
    tv.generate_pseudorandom_signatures(ec_groups.curveP521, bytes(20),
                                        "SHA-512", b"981273jkhsdf", cnt)
    tv.generate_pseudorandom_signatures(ec_groups.curveP384, b"Test", "SHA-384",
                                        b"lk21j3lkj213", cnt)
    tv.generate_pseudorandom_signatures(ec_groups.curveP521, b"Test", "SHA-512",
                                        b"lk12j31lk2js", cnt)
    tv.generate_pseudorandom_signatures(ec_groups.brainpoolP256r1, b"123400",
                                        "SHA-256", b"k21j31lk231d", cnt)
    tv.generate_pseudorandom_signatures(ec_groups.brainpoolP256t1, b"123400",
                                        "SHA-256", b"lk12j313kwes", cnt)
    tv.generate_pseudorandom_signatures(ec_groups.brainpoolP512r1, b"123400",
                                        "SHA-512", b"lk12lkj4lkoisu", cnt)
    return tv.test


# DEPRECATED: Use Producer.produce() instead
def main(namespace):
  EcnrProducer().produce(namespace)


if __name__ == "__main__":
  EcnrProducer().produce_with_args()
