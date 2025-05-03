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

import gen_ecdsa
import test_vector
import AST
import ec
import ec_key
import ec_groups
import ecdsa
import gen_ecdsa
import flag
import hlib
import jws
import util
import flag
import producer
import base64
import prand
import jws_test_vector

from util import type_check
from collections.abc import Iterator
from typing import Any, Optional, Union

JsonType = Any
Flags = list[flag.Flag]
Signer = ecdsa.EcdsaSigner



ALGORITHMS = list(jws.ECDSA_ALGORITHMS)
  
def get_params(alg: str) -> dict[str, str]:
  if alg in jws.ECDSA_ALGORITHMS:
    return jws.ECDSA_ALGORITHMS[alg]
  else:
    raise ValueError("Unsupported algorithm:" + alg)

def get_md(alg) -> str:
  return get_params(alg)["md"]

def get_group(alg) -> ec_groups.EcGroup:
  return ec_groups.named_curve(get_params(alg)["crv"])

def b64encode(s: bytes) -> bytes:
  w = base64.urlsafe_b64encode(s)
  w = w.replace(b"=",b"")
  return w

@type_check
def get_signer(key:ec_key.EcPrivateKey, alg: str) -> Signer:
  """Returns a signer for the underlying primitive"""
  return ecdsa.EcdsaSigner(key, get_md(alg))


class JwsEcdsaTestGenerator(test_vector.TestGenerator):
  pass


JwsEcdsaTestVector = jws_test_vector.JwsTestVector

class JwsEcdsaVerify(test_vector.TestType):
  """Test vectors of class JwsEcdsaVerify are intended for checking the
     verification of ECDSA signatures.
  """

class JwsEcdsaTestGroup(test_vector.TestGroup):
  algorithm = "ECDSA"
  testtype = JwsEcdsaVerify
  vectortype = jws_test_vector.JwsTestVector
  schema = {
      "kid" : {
          "type": str,
          "desc": "the kid of the key"
      },
      "publicKey": {
          "type": ec_key.EcPublicKey,
          "desc": "the public key",
      },
      "publicKeyJwk": {
          "type":
              ec_key.JwkEcPublicKey,
          "desc":
              "the public key in JWK format.",
          "ref":
              "RFC 7517",
      },
      "publicKeyPem": {
          "type":
              AST.Pem,
          "short":
              "Public key in PEM format",
          "desc":
              "The public key in PEM format. This is the same key as the key in publicKeyJwk. "
              "Some libraries have better support for PEM encoded keys than for the JWK format. "
              "It should be noted that the PEM format does not include the algorithm.",
          "ref":
              "RFC 7517",
      },
      "alg": {
          "type": str,
          "desc": "the algorithm",
      },
      "keySize": {
          "type": int,
          "desc": "the size of the modulus in bits",
      },
  }

  def __init__(self, key, key_id: str, alg, footnotes):
    super().__init__()
    self.key = key
    self.kid = key_id
    self.alg = alg
    self.signer = get_signer(key, alg)
    self.footnotes = footnotes
    self.key_flags = []

  @util.type_check
  def add_flags(self, flags: Flags) -> list[str]:
    return self.footnotes.add_flags(flags)

  def encode_signature(self, r: int, s:int) -> bytes:
    sz = get_params(self.alg)["field_size"]
    rs = r.to_bytes(sz, 'big') + s.to_bytes(sz, 'big')
    return b64encode(rs)
    
  def header(self)-> bytes:
    return jws.jws_header(self.alg, self.kid)
    
  def bytes_to_sign(self, payload: bytes) -> bytes:
    return b64encode(self.header()) + b"." + b64encode(payload) 
    
  @util.type_check
  def raw_sign(self, bytes_to_sign: bytes) -> bytes:
    r, s = self.signer.sign_deterministic(bytes_to_sign)
    return self.encode_signature(r, s)

  @util.type_check
  def sign(self, payload: bytes) -> bytes:
    return self.raw_sign(self.bytes_to_sign(payload))

  def format_jws(self, payload: bytes, raw_sig: bytes) -> str:
    parts = [self.header(), payload, raw_sig]
    return ".".join(b64encode(p).decode("utf-8") for p in parts)

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
    sig = self.sign(message)
    test = JwsEcdsaTestVector()
    test.comment = comment
    test.msg = message
    test.jws = self.format_jws(message, sig)
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
                    payload: bytes,
                    sig: bytes,
                    more_flags: Optional[Flags] = None):
    if not comment:
      valid = "valid"
      comment = "valid"

    test = JwsEcdsaTestVector()
    test.comment = comment
    test.msg = payload
    test.jws = self.format_jws(payload, sig)

    test.result = valid
    test.flags = self.key_flags[:]
    if more_flags:
      test.flags += self.add_flags(more_flags)
    self.add_test(test)

  @type_check
  def add_signature_parts(self,
                    valid: str,
                    comment: Optional[str],
                    header: bytes,
                    payload: bytes,
                    sig: bytes,
                    flags: Optional[Flags] = None):
    if flags is None:
      flags = []
    test = JwsEcdsaTestVector()
    test.comment = comment
    test.msg = payload
    test.result = valid
    parts = [header, payload, sig]
    test.jws = ".".join(b64encode(p).decode("utf-8") for p in parts)
    test.flags = self.key_flags[:] + self.add_flags(flags)
    self.add_test(test)

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

  def generate_wrong_primitive(self, payload: bytes):
    return
    # Generates PSS signatures. Not sure if this covers:
    # https://bugzilla.redhat.com/show_bug.cgi?id=1510156
    flag_wrong = flag.Flag(
        label="WrongPrimitive",
        bug_type=flag.BugType.WRONG_PRIMITIVE,
        description="The signature uses an incorrect signature scheme.",
        effect="The security of the signature scheme is reduced to the "
        "security of the weakest padding. Bugs in the verification are "
        "difficult to detect.",
        links=["https://bugzilla.redhat.com/show_bug.cgi?id=1510156"],
    )

    for wrong_alg in ALGORITHMS:
      if self.alg == wrong_alg:
        continue
      wrong_signer = get_signer(self.key, wrong_alg)
      for wrong_header in [
          jws.jws_header(self.alg, self.kid),
          jws.jws_header(wrong_alg, self.kid)]:
        bytes_to_sign = b64encode(wrong_header) + b"." + b64encode(payload) 
        wrong_sig = wrong_signer.sign(bytes_to_sign)
        comment = f"Using{wrong_alg}"
        self.add_signature_parts("invalid", comment, wrong_header, payload, wrong_sig, [flag_wrong])
        
    return


  def generate_broken(self, payload):
    flag_none_alg = flag.Flag(
        label="AlgIsNone",
        bug_type=flag.BugType.AUTH_BYPASS,
        description="The header contains alg:none. "
        "RFC 7515 specifies a none algorithm, which does not verify the payload. "
        "However, any correct implementation must rejecet this algorithm unless "
        "it has been specifically enabled by the user of the implementation.", 
        effect="JWS signed messages can be easily modified by changing the header.",
        links=["https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/"],
    )
    for alg, kid, sig, comment in [
        ("none", None, b"", None),  # This is the 'valid' case.
        ("NONE", None, b"", None),
        ("none", "none", b"", None),
        ("none", self.kid, b"", None)]:
      header = jws.jws_header(alg, kid)
      if comment is None:
        hstr = repr(header.decode("utf-8"))
        comment = f"Changed header to {hstr}"
      self.add_signature_parts("invalid", comment, header, payload, sig,
          [flag_none_alg])

  @type_check
  def generate_all(self, payload: bytes):
    self.generate_valid()
    # self.generate_modified(payload)
    self.generate_wrong_primitive(payload)
    self.generate_broken(payload)

  def as_struct(self, sort_by: Optional[str] = None, include_priv: bool=False) -> JsonType:
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
    pub = key.public()
    jwk_key = pub.jwk(self.alg, kid=self.kid)
    jwk_priv = key.jwk(self.alg, kid=self.kid)
    group1 = {}
    group1["type"] = self.testtype
    group1["keySize"] = key.group.n.bit_length()
    group1["alg"] = self.alg
    group1["publicKey"] = pub.as_struct()
    group1["publicKeyJwk"] = jwk_key
    group1["publicKeyPem"] = pub.pem()
    if include_priv:
      group1["privateKeyJwk"] = jwk_priv
    group1["tests"] = self.get_all_vectors(sort_by)
    return group1


class EcdsaTestGenerator(test_vector.TestGenerator):
  algorithm = "ECDSA"
  testinput = "jws"
  
  def __init__(self, alg: str):
    """Constructs a test vector generator for ECDSA signatures.

    Args:
      encoding: the encoding of the signature (e.g. "asn", "p1363" or "jwk")
      msgs: an optional list of messages, that are being signed.
      msgbuilder: an optional function that builds a message from an a public key
        and message digest
    """
    super().__init__()
    self.alg = alg
    self.test = test_vector.Test(alg)

  def generate_all(self):
    group = get_group(self.alg)
    s = prand.randrange(1, group.n, "61476a5278as123")
    key_pair = gen_ecdsa.make_key_pair(group, s)
    priv = key_pair.priv
    pub = key_pair.pub
    group = JwsEcdsaTestGroup(priv, "ecdsa_key", self.alg, self.footnotes())
    group.generate_all(b'Test')
    keyid = str(s)
    self.test.add_group(keyid, group)

def gen_jws_verify_test(namespace):
  alg = namespace.alg  # the hash function
  tv = EcdsaTestGenerator(alg)
  tv.generate_all()
  return tv.test

class JwsEcdsaProducer(producer.Producer):
  def parser(self):
    res = self.default_parser()
    res.add_argument(
        "--alg",
        type=str,
        choices=ALGORITHMS,
        default="ES256",
        help="the algorithm")
    return res

  def generate_test_vectors(self, namespace):
    return gen_jws_verify_test(namespace)


# DEPRECATED: Use Producer.produce() instead
def main(namespace):
  JwsEcdsaProducer().produce(namespace)


if __name__ == "__main__":
  JwsEcdsaProducer().produce_with_args()
