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

import gen_rsa_signature
import test_vector
import AST
import rsa_key
import util
import flag
import producer
import rsa_test_keys
import rsassa_pkcs1
import rsa_pss
import base64
import hlib
import modify
import gen_rsa_signature
import jws_test_vector
from util import type_check
from collections.abc import Iterator
from typing import Any, Optional, Union

JsonType = Any
Flags = list[flag.Flag]
Signer = Union[rsassa_pkcs1.RsassaPkcs1, rsa_pss.RsassaPss]
RsaKey = Union[rsa_key.RsaPrivateKey, rsa_key.RsaPublicKey]

PKCS1_ALGORITHMS = ["RS256", "RS384", "RS512" ]
PSS_ALGORITHMS = ["PS256", "PS384", "PS512" ]
ALGORITHMS = PKCS1_ALGORITHMS + PSS_ALGORITHMS

def get_md(alg: str) -> str:
  if alg in ["RS256", "PS256"]:
    return "SHA-256"
  elif alg in ["RS384", "PS384"]:
    return "SHA-384"
  elif alg in ["RS512", "PS512"]:
    return "SHA-512"
  else:
    raise ValueError("Unknown algorithm:" + alg)

def get_slen(alg: str) -> str:
  if alg == "PS256":
    return 32
  if alg == "PS384":
    return 48
  if alg == "PS512":
    return 64
  else:
    raise ValueError("Unknown algorithm:" + alg) 

def b64encode(s: bytes) -> bytes:
  w = base64.urlsafe_b64encode(s)
  w = w.replace(b"=",b"")
  return w

def get_signer(key:rsa_key.RsaPrivateKey, alg: str) -> Signer:
  """Returns a signer for the underlying primitive"""
  md = get_md(alg)
  if alg in PKCS1_ALGORITHMS:
    return rsassa_pkcs1.RsassaPkcs1(key, md)
  elif alg in PSS_ALGORITHMS:
    slen = get_slen(alg)
    return rsa_pss.RsassaPss(
         key=key, md=md, mgf="MGF1", mgf_md=md, s_len=slen)
  else:
    raise ValueError("unsupported algorithm:" + alg)

def jws_header(alg:str, kid: Optional[str]) -> bytes:
    if kid is not None:
      h = f'"alg":"{alg}","kid":"{kid}"'
    else:
      h = f'"alg":"{alg}"'
    hs = "{" + h + "}"
    return hs.encode("utf-8")

class JwsRsaTestGenerator(test_vector.TestGenerator):
  pass

JwsRsaTestVector = jws_test_vector.JwsTestVector

class JwsRsaVerify(test_vector.TestType):
  """Test vectors of class JwsRsaVerify are intended for checking the
     verification of RSA PKCS #1 v 1.5 signatures.

     RSA signature verification should generally be very strict about
     checking the padding. Because of this most RSA signatures with
     a slightly modified padding have "result" : "invalid". Only a
     small number of RSA signatures implementing legacy behaviour
     (such as a missing NULL in the encoding) have 
     "result" : "acceptable".
  """

class JwsRsaTestGroup(test_vector.TestGroup):
  algorithm = "RSA1_5"
  testtype = JwsRsaVerify
  vectortype = JwsRsaTestVector
  schema = {
      "kid" : {
          "type": str,
          "desc": "the kid of the key"
      },
      "publicKey": {
          "type": rsa_key.RsaPublicKey,
          "desc": "the public key",
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

  def header(self)-> bytes:
    return jws_header(self.alg, self.kid)
    
  def bytes_to_sign(self, payload: bytes) -> bytes:
    return b64encode(self.header()) + b"." + b64encode(payload) 
    
  @util.type_check
  def raw_sign(self, bytes_to_sign: bytes) -> bytes:
    return self.signer.sign(bytes_to_sign)

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
    test = JwsRsaTestVector()
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

    test = JwsRsaTestVector()
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
    test = JwsRsaTestVector()
    test.comment = comment
    test.msg = payload
    test.result = valid
    parts = [header, payload, sig]
    test.jws = ".".join(b64encode(p).decode("utf-8") for p in parts)
    test.flags = self.key_flags[:] + self.add_flags(flags)
    self.add_test(test)

  def generate_modified_pkcs1(self, payload):
    bytes_to_sign = self.bytes_to_sign(payload)
    md = get_md(self.alg)
    for bug, sig, flags, validity in gen_rsa_signature.generate_modified(bytes_to_sign, self.key, md):
      self.add_signature(validity, bug, payload, sig, flags)

  def generate_modified_pss(self, payload):
    modified_signature = flag.Flag(
        label="ModifiedSignature",
        bug_type=flag.BugType.CAN_OF_WORMS,
        description="The test vector contains an invalid signature. "
        "This signature was obtained by modifying the padding before "
        "signing it.",
        effect="Accepting modified paddings may indicate that the "
        "verification is implemented by decoding the encoded message "
        "EM instead of encoding the hash as described in Section 8.2.2 "
        "of RFC 8017. A carelessly implemented decoding operation "
        "can lead to signature forgeries.")
    bytes_to_sign = self.bytes_to_sign(payload)
    for sig, comment in modify.CaseIter(
      lambda case: self.signer.modified_sign(bytes_to_sign, case)):
        if self.signer.verify(bytes_to_sign, sig):
          result = "valid"
          flags = []
        else:
          result = "invalid"
          flags = [modified_signature]
        self.add_signature(result, comment, payload, sig, flags)
  
  @type_check
  def generate_modified(self, payload: bytes):
    """Generates modified signatures for a given payloid"""
    if self.alg in PKCS1_ALGORITHMS:
      self.generate_modified_pkcs1(payload)
    elif self.alg in PSS_ALGORITHMS:
      self.generate_modified_pss(payload)

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
          jws_header(self.alg, self.kid),
          jws_header(wrong_alg, self.kid)]:
        try:
          bytes_to_sign = b64encode(wrong_header) + b"." + b64encode(payload) 
          wrong_sig = wrong_signer.sign(bytes_to_sign)
          comment = f"Using{wrong_alg}"
          self.add_signature_parts("invalid", comment, wrong_header, payload, wrong_sig, [flag_wrong])
        except ValueError as ex:
          pass
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
      header = jws_header(alg, kid)
      if comment is None:
        hstr = repr(header.decode("utf-8"))
        comment = f"Changed header to {hstr}"
      self.add_signature_parts("invalid", comment, header, payload, sig,
          [flag_none_alg])

  @type_check
  def generate_all(self, payload: bytes):
    self.generate_valid()
    self.generate_modified(payload)
    self.generate_wrong_primitive(payload)
    self.generate_broken(payload)

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
    jwk_key = pub.publicKeyJwk(use="sig", alg=self.alg, kid=self.kid)
    jwk_priv = key.privateKeyJwk(use="sig", alg=self.alg, kid=self.kid)
    group1 = {}
    group1["type"] = self.testtype
    group1["keySize"] = key.n.bit_length()
    group1["alg"] = self.alg
    group1["publicKey"] = pub.as_struct()
    group1["publicKeyJwk"] = jwk_key
    group1["privateKeyJwk"] = jwk_priv
    group1["tests"] = self.get_all_vectors(sort_by)
    return group1


# TODO: precompute keys for edge cases
#   The edge cases for PKCS #1.5 signatures don't work here, since the
#   signatures are computed over header.payload instead of just the header.
#

def gen_rsa_sign_test(namespace):
  raise ValueError("not implemented")

def gen_rsa_verify_test(namespace):
  size = namespace.size  # modulus size in bits
  alg = namespace.alg  # the hash function
  md = get_md(alg)
  t = test_vector.Test(alg)
  if size < 1024:
    raise ValueError("RSA key size should be given in bits")
  e = getattr(namespace,"e", 65537)
  if e == 65537:
    key = rsa_test_keys.get_test_key(size, md)
  else:
    key = rsa_test_keys.get_test_key(size, md, e=e, generate_new=True)
  key_id = f"{alg}_{size}"
  # ...
  g = JwsRsaTestGroup(key, key_id, alg, t.footnotes())
  g.generate_all(b"123400")
  t.add_group("g", g)
  return t


class JwsRsaProducer(producer.Producer):

  def parser(self):
    res = self.default_parser()
    res.add_argument(
        "--size", type=int, default=2048, help="the size of the RSA key in bits")
    res.add_argument(
        "--alg",
        type=str,
        choices=ALGORITHMS,
        default="RS256",
        help="the algorithm")
    res.add_argument(
        "--e",
        type=int)
    res.add_argument(
        "--op",
        type=str,
        choices=["sign", "verify"],
        default="verify",
        help="Determines whether the test vectors are used to test signature"
        " or signature verification.")
    return res

  def generate_test_vectors(self, namespace):
    if namespace.op == "sign":
      return gen_rsa_sign_test(namespace)
    elif namespace.op == "verify":
      return gen_rsa_verify_test(namespace)


# DEPRECATED: Use Producer.produce() instead
def main(namespace):
  JwsRsaProducer().produce(namespace)


if __name__ == "__main__":
  JwsRsaProducer().produce_with_args()
