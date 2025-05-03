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

import amd_sev_rsa
import asn
import AST
import flag
import modify
import producer
import rsa_key
import rsa_pss
import rsassa_pkcs1
import rsa_test_keys
import special_values
import sys
import test_vector
from typing import Optional
import util

# The algorithms defined in RFC 8017, Section A.2.1.
# This set will be extended in
# https://tools.ietf.org/id/draft-ietf-lamps-pkix-shake-12.html
# However, the format of the parameters may change.
OAEP_PSS_DIGEST_ALGORITHMS = [
  "SHA-1", "SHA-224", "SHA-256", "SHA-384", "SHA-512",
  "SHA-512/224", "SHA-512/256"]

SIGNATURE_ENCODINGS = ["osp", "amd_sev"]

MGF = ["MGF1", "SHAKE128", "SHAKE256"]
class RsassaPssTestVector(test_vector.TestVector):
  test_attributes = ["msg", "sig"]
  schema = {
     "msg" : {
         "type" : AST.HexBytes,
         "desc" : "The message to sign",
     },
     "sig" : {
         "type" : AST.HexBytes,
         "desc" : "a signature for msg",
     }
  }

  def testrep(self):
    return repr(self.sig) + repr(self.msg)

class RsassaPssVerify(test_vector.TestType):
  """Test vectors of class RsassaPssVerify are intended for checking the
     verification of RSASSA-PSS signatures.

     RSA signature verification should generally be very strict about
     checking the padding. Because of this RSASSA-PSS signatures with
     a modified padding have "result" : "invalid".
  """

class RsassaPssTestGroup(test_vector.TestGroup):
  algorithm = "RSASSA-PSS"
  testtype = RsassaPssVerify
  vectortype = RsassaPssTestVector

  schema = {
      "publicKey": {
          "type": rsa_key.RsaPublicKey,
          "desc": "the public key",
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
      "keySize": {
          "type": int,
          "desc": "the size of the modulus in bits",
      },
      "sha": {
          "type": AST.MdName,
          "desc": "The hash function for hasing the message."
      },
      "sLen": {
          "type": int,
          "desc": "The length of the salt in bytes",
      },
      "mgf": {
          "type": str,
          "desc": "the message generating function (e.g. MGF1 or SHAKE128)",
      },
      "mgfSha": {
          "type":
              AST.MdName,
          "desc":
              """The hash function used for the message generating
                   function."""
      }
  }

  @util.type_check
  def __init__(self,
               key,
               md: Optional[str],
               mgf: str,
               mgf_md: Optional[str],
               slen: Optional[int],
               specify_params: bool,
               encoding: str,
               save_private: bool = False,
               allow_variable_length_salt: bool = False,
               footnotes=None,
               key_flags=[]):
    super().__init__()
    self.key = key
    self.signer = rsa_pss.RsassaPss(
        key,
        md,
        mgf,
        mgf_md,
        slen,
        specify_params,
        allow_variable_length_salt=allow_variable_length_salt)
    self.mgf = mgf
    self.md = md
    self.mgf_md = mgf_md
    self.s_len = slen
    if self.mgf in ("SHAKE128", "SHAKE256"):
      self.s_len = self.signer.s_len
      self.md = mgf
      self.mgf_md = ""
    self.specify_params = specify_params
    # set the flags for the key
    self.key_flags = key_flags[:]
    self.encoding = encoding
    self.save_private = save_private
    if footnotes is None:
      raise ValueError("footnotes cannot be None")
    self.footnotes = footnotes

  # TODO: All the stuff below belongs into the Generator class.
  @util.type_check
  def add_signature(self,
                    message: bytes,
                    sig: Optional[bytes] = None,
                    comment: str = "",
                    flags: list[flag.Flag] = []):
    """Adds a signature to the set of test vectors.

    Args:
      message: the message that is signed
      sig: the signature. If None then a valid signature is generated
      comment: a comment describing the test case
    """
    if sig is None:
      sig = self.signer.sign(message)
    test = RsassaPssTestVector()
    test.flags = self.footnotes.add_flags(self.key_flags + flags)
    try:
      if self.signer.verify(message, sig):
        test.result = "valid"
      else:
        test.result = "invalid"
    except Exception as e:
      test.result = "invalid"
    test.comment = comment
    test.msg = message
    if self.encoding == "amd_sev":
      try:
        sig = amd_sev_rsa.encode_rsa_pss_signature(sig)
      except Exception as e:
        # Encoding exceptions are expected for signatures larger than 512 bytes,
        # such as the signature generated by "appending 0"s to signature" test.
        # Skip test in this case.
        return
    elif self.encoding == "osp":
      # Signature already encoded in octet sequence.
      pass
    test.sig = sig
    self.add_test(test)

  @util.type_check
  def generate_modified(self, message: bytes):
    """Generates modified signatures for message.

    This method generates mostly invalid signatures where the
    padding or other steps in the signature generation are
    incorrect.

    Args:
      message: the message that is signed.
    """
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
    for sig, comment in modify.CaseIter(
      lambda case: self.signer.modified_sign(message, case)):
      self.add_signature(
          message, sig=sig, comment=comment, flags=[modified_signature])

  def generate_valid(self, messages: list[bytes]):
    for m in messages:
      self.add_signature(m, comment="valid signature", flags=[flag.NORMAL])

  def generate_edge_cases(self, restricted: Optional[list[bytes]] = None):
    """Generates edge cases for the hash function.

    Args:
      restricted: if empty or None then any edge case will be produced
                otherwise only messages in this lists will be produced.
    """
    flag_special_hash = flag.Flag(
        label="SpecialCaseHash",
        bug_type=flag.BugType.EDGE_CASE,
        description="The test vector contains a signature where the hash of "
        "the message is a special case, e.g., contains a long run of 0 or 1 "
        "bits.")

    for m in special_values.edge_case_msg_for_hash(self.md):
      if not restricted or m in restricted:
        self.add_signature(
            m, comment="special case for hash", flags=[flag_special_hash])

  def generate_wrong_primitive(self, message: bytes):
    """Generates PKCS #1 v1.5 signatures instead of PSS signatures.

    This is motivated by the following bug description:
    https://bugzilla.redhat.com/show_bug.cgi?id=1510156
    Not sure however if the bug is covered.

    Args:
      message: the message to sign
    """
    wrong_primitive = flag.Flag(
        label="WrongPrimitive",
        bug_type=flag.BugType.WRONG_PRIMITIVE,
        description="The signature is a valid PKCS #1 v1.5 signature. "
        "Expected was an RSASSA-PSS signature. Implementations should not "
        "accept multiple signature schemes.")
    for md in sorted({self.md, self.mgf_md, "SHA-256"}):
      if md in ("", "SHAKE128", "SHAKE256"):
        continue
      signer = rsassa_pkcs1.RsassaPkcs1(self.key, md)
      sig = signer.sign(message)
      self.add_signature(
          message,
          sig=sig,
          comment=f"PKCS #1 v1.5 signature with {md}",
          flags=[wrong_primitive])

  def generate_all(self, msgs: Optional[list[bytes]]):
    """Generates all test vectors.

    Args:
      msgs: an optional list of messages that are signed.
            Specifying a list means that precomputed special cases
            not in the list will not be used for test vectors.
            Hence, using msgs=None is preferable at this point.
    """
    if not msgs:
      msg0 = b"123400"
      messages = [
        b"",
        bytes(20),
        b"Test",
        b"123400",
        b"Message",
        b"a",
        bytes(range(224,256))]
    else:
      messages = msgs
      msg0 = messages[0]
    self.generate_valid(messages)
    self.generate_edge_cases(msgs)
    self.generate_modified(msg0)
    self.generate_wrong_primitive(msg0)

  def as_struct(self, sort_by = None):
    group = {}
    pub = self.signer.public_key()
    group["type"] = self.testtype
    group["keySize"] = pub.n.bit_length()
    group["sha"] = self.md
    group["mgf"] = self.mgf
    group["mgfSha"] = self.mgf_md
    group["sLen"] = self.s_len
    group["publicKey"] = pub.as_struct()
    if self.save_private:
      priv = self.signer.key
      group["privateKey"] = priv.as_struct()
    group["publicKeyAsn"] = asn.encode_hex([pub.n, pub.e])
    # TODO: Is slen and mgf part of the key?
    group["publicKeyDer"] = asn.encode_hex(self.signer.public_key_asn())
    # Not using X509 here.
    group["publicKeyPem"] = self.signer.public_key_pem()
    group["tests"] = self.get_all_vectors(sort_by)
    return group

def gen_rsa_pss(namespace):
  size = namespace.size
  mgf = namespace.mgf
  md = getattr(namespace, "sha", "")
  slen = getattr(namespace, "slen", None)
  mgf_md = getattr(namespace, "mgf_sha", "")
  specify_params = getattr(namespace, "specify_pkcs1algorithm", False)
  messages = getattr(namespace, "msgs", None)
  encoding = getattr(namespace, "encoding", "osp")
  allow_variable_length_salt = getattr(namespace, "allow_variable_length_salt",
                                       False)
  if mgf_md == "":
    mgf_md = md
  t = test_vector.Test("RSASSA-PSS")
  if size == 0:
    # TODO: Maybe deprecate this.
    # If size == 0 use some defaults
    g = RsassaPssTestGroup(
        rsa_test_keys.rsa_test_key2,
        md,
        mgf,
        mgf_md,
        slen,
        specify_params,
        encoding,
        allow_variable_length_salt=allow_variable_length_salt,
        footnotes=t.footnotes())
    g.generate_all(messages or [b"Test"])
    t.add_group("g", g)
    for key in rsa_test_keys.rsa_signature_keys:
      if key.n.bit_length() < 1024:
        continue
      g = RsassaPssTestGroup(
          key,
          md,
          mgf,
          mgf_md,
          slen,
          specify_params,
          encoding,
          footnotes=t.footnotes())
      g.generate_valid([b"123400"])
      g.generate_edge_cases()
      idx = f"rsa_{key.n.bit_length()}_{key.md}_{mgf}_{slen}"
      t.add_group(idx, g)
  else:
    id_md = md or mgf
    assert id_md
    key = rsa_test_keys.get_test_key(size, id_md)
    g = RsassaPssTestGroup(
        key,
        md,
        mgf,
        mgf_md,
        slen,
        specify_params,
        encoding,
        allow_variable_length_salt=allow_variable_length_salt,
        footnotes=t.footnotes())
    g.generate_all(messages)
    t.add_group("g", g)
  return t

def gen_amd_sev_rsa_pss_signatures(namespace):
  def self_signed_builder(key, md: str) -> bytes:
    ver = b"\x01\x00\x00\x00"
    api_mj = b"\x00"
    api_mn = b"\x18"
    reserved0 = b"\x00\x00"
    usage = b"\x01\x10\x00\x00" # OCA
    if md == "SHA-256":
      algo = b"\x01\x00\x00\x00"
    elif md == "SHA-384":
      algo = b"\x01\x01\x00\x00"
    else:
      raise Exception("Unsupported md " + md)
    pubkey = amd_sev_rsa.encode_rsa_public(key)
    return ver + api_mj + api_mn + reserved0 + usage + algo + pubkey

  size = namespace.size
  mgf = namespace.mgf
  md = getattr(namespace, "sha", "")
  slen = getattr(namespace, "slen", None)
  mgf_md = getattr(namespace, "mgf_sha", "")
  specify_params = getattr(namespace, "specify_pkcs1algorithm", False)
  allow_variable_length_salt = getattr(namespace, "allow_variable_length_salt",
                                       False)
  if mgf_md == "":
    mgf_md = md
  if size == 0:
    size = 2048
  t = test_vector.Test("RSASSA-PSS")
  if size not in [2048, 4096]:
    raise ValueError("Unsupported size: %d" % (size))
  id_md = md or mgf
  assert id_md
  key = rsa_test_keys.get_test_key(size, id_md)
  encoding = "amd_sev"
  save_private = True
  g = RsassaPssTestGroup(
      key,
      md,
      mgf,
      mgf_md,
      slen,
      specify_params,
      encoding,
      save_private,
      allow_variable_length_salt,
      footnotes=self.footnotes())
  msg = self_signed_builder(key, md)
  g.generate_all([msg])
  t.add_group("g", g)
  return t


class RsaPssProducer(producer.Producer):

  def parser(self):
    """Sample usages:
    Generate test vectors for a specified paremeter set

    $ python gen_rsa_pss_test.py --size=2048 --sha=SHA-256 --mgf=MGF1 \
       --mgf_sha=SHA-256 --slen=32 --out=filename

    RFC 8692 specifies the parameters when using SHAKE128 or SHAKE256. Hence
    the following is sufficient to specify all necessary parameters.

    $ python gen_rsa_pss_test.py --size=2048 --mgf=SHAKE128 --out=filename
    """
    res = self.default_parser()
    res.add_argument(
        "--size", type=int, default=0, help="the size of the RSA key in bits")
    res.add_argument(
        "--sha",
        type=str,
        choices=[""] + OAEP_PSS_DIGEST_ALGORITHMS,
        help="the hash function for message. Leave empty when using SHAKE.")
    res.add_argument(
        "--mgf",
        type=str,
        choices=MGF,
        default="MGF1",
        help="the name of the mask generation function")
    res.add_argument(
        "--mgf_sha",
        type=str,
        choices=[""] + OAEP_PSS_DIGEST_ALGORITHMS,
        default="",
        help="the hash function for mask generation funtion."
        "This is the same as --sha if not specified.")
    res.add_argument(
        "--slen", type=int, help="The length of the salt in bytes.")
    res.add_argument(
        "--specify_pkcs1algorithm",
        action="store_true",
        help="Specifies that the PKCS1Algorithm (as defined in Appendix A of"
        " RFC 8017) has OID id-RSASSA-PSS and that the mgf parameters"
        " are specified. Otherwise OID rsaEncryption is is used."
        " Many crypto libraries do not accept RSA-PSS parameters"
        " in the keys.")
    res.add_argument(
        "--allow_variable_length_salt",
        action="store_true",
        help="Specifies that the verification of RSASSA-PSS accepts"
        " signatures where the salt length differs from specified"
        " length. Some implementations allow this behaviour.")
    res.add_argument(
        "--msgs",
        type=str,
        nargs="+",
        help="Optional: a list of messages to sign. The messages are"
        " represented in hexadecimal")
    res.add_argument(
        "--encoding",
        type=str,
        help="Encoding of the signatures",
        choices=SIGNATURE_ENCODINGS,
        default="osp")
    return res

  def generate_test_vectors(self, namespace):
    specify_pkcs1algorithm = getattr(namespace, "specify_pkcs1algorithm", False)
    if getattr(namespace, "encoding", "osp") == "osp":
      test = gen_rsa_pss(namespace)
    elif namespace.encoding == "amd_sev":
      test = gen_amd_sev_rsa_pss_signatures(namespace)
    else:
      raise ValueError("Unknown encoding:" + namespace.encoding)
    if specify_pkcs1algorithm:
      test.header.append(
          "keyDer contains the MGF parameters specified in Appendix A of"
          " RFC 8017.")
    return test


# DEPRECATED: Use Producer.produce() instead
def main(namespace):
  RsaPssProducer().produce(namespace)


if __name__ == "__main__":
  RsaPssProducer().produce_with_args()
