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
import AST
import modify
import flag
import producer
import rsa_key
import rsaes_pkcs1
import rsaes_pkcs1_special
import rsa_test_keys
import test_vector
from typing import Optional
import util

class RsaesPkcs1TestVector(test_vector.TestVector):
  test_attributes = ["msg", "ct"]
  schema = {
      "msg": {
          "type": AST.HexBytes,
          "desc": "The encrypted message",
      },
      "ct": {
          "type": AST.HexBytes,
          "desc": "An encryption of msg",
      },
  }

  def testrep(self):
    return repr(self.ct)

class RsaesPkcs1Decrypt(test_vector.TestType):
  """Test vectors of type RsaesPkcs1Decrypt are intended to check the decryption

     of RSA encrypted ciphertexts.

     The test vectors contain ciphertexts with invalid format (i.e. incorrect
     size) and test vectors with invalid padding. Hence the test vectors
     are a bit inconvenient to detect padding oracles. One potential plan
     is to generate separate, new files that only contain ciphertexts with
     invalid paddings.
  """

class RsaesPkcs1TestGroup(test_vector.TestGroup):
  algorithm = "RSAES-PKCS1-v1_5"
  testtype = RsaesPkcs1Decrypt
  vectortype = RsaesPkcs1TestVector
  schema = {
      "keySize": {
          "type": int,
          "desc": "The key size in bits",
      },
      "privateKey": {
          "type": rsa_key.RsaPrivateKey,
          "desc": "the private key",
      },
      "privateKeyPkcs8": {
          "type": AST.Der,
          "desc": "Pkcs 8 encoded private key."
      },
      "privateKeyPem": {
          "type": AST.Pem,
          "desc": "Pem encoded private key"
      },
      "privateKeyJwk": {
          "type": rsa_key.JwkRsaPrivateKey,
          "desc": "JWK encoded private key",
          "since": "0.7",
          "optional": True,
      },
  }

  def __init__(self, key, test: test_vector.Test):
    super().__init__()
    self.key = key
    self.crypter = rsaes_pkcs1.RsaesPkcs1(key)
    self.key_flags = []  # list[flag.Flag]
    self.test = test  # TODO: shouldn't be here

  @util.type_check
  def add_vector(self,
                 message: bytes,
                 ct: Optional[bytes] = None,
                 comment: str = "",
                 flags: Optional[list[flag.Flag]] = None):
    if flags is None:
      flags = []
    else:
      flags = flags[:]
    flags += self.key_flags

    test = RsaesPkcs1TestVector()
    if ct is None:
      ct = self.crypter.encrypt(message)
    test.flags = self.key_flags[:]
    try:
      decrypted = self.crypter.decrypt(ct)
      if decrypted != message:
        # This case happens when a modification leads to a valid
        # plaintext. We could either add this as a valid test
        # vector or just ignore it.
        return
      test.result = "valid"
    except rsaes_pkcs1.DecryptionError:
      invalid_padding = flag.Flag(
          label="InvalidPkcs1Padding",
          bug_type=flag.BugType.CONFIDENTIALITY,
          description="This is a test vector with an invalid PKCS #1 padding. "
          "Implementations must ensure that different error "
          "conditions cannot be distinguished, since the "
          "information about the error condition can be used "
          "for a padding oracle attack. (RFC 8017 Section 7.2.2).")
      flags.append(invalid_padding)
      test.result = "invalid"
    except ValueError:
      # Probably not as bad as invalid PKCS #1 padding.
      # Needs analysis.
      test.result = "invalid"
      invalid_ct_format = flag.Flag(
          label="InvalidCiphertextFormat",
          bug_type=flag.BugType.CONFIDENTIALITY,
          description="This is a test vector with an invalid ciphertext. ")
      flags.append(invalid_ct_format)
    if flags: test.flags += flags
    test.comment = comment
    test.msg = message
    test.ct = ct
    test.flags = self.test.footnotes().add_flags(flags)
    self.add_test(test)

  def generate_modified(self, message: bytes):
    """Generates modified ciphertexts for message"""
    for ct, comment, flags in modify.CaseIterWithFlags(
        lambda case: self.crypter.modified_encrypt(message, True, case)):
      self.add_vector(message, ct, comment=comment, flags=flags)

  def generate_valid(self):
    messages = [
        b"",
        bytes(20),
        b"Test",
        b"123400",
        b"Message",
        b"a",
        bytes(range(224, 256)),
    ]
    for m in messages:
      if len(m) < self.crypter.max_message_size():
        comment = f"Message of length {len(m)}."
        self.add_vector(m, comment=comment, flags=[flag.NORMAL])
    max_msg = b"x" * self.crypter.max_message_size()
    self.add_vector(
        max_msg,
        comment="Longest valid message size",
        flags=[flag.NORMAL])

  def generate_edgecases(self):
    pass

  def generate_all(self, message):
    self.generate_valid()
    self.generate_modified(message)
    self.generate_edgecases()

  def as_struct(self, sort_by=None):
    key = self.key
    group = {}
    group["type"] = self.testtype
    group["privateKey"] = key.as_struct()
    # Note(bleichen): private keys use pkcs1algorithm = rsaEncryption
    group["privateKeyPkcs8"] = asn.encode_hex(self.crypter.privateKeyPkcs8())
    group["privateKeyPem"] = key.privateKeyPem()
    group["privateKeyJwk"] = key.privateKeyJwk("RSA1_5")
    group["keySize"] = key.n.bit_length()
    group["tests"] = self.get_all_vectors(sort_by)
    return group

def gen_rsa_pkcs1(size):
  # Sanity check: Size is in bits and must be defined
  assert size >= 512
  t = test_vector.Test("RSAES-PKCS1-v1_5")
  key = rsa_test_keys.get_test_key(size)
  g = RsaesPkcs1TestGroup(key, t)
  g.generate_all(b"Test")
  t.add_group("g", g)
  # edge cases with constructed keys.
  flag_special_case = flag.Flag(
      label="SpecialCase",
      bug_type=flag.BugType.EDGE_CASE,
      description="The test vector contains a constructed special case. "
      "Such special cases check for arithmetic errors in the implementation. ")
  for key, ct_hex, pt_hex, comment in rsaes_pkcs1_special.SPECIAL_CASES:
    if key.n.bit_length() == size:
      g = RsaesPkcs1TestGroup(key, t)
      g.add_vector(
          message=bytes.fromhex(pt_hex),
          ct=bytes.fromhex(ct_hex),
          comment=comment,
          flags=[flag_special_case])
      t.add_group(str(key.n), g)
  return t

def gen_rsa_pkcs1_misc():
  t = test_vector.Test("RSAES-PKCS1-v1_5")
  for key in rsa_test_keys.rsa_pkcs1_keys:
    if key.n.bit_length() < 1024:
      continue
    g = RsaesPkcs1TestGroup(key, t)
    g.generate_valid()
    idx = "rsa_%d"%key.n.bit_length()
    t.add_group(idx, g)
  return t


class RsaesPkcs1Producer(producer.Producer):

  def parser(self):
    res = self.default_parser()
    res.add_argument(
        "--size",
        type=int,
        default=0,
        help="the key size of the RSA key in bits")
    return res

  def generate_test_vectors(self, namespace):
    if namespace.size == 0:
      return gen_rsa_pkcs1_misc()
    else:
      return gen_rsa_pkcs1(namespace.size)


# DEPRECATED: Use Producer.produce() instead
def main(namespace):
  RsaesPkcs1Producer().produce(namespace)


if __name__ == "__main__":
  RsaesPkcs1Producer().produce_with_args()
