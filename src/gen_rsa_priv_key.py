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

# Generates modified RSA public keys.

import asn
import asn_fuzzing
import AST
import base64
import producer
import rsa_key
import rsa_test_keys
import test_vector
import util
import pem_util


class RsaPrivateKeyPkcs8TestVector(test_vector.TestVector):
  test_attributes = ["encoded"]
  status = "alpha"
  schema = {
      "encoded": {
          "type": AST.Asn,
          "desc": "a modified PKCS #8 encoded private key"
      },
  }

class RsaPrivateKeyPkcs8Test(test_vector.TestType):
  """Test vectors of type RsaPrivateKeyTest are intended for checking

     the decoding of PKCS #8 encoded private RSA keys for crashes.

     Since private keys are typically trusted there are not many attack
     vectors possible by modifying a private key.

     The test vectors contain modified private keys. They have no clear
     status, meaning that the behaviour while parsing a private key
     is not defined. Libraries often accept private keys with invalid
     or weak parameters, basically counting on the caller not to
     choose weak parameters.
  """
  status = "alpha"

class RsaPrivateKeyPemTestVector(test_vector.TestVector):
  test_attributes = ["encoded"]
  status = "alpha"
  schema = {
      "encoded": {
          "type": AST.Pem,
          "desc": "a modified PEM encoded private key"
      },
  }

class RsaPrivateKeyPemTest(test_vector.TestType):
  """Test vectors of type RsaPrivateKeyTest are intended for checking

     the decoding of PEM encoded private RSA keys for crashes.

     Since private keys are typically trusted there are not many attack
     vectors possible by modifying a private key.

     The test vectors contain modified private keys. They have no clear
     status, meaning that the behaviour while parsing a private key
     is not defined. Libraries often accept private keys with invalid
     or weak parameters, basically counting on the caller not to
     choose weak parameters.
  """
  status = "alpha"


class RsaPrivateKeyPkcs8TestGroup(test_vector.TestGroup):
  vectortype = RsaPrivateKeyPkcs8TestVector
  testtype = RsaPrivateKeyPkcs8Test
  testdoc = "Tests the decoding of RSA keys."
  status = "alpha"
  schema = {
      "privateKey": {
          "type": rsa_key.RsaPrivateKey,
          "desc": "the private key",
      },
      "publicKeyAsn": {
          "type": AST.Der,
          "short": "the corresponding X509 encoded public key",
          "desc": "The corresponding X509 encoded public key."
                  "One way to use the test vectors is to encrypt and decrypt"
                  "a message and determine whether the modified private key"
                  "influences the result.",
      },
      "privateKeyPkcs8": {
          "type": AST.Der,
          "short": "the original private.",
          "desc": "The original valid private key encoded with PKCS #8. "
                  "The test vectors contain modified versions of this key."
      },
  }

  def __init__(self, private):
    super().__init__()
    self.private = private
    self.public = private.publicKey()

  def as_struct(self, sort_by=None):
    if sort_by is None:
      sort_by = "comment"
    group = {}
    group["type"] = self.testtype
    group["privateKey"] = self.private.as_struct()
    group["privateKeyPkcs8"] = asn.encode_hex(self.private.privateKeyPkcs8())
    group["publicKeyAsn"] = asn.encode_hex(self.public.publicKeyAsn())
    group["tests"] = self.get_all_vectors(sort_by=sort_by)
    return group

class RsaPrivateKeyPemTestGroup(test_vector.TestGroup):
  vectortype = RsaPrivateKeyPemTestVector
  testtype = RsaPrivateKeyPemTest
  testdoc = "Tests the decoding of RSA keys."
  status = "alpha"
  schema = {
      "privateKey": {
          "type": rsa_key.RsaPrivateKey,
          "desc": "the private key",
      },
      "publicKeyPem": {
          "type": AST.Pem,
          "short": "the corresponding PEM encoded public key",
          "desc": "The corresponding PEM encoded public key."
                  "One way to use the test vectors is to encrypt and decrypt"
                  "a message and determine whether the modified private key"
                  "influences the result.",
      },
      "privateKeyPem": {
          "type": AST.Pem,
          "short": "the original private.",
          "desc": "The original valid private key encoded with PEM. "
                  "The test vectors contain modified versions of this key."
      },
  }

  def __init__(self, private):
    super().__init__()
    self.private = private
    self.public = private.publicKey()

  def as_struct(self, sort_by=None):
    if sort_by is None:
      sort_by = "comment"
    group = {}
    group["type"] = self.testtype
    group["privateKey"] = self.private.as_struct()
    group["privateKeyPem"] = self.private.privateKeyPem()
    group["publicKeyPem"] = self.public.publicKeyPem()
    group["tests"] = self.get_all_vectors(sort_by=sort_by)
    return group



class RsaPrivateKeyTestGenerator(test_vector.TestGenerator):
  algorithm = "RSA"
  def __init__(self, encoding):
    super().__init__()
    self.test = test_vector.Test(self.algorithm)
    self.encoding = encoding

  def new_test_group(self, key):
    if self.encoding == "asn":
      group = RsaPrivateKeyPkcs8TestGroup(key)
    elif self.encoding == "pem":
      group = RsaPrivateKeyPemTestGroup(key)
    else:
      raise ValueError("Encoding not supported:" + self.encoding)
    return group


  def generate_modified_pkcs8(self, key):
    privKeyAsn = key.privateKeyPkcs8()
    for x in asn_fuzzing.generate_hex(privKeyAsn):
      yield x
    for struct, comment in key.modifiedPkcs8():
      yield comment, asn.encode_hex(struct)

  def generate_modified_pem(self, key):
    for comment, asn in self.generate_modified_pkcs8(key):
      yield comment, pem_util.private_key_pem(bytes.fromhex(asn))

  def generate_modified(self, key):
    if self.encoding == "asn":
      yield from self.generate_modified_pkcs8(key)
    elif self.encoding == "pem":
      yield from self.generate_modified_pem(key)
    else:
      raise ValueError("unsupported encoding")

  @util.type_check
  def generateGroup(self, key: rsa_key.RsaPrivateKey):
    group = self.new_test_group(key)
    self.test.add_group(key.id, group)
    modified = self.footnote(
        "modified",
        """The RSA key has been modified. Some libraries ignore corrupted or
         redundant values and recompute missing values. Thus accepting such
         modifications as long as they do not change the behaviour of
         the key is often acceptable.""")
    for bugtype, encoded in self.generate_modified(key):
      if self.encoding == "asn":
        test = RsaPrivateKeyPkcs8TestVector()
      elif self.encoding == "pem":
        test = RsaPrivateKeyPemTestVector()
      else:
        raise ValueError("Unsupported encoding:" + self.encoding)
      test.encoded = encoded
      if bugtype is None:
        test.comment = "unchanged"
        test.result = "valid"
      else:
        test.comment = bugtype
        test.result = "acceptable"
        test.flags = [modified]
      group.add_test(test)


class RsaPrivateKeyProducer(producer.Producer):

  def parser(self):
    res = self.default_parser()
    res.add_argument(
        "--encoding",
        type=str,
        choices=["asn", "pem"],
        help="the encoding of the RSA public key",
        default="asn")
    res.add_argument(
        "--size",
        type=int,
        help="the size of the RSA key in bits",
        default=2048)
    res.add_argument(
        "--three_primes",
        action="store_true",
        help="uses three prime RSA keys if set")
    return res

  def generate_test_vectors(self, namespace):
    three_primes = getattr(namespace, "three_primes", False)
    tv = RsaPrivateKeyTestGenerator(namespace.encoding)
    tv.generateGroup(
        rsa_test_keys.get_test_key(namespace.size, three_primes=three_primes))
    return tv.test


# DEPRECATED: Use Producer.produce() instead
def main(namespace):
  RsaPrivateKeyProducer().produce(namespace)


if __name__ == "__main__":
  RsaPrivateKeyProducer().produce_with_args()
