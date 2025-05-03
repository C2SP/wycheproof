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
import asn_parser
import AST
import pem_util
import producer
import rsa_key
import rsa_test_keys
import test_vector
import util

def rsa_generate_modified_public_keys(pub):
  """Generates modified public keys.
  
  Args:
    pub: a public key
  Yeilds:
    tuples (encoding, comment, validity) where encoding is modified public key
    and comment describes the modification.
  """

  def modified_key():
    n, e = pub.n, pub.e
    yield 0, e, 'n=0', "invalid"
    yield -n, e, "negative n", "invalid"
    yield n, 0, 'e=0', "invalid"
    yield n, 1, 'e=1', "invalid"
    yield n, 2, 'e=2', "invalid"
    yield n, -e, 'negative e', "invalid"

  pubKeyAsn = pub.publicKeyAsn()
  for comment, encoded in asn_fuzzing.generate(pubKeyAsn):
    if comment is None:
      yield encoded, "unmodified", "valid"
    else:
      try:
        # TODO: Maybe, parse(encoded, strict=False) is enough.
        asn_parser.parse(encoded)
        # TODO: add more checks
        yield encoded, comment, "acceptable"
      except Exception as ex:
        yield encoded, comment + ": "+ str(ex), "invalid"
  for nn, ee, err, validity in modified_key():
    modified_pub = rsa_key.RsaPublicKey(n=nn, e=ee)
    encoding = asn.encode(modified_pub.publicKeyAsn())
    yield encoding, err, validity


def generate_modified_pem(pub_key):
  """Generates modified PEMs of the public keys.

  Args:
    pub_key: a public key
  Yeilds: tuples (encoding, validity, comment) where encoding is modified public
    key and comment describes the modification.
  """

  der = asn.encode(pub_key.publicKeyAsn())
  yield from pem_util.PublicKeyFormat.generate_lax_pem(der)


class RsaPublicKeyAsnTestVector(test_vector.TestVector):
  test_attributes = ['encoded']
  schema = {
    'encoded' : {
       'type' : AST.Asn,
       'desc' : 'a modified X509 encoded public key'
    },
  }

class RsaPublicKeyPemTestVector(test_vector.TestVector):
  test_attributes = ['encoded']
  schema = {
    'encoded' : {
       'type' : AST.Pem,
       'desc' : 'a modified PEM encoded public key'
    },
  }

class RsaPublicKeyAsnTest(test_vector.TestType):
  '''Test vectors of type RsaKeyTest are intended for checking
     the decoding of X509 encoded RSA public keys.
  '''

class RsaPublicKeyPemTest(test_vector.TestType):
  '''Test vectors of type RsaKeyTest are intended for checking
     the decoding of PEM encoded RSA public keys.
  '''

class RsaPublicKeyAsnTestGroup(test_vector.TestGroup):
  vectortype = RsaPublicKeyAsnTestVector
  testtype = RsaPublicKeyAsnTest
  testdoc = "Tests the decoding of RSA keys."
  schema = {
    'privateKey' : {
       'type' : rsa_key.RsaPrivateKey,
       'desc' : 'the private key',
    },
    'privateKeyPkcs8' : {
       'type' : AST.Der,
       'desc' : "PKCS #8 encoded private key",
    },
    'publicKeyAsn' : {
        'type' : AST.Der,
        'desc'  : '''the X509 encoded public key'''
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
    group['type'] = self.testtype
    group['privateKey'] = self.private.as_struct()
    group['publicKeyAsn'] = asn.encode_hex(self.public.publicKeyAsn())
    group['privateKeyPkcs8'] = asn.encode_hex(self.private.privateKeyPkcs8())
    group['tests'] = self.get_all_vectors(sort_by=sort_by)
    return group

class RsaPublicKeyPemTestGroup(test_vector.TestGroup):
  vectortype = RsaPublicKeyPemTestVector
  testtype = RsaPublicKeyPemTest
  testdoc = "Tests the decoding of PEM encoded RSA public keys."
  schema = {
    'privateKey' : {
       'type' : rsa_key.RsaPrivateKey,
       'desc' : 'the private key',
    },
    'privateKeyPem' : {
       'type' : AST.Pem,
       'desc' : "PEM encoded private key",
    },
    'publicKeyPem' : {
        'type' : AST.Pem,
        'desc'  : '''the corresponding PEM encoded public key'''
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
    group['type'] = self.testtype
    group['privateKey'] = self.private.as_struct()
    group['publicKeyPem'] = self.public.publicKeyPem()
    group['privateKeyPem'] = self.private.privateKeyPem()
    group['tests'] = self.get_all_vectors(sort_by=sort_by)
    return group

class RsaKeyTestGenerator(test_vector.TestGenerator):
  algorithm = "RSA"
  def __init__(self, output_format):
    super().__init__()
    self.test = test_vector.Test(self.algorithm)
    self.output_format = output_format

  @util.type_check
  def generateGroup(self, priv: rsa_key.RsaPrivateKey):
    pub = priv.publicKey()
    if self.output_format == "asn":
      group = RsaPublicKeyAsnTestGroup(priv)
    elif self.output_format == "pem":
      group = RsaPublicKeyPemTestGroup(priv)
    self.test.add_group(priv.id, group)
    modified = self.footnote("modified",
      '''The RSA key has been modified. However the test vector generation
         does not distinguish between valid and invalid RSA keys.''')
    pem_flag = self.footnote('modifiedPem',
                             """The PEM encoding has been modified.""")
    for encoding, bugtype, validity in rsa_generate_modified_public_keys(pub):
      assert isinstance(encoding, bytes)
      if self.output_format == "asn":
        test = RsaPublicKeyAsnTestVector()
      elif self.output_format == "pem":
        test = RsaPublicKeyPemTestVector()
      test.comment = bugtype
      test.result = validity
      test.flags = [] if validity == "valid" else [modified]
      if self.output_format == "pem":
        pem = pem_util.public_key_pem(encoding)
        test.encoded = pem
      else:
        test.encoded = encoding
      group.add_test(test)
    if self.output_format == 'pem':
      for pem, validity, comment in generate_modified_pem(pub):
        test = RsaPublicKeyPemTestVector()
        test.result = validity
        test.flags = [pem_flag]
        test.comment = comment


class RsaPubKeyProducer(producer.Producer):

  def parser(self):
    res = self.default_parser()
    res.add_argument(
        '--encoding',
        type=str,
        choices=["asn", "pem"],
        help=["the encoding of the RSA public key"],
        default='asn')
    res.add_argument(
        '--size',
        type=int,
        help=["the size of the RSA key in bits"],
        default=2048)
    return res

  def generate_test_vectors(self, namespace):
    tv = RsaKeyTestGenerator(namespace.encoding)
    tv.generateGroup(rsa_test_keys.get_test_key(namespace.size))
    return tv.test

# DEPRECATED: Use Producer instead
def main(namespace):
  RsaPubKeyProducer().produce(namespace)


if __name__ == "__main__":
  RsaPubKeyProducer().produce_with_args()
