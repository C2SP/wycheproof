# Copyright 2019 Google Inc. All Rights Reserved.
# Author: bleichen@google.com (Daniel Bleichenbacher)
#
# Generating test cases for ECIES as defined in
# https://www.secg.org/sec1-v2.pdf

import AST
import asn
import asn_fuzzing
import ec_key
import producer
import test_vector
import typing
import util

HASHES = ["SHA-224", "SHA-256", "SHA-384", "SHA-512",
          "SHA3-224", "SHA3-256", "SHA3-384", "SHA3-512"]

class EciesSec1Decrypt(test_vector.TestType):
  '''Test vectors of type EciesSec1Decrypt are meant for testing
     the decryption of messages encrypted ECIES as defined in
     https://www.secg.org/sec1-v2.pdf

     Test vectors with "result" : "valid" are valid ciphertexts.
     Test vectors with "result" : "invalid" are invalid.
     Test vectors with "result" : "acceptable" are ciphertexts that may
     or may not be rejected. The reasons for potential rejection are
     described with labels.
  '''
  status = 'alpha'

class EciesSec1TestVector(test_vector.TestVector):
  '''ECIES test vector'''
  status = 'alpha'

class EciesSec1TestGroup(test_vector.TestGroup):
  '''A test group for ECIES encrypted messages.

     The test group contains the same public key for the signatures in
     multiple representations. The public keys are valid with the sole
     exception that they may use short keys and weak hash functions
     such as SHA-1.
  '''
  status = 'alpha'

  algorithm = "ECIES"
  testtype = EciesSec1Decrypt
  vectortype = EciesSec1TestVector
  #####------------------------------------------------------
  schema = {
      'key': {
          'type': ec_key.EcPublicKey,
          'desc': 'unencoded EC public key',
      },
      'keyDer': {
          'type': AST.Der,
          'desc': 'DER encoded public key',
      },
      'keyPem': {
          'type': AST.Pem,
          'desc': 'Pem encoded public key',
      },
      'sha': {
          'type': AST.MdName,
          'desc': 'the hash function used for ECDSA',
      }
  }

  def __init__(self, pubkey, md):
    super().__init__()
    self.pubkey = pubkey
    self.md = md
    self.encoding = "asn"

  def as_struct(self, sort_by=None):
    if sort_by is None:
      sort_by = "comment"
    key = self.pubkey
    group = {}
    group['type'] = self.testtype
    group['key'] = key.as_struct()
    group['keyDer'] = key.encode_hex()
    group['keyPem'] = key.pem()
    group['sha'] = self.md
    group['tests'] = self.get_all_vectors(sort_by=sort_by)
    return group


class EciesProducer(producer.Producer):

  def parser(self):
    res = self.default_parser()
    res.add_argument(
        '--curve', type=str, default='', help='the name of the curve')
    res.add_argument('--sha', type=str, choices=[""] + HASHES, default='')
    return res

  def generate_test_vectors(self, namespace):
    tv = EciesTestGenerator(namespace.encoding)
    tv.generate_all()
    return tv.test


# DEPRECATED: Use Producer.produce() instead
def main(namespace):
  EciesProducer().produce(namespace)


if __name__ == "__main__":
  EciesProducer().produce_with_args()
