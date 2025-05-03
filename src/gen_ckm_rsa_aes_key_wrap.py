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
import AST
import base64
import collections
import gen_rsa_oaep
import hashlib
import keywrap
import mod_arith
import modify
import pseudoprimes
import rsa_key
import rsa_oaep
import rsa_test_keys
import sys
import test_vector
import util
import prand
import producer
from typing import Optional

STATUS = 'alpha'
HASHES = ["SHA-1", "SHA-224", "SHA-256", "SHA-384", "SHA-512"]

class CkmRsaAesKeyWrap:
  '''Using Section 2.1.21 of
     http://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/cos01/pkcs11-curr-v2.40-cos01.html
     This is only an informal description and leaves a number of details open.
     E.g., there is no description whether labels for OAEP (aka psource) are allowed.
     Depending on this the the test vectors change.
  '''
  def __init__(self, rsa_key, md, mgf, mgf_md, kwbytesize, seed='12kl4j124h1d'):
    assert kwbytesize in (16, 24, 32)
    self.kwbytesize = kwbytesize
    hlen = len(util.hash(md, b""))
    self.max_message_size = rsa_key.key_size_in_bytes() - 2 * hlen - 2
    assert self.max_message_size >= kwbytesize
    self.seed = seed
    self.oaep = rsa_oaep.RsaesOaep(rsa_key, md, mgf, mgf_md, seed)
    self.asym_size = rsa_key.key_size_in_bytes()

  def wrap(self, ba: bytes, label=None)->bytes:
    '''Wraps pseudorandomly to get deterministic test vectors.'''
    assert not label
    wrapkey = prand.randbytes(self.kwbytesize, seed=self.seed, label=ba)
    asympart = self.oaep.encrypt(wrapkey)
    assert len(asympart) == self.asym_size
    sympart = keywrap.keywrap_rfc5649(wrapkey).wrap(ba)
    return asympart + sympart

  def unwrap(self, ba: bytes, label=None)->bytes:
    assert not label
    if self.asym_size > len(ba):
      raise ValueError("ba too small")
    asympart = ba[:self.asym_size]
    sympart = ba[self.asym_size:]
    wrapkey = self.oaep.decrypt(asympart)
    keybytes = keywrap.keywrap_rfc5649(wrapkey).unwrap(sympart)
    return keybytes

  def modified_wrap(self, ba: bytes, label=None, case=None):
    assert not label
    wrapkey = prand.randbytes(self.kwbytesize, seed=self.seed, label=ba)
    if case("wrapping key is all 0"):
      wrapkey = bytes(len(wrapkey))
    if case("wrapping key is all 1"):
      wrapkey = bytes([0xff])*len(wrapkey)
    encryptedbytes = wrapkey
    keysizes = sorted({0, 8, 16, 17, 24, 31, 32, 40, 48, self.max_message_size,
                       self.kwbytesize - 1, self.kwbytesize + 1})
    for wrappedkeysize in keysizes:
      if (wrappedkeysize <= self.max_message_size and
          wrappedkeysize != self.kwbytesize):
        if case("encrypted key has size %s" % wrappedkeysize):
          encryptedbytes = bytes(wrappedkeysize)
          wrapkey = bytes(self.kwbytesize)
    asympart = self.oaep.modified_encrypt(encryptedbytes, case=case)
    sympart = keywrap.keywrap_rfc5649(wrapkey).modified_wrap(ba, case=case)
    res = asympart + sympart
    if case("appending bytes to key wrapping"):
      res += bytes(2)
    if case("result is empty"):
      res = bytes()
    if case("result truncated"):
      res = res[1:]
    return res

class CkmRsaAesKeyWrapTestVector(test_vector.TestVector):
  # TODO: Can we use labels?
  test_attributes = ["msg", "ct"]
  schema = {
    'msg' : {
        'type' : AST.HexBytes,
        'desc' : 'The encrypted message',
    },
    'ct' : {
        'type' : AST.HexBytes,
        'desc' : 'An encryption of msg',
    },
  }

  def testrep(self):
    return repr(self.ct)


class Field:
  # TODO: Maybe use NamedTuples:
  # Employee = NamedTuple('Employee', [('name', str), ('id', int)])
  def __init__(self, name, field_type, short=None, desc=None, enum=None):
    self.name = name
    self.field_type = field_type
    self.short = short
    self.desc = desc
    self.enum = enum


class CkRsaPkcsOaepParams:
  """ A structure replicating CK_RSA_PKCS_OAEP_PARAMS as defined in section 2.1.7 of

      http://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/cos01/pkcs11-curr-v2.40-cos01.html
  """
  fields = [
      Field(
          'hashAlg',
          int,
          short='CK_MECHANISM_TYPE',
          desc="""The value of CK_MECHANISM_TYPE. This value is
                   an integer encoding the hash function (sha)"""),
      Field(
          'mgf',
          int,
          short='CK_RSA_PKCS_MGF_TYPE',
          desc="""The value of CK_RSA_PKCS_MGF_TYPE. This value
                    is an integer encoding mgf and mgfSha.""",
          enum=(1, 2, 3, 4, 5)),
      Field(
          'source',
          int,
          desc='CK_RSA_PKCS_OAEP_SOURCE_TYPE',
      ),
      Field(
          'sourceData',
          AST.HexBytes,
          desc='The source data for RSA_PKCS_OAEP',
      ),
  ]

class CkmRsaAesKeyWrapTest(test_vector.TestType):
  '''Test vector of type CkmRsaAesKeyWrapTest are intended to
     check the unwrapping of keys wrapped with 
     CKM_RSA_AES_KEY_WRAP.
  '''

class CkmRsaAesKeyWrapTestGroup(test_vector.TestGroup):
  '''A test group for validating the unwrapping key wrapped
     with CKM_RSA_AES_KEY_WRAP.

     The test group replicates many of the fields.
     E.g. 'sha', 'mgf', 'mgfSha' use the same values and types
     as other test vectors in Wycheproof.
     The data structure CkRsaAesKeyWrapParams contains the
     same fields using the PKCS #11 enumeration values.
  '''
  algorithm = "CKM-RSA-AES-KEY-WRAP"
  testtype = CkmRsaAesKeyWrapTest
  vectortype = CkmRsaAesKeyWrapTestVector
  schema = {
    'n' : {
       'type' : AST.BigInt,
       'desc' : 'The modulus of the key',
    },
    'e' : {
       'type' : AST.BigInt,
       'desc' : 'The public exponent',
    },
    'd' : {
       'type' : AST.BigInt,
       'desc' : 'The private exponent',
    },
    'privateKeyPkcs8' : {
       'type' : 'Der',
       'short' : 'Pkcs #8 encoded private RSA key.',
       'desc' : '''Pkcs #8 encoded private RSA key.
                   I.e this is an ASN encoding of type PrivateKeyInfo
                   as described in Section 5 of RFC 5208.
                   The encoding uses PKCS1algorithm = rsaEncryption
                   mainly since this is a popular choice in current
                   crypto libraries.
                   
                   This encoding is recommended in
                   pkcs11-ckm-rsa-aes-key-wrap-r1-4.doc''',
    },
    'privateKeyPem' : {
       'type' : 'Pem',
       'desc' : 'Pem encoded private RSA key'
    },
    'sha' : {
       'type' : str,
       'desc' : 'The hash function for hashing the label.'
    },
    'mgf' : {
       'type' : str,
       'desc' : 'the message generating function (e.g. MGF1)',
    },
    'mgfSha' : {
       'type' : str,
       'desc' : '''The hash function used for the message generating
                   function.'''
    },
    'wrapKeySize' : {
        'type' : int,
        'desc' : 'The key size of the wrapping key in bits',
        'enum' : (128, 192, 256),
    },
  }

  def __init__(self, key, md, mgf, mgf_md, wrap_size_in_bytes):
    super().__init__()
    self.key = key
    self.wrapper = CkmRsaAesKeyWrap(key, md, mgf, mgf_md, wrap_size_in_bytes)
    self.md = md
    self.mgf = mgf
    self.mgf_md = mgf_md
    # set the flags for the key
    self.flags = []
    self.wrap_size_in_bytes = wrap_size_in_bytes

    if self.key.n.bit_length() < 2048:
      ref = self.footnote("SmallModulus",
          '''The key for this test vector has a modulus of size < 2048.''')
      self.flags.append(ref)
    if self.key.md in ("MD5"):
      ref = self.footnote("WeakHash",
          '''The key for this test vector uses a weak hash function.''')
      self.flags.append(ref)
    # TODO: Set padding for weak parameters

  @util.type_check
  def add_vector(self, message: bytes, label:Optional[bytes]=None,
                 ct: Optional[bytes]=None, comment:str="", flags:Optional[list[str]]=None):
    # TODO: So far it is unclear if CKM supports labels aka psource
    if label is not None:
      return
    test = CkmRsaAesKeyWrapTestVector()
    if label is None:
      label = b""
    if ct is None:
      ct = self.wrapper.wrap(message, label)
    test.flags = self.flags[:]
    try:
      decrypted = self.wrapper.unwrap(ct, label)
      if decrypted == message:
        if test.flags:
          test.result = "acceptable"
        else:
          test.result = "valid"
      else:
        test.result = "invalid"
    # TODO: Incorrect encodings should be ValueErrors
    except Exception:
      test.result = "invalid"
    if len(message) <= 8 and test.result == "acceptable":
      test.flags += [self.footnote("ShortWrappedKey",
         '''The wrapped key is <= 8 bytes. Implementations may reasonably
            reject such keys.''')]
    if flags:
      test.flags += flags
    test.comment = comment
    test.msg = message
    test.ct = ct
    test.label = label
    self.add_test(test)

  @util.type_check
  def generate_modified(self, message: bytes, label: Optional[bytes]=None):
    '''Generates modified signatures for message'''
    for ct, comment in modify.CaseIter(
      lambda case: self.wrapper.modified_wrap(message, label, case)):
      self.add_vector(message, label, ct, comment=comment)

  def generate_valid(self, label: Optional[bytes]=None):
    messages = [
      # Typical key sizes
      bytes(range(16)),
      bytes(range(24)),
      bytes(range(32)),
      # Odd key sizes
      bytes(range(17)),
      bytes(range(31)),
      bytes(range(41)),
      # Short key size
      bytes(range(8)),
      # a long key size
      bytes(range(256))]
    for m in messages:
      self.add_vector(m, label)

  def generate_valid_with_labels(self, msg: bytes):
    labels = [
       bytearray(8),
       bytearray(range(20)),
       bytearray(range(32))]
    for label in labels:
      self.add_vector(msg, label)

  def generate_edgecases(self):
    # TODO: Should be similar to OAEP test
    pass

  @util.type_check
  def generate_all(self, message: bytes, label: Optional[bytes] = None,
                   allow_labels: bool = False):
    self.generate_valid(label)
    self.generate_modified(message, label)
    if allow_labels:
      if label is None:
        self.generate_valid_with_labels(message)
      self.generate_edgecases()

  def as_struct(self, sort_by=None):
    key = self.key
    group = {}
    group['type'] = self.testtype
    # TODO: can we wrap this into key.
    group['n'] = AST.BigInt(key.n)
    group['e'] = AST.BigInt(key.e)
    group['d'] = AST.BigInt(key.d)
    group['keySize'] = key.n.bit_length()
    group['sha'] = self.md
    group['mgfSha'] = self.mgf_md
    group['mgf'] = self.mgf
    group['wrapKeySize'] = self.wrap_size_in_bytes * 8
    # Note(bleichen): private keys use pkcs1algorithm = rsaEncryption
    group['privateKeyPkcs8'] = asn.encode_hex(key.privateKeyPkcs8())
    group['privateKeyPem'] = key.privateKeyPem()
    group['tests'] = self.get_all_vectors(sort_by)
    return group

def gen_ckm_rsa_aes_key_wrap(size, md, mgf, mgf_md, wrap_key_sizes_in_bits):
  # Sanity check: Size is in bits and must be defined
  assert size >= 512
  t = test_vector.Test("CKM-RSA-AES-KEY-WRAP")
  if mgf_md == '':
    mgf_md = md
  assert md
  key = rsa_test_keys.get_test_key(size, md)
  for size_in_bits in wrap_key_sizes_in_bits:
    wrap_key_size_in_bytes = size_in_bits // 8
    g = CkmRsaAesKeyWrapTestGroup(key, md, mgf, mgf_md, wrap_key_size_in_bytes)
    g.generate_all(bytes(range(16, 16 + wrap_key_size_in_bytes)))
    t.add_group("g%d" % size_in_bits, g)
  return t

def gen_ckm_rsa_aes_key_wrap_misc():
  t = test_vector.Test("CKM-RSA-AES-KEY-WRAP")
  for key in rsa_test_keys.rsa_signature_keys:
    md = key.md
    hlen = len(util.hash(md, b''))
    if key.n.bit_length() < 1024:
      continue
    for mgf in ["MGF1"]:
      for mgf_md in HASHES:
        max_message_size = key.key_size_in_bytes() - 2 * hlen - 2
        for wrap_size in (16, 24, 32):
          if wrap_size > max_message_size:
            continue
          g = CkmRsaAesKeyWrapTestGroup(key, md, mgf, mgf_md, wrap_size)
          g.generate_valid()
          idx = "rsa_%d_%s_%s%s" % (key.n.bit_length(), md, mgf, mgf_md)
          t.add_group(idx, g)
  # TODO: Add special key sizes if label is supported.
  return t


class CkmRsaAesKeyWrapProducer(producer.Producer):

  def parser(self):
    parser = self.default_parser()
    parser.add_argument(
        '--mode',
        type=str,
        default='',
        choices=['', 'misc', 'search'],
        help="misc: Generate combinations of hash functions, edgecases,"
        ' unused key sizes')
    parser.add_argument('--size', type=int, default=0)
    parser.add_argument(
        '--sha',
        type=str,
        choices=["SHA-1", "SHA-224", "SHA-256", "SHA-384", "SHA-512"],
        default='SHA-256')
    parser.add_argument('--mgf', type=str, choices=['MGF1'], default='MGF1')
    parser.add_argument(
        '--mgf_sha',
        type=str,
        choices=["", "SHA-1", "SHA-224", "SHA-256", "SHA-384", "SHA-512"],
        default='')
    return parser

  def generate_test_vectors(self, namespace):
    mode = getattr(namespace, 'mode', '')
    if mode == 'misc':
      test = gen_ckm_rsa_aes_key_wrap_misc()
    else:
      assert mode == ''
      wrap_key_sizes = getattr(namespace, 'key_sizes', None)
      if not wrap_key_sizes:
        # key_sizes was not defined or empty
        wrap_key_sizes = [128, 192, 256]
      test = gen_ckm_rsa_aes_key_wrap(namespace.size, namespace.sha,
                                      namespace.mgf, namespace.mgf_sha,
                                      wrap_key_sizes)
    return test


# DEPRECATED: Use Producer.produce() instead
def main(namespace):
  CkmRsaAesKeyWrapProducer().produce(namespace)


if __name__ == '__main__':
  CkmRsaAesKeyWrapProducer().produce_with_args()
