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
import kdf
import keywrap
import hlib
import mod_arith
import modify
import producer
import pseudoprimes
import test_vector
import util
import prand
from typing import Optional

STATUS = 'alpha'
HASHES = ['SHA-224', 'SHA-256', 'SHA-384', 'SHA-512']
KDFS = [
    'CKD_NULL', 'CKD_SHA1_KDF', 'CKD_SHA224_KDF', 'CKD_SHA256_KDF',
    'CKD_SHA384_KDF', 'CKD_SHA512_KDF'
],


def get_kdf(name: str):
  if name == 'CKD_SHA1_KDF':
    return kdf.kdfX963Sha1
  else:
    raise ValueError('KDF not implemented:' + name)


class CkmEcdhAesKeyWrap:
  """Defined in http://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/cos01/pkcs11-curr-v2.40-cos01.html

     Section 2.3.12


     typedef struct CK_ECDH_AES_KEY_WRAP_PARAMS {
        CK_ULONG             ulAESKeyBits;
        CK_EC_KDF_TYPE       kdf;
        CK_ULONG             ulSharedDataLen;
        CK_BYTE_PTR          pSharedData;
     } CK_ECDH_AES_KEY_WRAP_PARAMS;

     The fields of the structure have the following meanings:
     ulAESKeyBits     length of the temporary AES key in bits.
                      Can be only 128, 192 or 256.
     Kdf              key derivation function used on the shared secret value to
                      generate an AES key.
     ulSharedDataLen  the length in bytes of the shared info
     pSharedData Some data shared between the two parties.

     Open: CKD_SHAxxx_KDF juse uses a reference to Ansi X9.63.
     From a draft version
     ftp://ftp.iks-jena.de/mitarb/lutz/standards/ansi/X9/x963-7-5-98.pdf
     Section 5.6.3 defines a key derivation function:
     As hash_1 || hash_2 || ..
     where hash_i = SHA-1(Z || i || sharedInfo),
     where Z is the shared secret, i is 4 bytes long in big-endian
     representation.
     kdf.kdfX963Sha1 in kdf.py might implement this function.

  """

  def __init__(self, ec_key, kdf: str, kwbytesize, seed='12kl4j124h1d'):
    assert kwbytesize in (16, 24, 32)
    self.kwbytesize = kwbytesize
    hlen = len(hlib.hash(md, ''))
    self.max_message_size = rsa_key.key_size_in_bytes() - 2 * hlen - 2
    assert self.max_message_size >= kwbytesize
    self.seed = seed
    self.kdf = kdf
    self.key = ec_key
    self.asym_size = None

  def wrap(self, ba: bytes, label: bytes = None) -> bytes:
    """Wraps pseudorandomly to get deterministic test vectors."""
    wrapkey = prand.randbytes(
        self.kwbytesize, seed=self.seed, label=(ba + label))
    asympart, secret = self.ecdh(seed=self.seed, label=(ba + label))
    wrapkey = self.kdf(secret, label, self.kwbytesize)
    sympart = keywrap.keywrap_rfc5649(wrapkey).wrap(ba)
    return asympart + sympart

  def unwrap(self, ba: bytes, label: bytes = None) -> bytes:
    if self.asym_size > len(ba):
      raise ValueError('ba too small')
    asympart = ba[:self.asym_size]
    sympart = ba[self.asym_size:]
    shared = self.ec_unwrap()
    # ...
    keybytes = keywrap.keywrap_rfc5649(wrapkey).unwrap(sympart)
    return keybytes

  def modified_wrap(self, ba: bytes, label=None, case=None):
    assert not label
    wrapkey = prand.randbytes(self.kwbytesize, seed=self.seed, label=ba)
    if case('wrapping key is all 0'):
      wrapkey = bytes(len(wrapkey))
    if case('wrapping key is all 1'):
      wrapkey = bytes([0xff]) * len(wrapkey)
    encryptedbytes = wrapkey
    keysizes = sorted({
        0, 8, 16, 17, 24, 31, 32, 40, 48, self.max_message_size,
        self.kwbytesize - 1, self.kwbytesize + 1
    })
    for wrappedkeysize in keysizes:
      if (wrappedkeysize <= self.max_message_size and
          wrappedkeysize != self.kwbytesize):
        if case('encrypted key has size %s' % wrappedkeysize):
          encryptedbytes = bytes(wrappedkeysize)
          wrapkey = bytes(self.kwbytesize)
    asympart = self.oaep.modified_encrypt(encryptedbytes, case=case)
    sympart = keywrap.keywrap_rfc5649(wrapkey).modified_wrap(ba, case=case)
    res = asympart + sympart
    if case('appending bytes to key wrapping'):
      res += bytes(2)
    if case('result is empty'):
      res = bytes()
    if case('result truncated'):
      res = res[1:]
    return res


class CkEcdhAesKeyWrapParams:
  """Defined in Section 2.3.13 of http://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/cos01/pkcs11-curr-v2.40-cos01.html
  """
  schema = {
      'aesKeyBits': {
          'type': int,
          'desc': 'the size of the derived AES key in bits',
      },
      'kdf': {
          'type': 'JSON',
          'desc': 'the key derivation algorithm for deriving an AES key'
      },
      'sharedData': {
          'type': AST.HexBytes,
          'desc': 'data shared between the two parties',
      },
  }


class CkmEcdhAesKeyWrapTestVector(test_vector.TestVector):
  # TODO: Can we use labels?
  #   Can we share the structure with CkmRsaAesKeyWrapTestVector?
  test_attributes = ['msg', 'ct']
  schema = {
      'msg': {
          'type': AST.HexBytes,
          'desc': 'The encrypted message',
      },
      'ct': {
          'type': AST.HexBytes,
          'desc': 'An encryption of msg',
      },
  }

  def testrep(self):
    return repr(self.ct)

class CkmUnwrapTest(test_vector.TestType):
  '''Test vectors of type CkmUnwrapTest are intended for testing unwrapping.
  '''
  status = 'alpha'


class CkmEcdhAesKeyWrapTestGroup(test_vector.TestGroup):
  """A test group for validating the unwrapping key wrapped

     with CKM_ECDH_AES_KEY_WRAP.
  """
  algorithm = 'CKM-ECDH-AES-KEY-WRAP'
  testtype = CkmUnwrapTest
  vectortype = CkmEcdhAesKeyWrapTestVector
  schema = {
      'privateKey': {},
      'privateKeyPkcs8': {
          'type': 'Der',
          'short': 'Pkcs #8 encoded private ECDH key.',
          'desc': """Pkcs #8 encoded private ECDH key.
                """,
      },
      'privateKeyPem': {
          'type': 'Pem',
          'desc': 'Pem encoded private ECDH key'
      },
      'kdf': {
          'type': str,
          'desc': 'The key derivation function used.',
          'enum': KDFS,
      },
      'wrapKeySize': {
          'type': int,
          'desc': 'The key size of the wrapping key in bits',
          'enum': (128, 192, 256),
      },
  }

  def __init__(self, key, kdf, wrap_size_in_bytes):
    super().__init__()
    self.key = key
    self.wrapper = CkmEcdhAesKeyWrap(key, kdf, wrap_size_in_bytes)
    self.md = md
    self.mgf = mgf
    self.mgf_md = mgf_md
    # set the flags for the key
    self.flags = []
    self.wrap_size_in_bytes = wrap_size_in_bytes

    if self.key.n.bit_length() < 224:
      ref = self.footnote(
          'SmallModulus',
          """The key for this test vector has a modulus of size < 224.""")
      self.flags.append(ref)
    # TODO: Set padding for weak parameters

  @util.type_check
  def add_vector(self, message: bytes, label: Optional[bytes]=None,
                 ct:Optional[bytes]=None,
                 comment:str='', flags:Optional[list[str]]=None):
    # TODO: So far it is unclear if CKM supports labels aka psource
    if label is not None:
      return
    test = CkmEdchAesKeyWrapTestVector()
    if label is None:
      label = b''
    if ct is None:
      ct = self.wrapper.wrap(message, label)
    test.flags = self.flags[:]
    try:
      decrypted = self.wrapper.unwrap(ct, label)
      if decrypted == message:
        if test.flags:
          test.result = 'acceptable'
        else:
          test.result = 'valid'
      else:
        test.result = 'invalid'
    # TODO: Incorrect encodings should be ValueErrors
    except Exception:
      test.result = 'invalid'
    if len(message) <= 8 and test.result == 'acceptable':
      test.flags += [
          self.footnote(
              'ShortWrappedKey',
              """The wrapped key is <= 8 bytes. Implementations may reasonably
            reject such keys.""")
      ]
    if flags:
      test.flags += flags
    test.comment = comment
    test.msg = message
    test.ct = ct
    test.label = label
    self.add_test(test)

  def generate_modified(self, message, label=None):
    """Generates modified signatures for message"""
    for ct, comment in modify.CaseIter(
        lambda case: self.wrapper.modified_wrap(message, label, case)):
      self.add_vector(message, label, ct, comment=comment)

  def generate_valid(self, label=None):
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
        bytes(range(256))
    ]
    for m in messages:
      self.add_vector(m, label)

  def generate_valid_with_labels(self, msg):
    labels = [bytearray(8), bytearray(range(20)), bytearray(range(32))]
    for label in labels:
      self.add_vector(msg, label)

  def generate_edgecases(self):
    # TODO: Should be similar to OAEP test
    pass

  def generate_all(self, message, label=None, allow_labels=False):
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
    group['keySize'] = key.n.bit_length()
    group['kdf'] = self.kdf
    group['wrapKeySize'] = self.wrap_size_in_bytes * 8
    group['tests'] = self.get_all_vectors(sort_by)
    return group


def gen_ckm_ecdh_aes_key_wrap(
     curve: str,
     kdf: str,
     wrap_key_sizes_in_bits: int):
  # Sanity check: Size is in bits and must be defined
  assert size >= 224
  t = test_vector.Test('CKM-ECDH-AES-KEY-WRAP')
  if mgf_md == '':
    mgf_md = md
  assert md
  key = rsa_test_keys.get_test_key(size, md)
  for size_in_bits in wrap_key_sizes_in_bits:
    wrap_key_size_in_bytes = size_in_bits // 8
    g = CkmEcdhAesKeyWrapTestGroup(key, kdf, wrap_key_size_in_bytes)
    g.generate_all(bytes(range(16, 16 + wrap_key_size_in_bytes)))
    t.add_group('g%d' % size_in_bits, g)
  return t


class CkmEcdhAesKeyWrapProducer(producer.Producer):

  def parser(self):
    res = self.default_parser()
    res.add_argument(
      '--curve', type=str, default='', help='the name of the curve')
    # The KDFs are typically stored as integers. None of the documents I've seen
    # includes the mapping of the KDF to the integer.
    # None of the documents I've seen define what happens to the lable if
    # the key derivation function is CKD_NULL.
    res.add_argument(
      '--kdf',
      type=str,
      choices=KDFS,
      default='CKD_SHA1_KDF',
      help='the key derivation function')
    return res


  def generate_test_vectors(self, namespace):
    wrap_key_sizes = getattr(namespace, 'key_sizes', None)
    if not wrap_key_sizes:
      # key_sizes was not defined or empty
      wrap_key_sizes = [128, 192, 256]
    # return = gen_ckm_ecdh_aes_key_wrap(...)
    ...


# DEPRECATED: Use Producer.produce() instead
def main(namespace):
  CkmEcdhAesKeyWrapProducer().produce(namespace)

if __name__ == "__main__":
  CkmEcdhAesKeyWrapProducer().produce_with_args()


