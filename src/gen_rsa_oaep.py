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
import flag
import modify
import producer
import rsa_key
import rsa_oaep
import rsa_test_keys
import test_vector
from typing import Optional
import util
import conversions

# The hash algorithms are defined in RFC 8017, Section A.2.1, which simply says
#  " * hashAlgorithm identifies the hash function.  It SHALL be an
#      algorithm ID with an OID in the set OAEP-PSSDigestAlgorithms."
# Hence in principle truncated hashes would be allowed. But so far no
# library seems to implement this.
# This set will be extended in
# https://tools.ietf.org/id/draft-ietf-lamps-pkix-shake-12.html
# However, the format of the parameters may change.

HASHES = ["SHA-1", "SHA-224", "SHA-256", "SHA-384", "SHA-512"]

class RsaesOaepTestVector(test_vector.TestVector):
  test_attributes = ["msg", "ct", "label"]
  schema = {
      "msg": {
          "type": AST.HexBytes,
          "desc": "The encrypted message",
      },
      "ct": {
          "type": AST.HexBytes,
          "desc": "An encryption of msg",
      },
      "label": {
          "type": AST.HexBytes,
          "desc": "The label used for the encryption",
      }
  }

  def testrep(self):
    return repr(self.ct)

class RsaesOaepDecrypt(test_vector.TestType):
  """Test vectors of type RsaOeapDecrypt are intended to check the decryption

     of RSA encrypted ciphertexts.

     The test vectors contain ciphertexts with invalid format (i.e. incorrect
     size) and test vectors with invalid padding. Hence the test vectors
     are a bit inconvenient to detect padding oracles. One potential plan
     is to generate separate, new files that only contain ciphertexts with
     invalid paddings.
  """

# TODO: split into generator and test group.
class RsaesOaepTestGroup(test_vector.TestGroup):
  algorithm = "RSAES-OAEP"
  testtype = RsaesOaepDecrypt
  vectortype = RsaesOaepTestVector
  schema = {
      "keySize": {
          "type": int,
          "desc": "key size in bits",
      },
      "privateKey": {
          "type": rsa_key.RsaPrivateKey,
          "desc": "the private key",
      },
      "privateKeyPkcs8": {
          "type": AST.Der,
          "desc": "Pkcs 8 encoded private key"
      },
      "privateKeyPem": {
          "type": AST.Pem,
          "desc": "Pem encoded private key"
      },
      "privateKeyJwk": {
          "type": rsa_key.JwkRsaPrivateKey,
          "desc": "JSON encoded private key",
          "since": "0.7",
          "optional": True,
      },
      "sha": {
          "type": AST.MdName,
          "desc": "The hash function for hashing the label."
      },
      "mgf": {
          "type": str,
          "desc": "the message generating function (e.g. MGF1)",
      },
      "mgfSha": {
          "type":
              AST.MdName,
          "desc":
              """The hash function used for the message generating
                   function."""
      }
  }

  def __init__(self, key, md, mgf, mgf_md, footnotes):
    super().__init__()
    self.key = key
    self.crypter = rsa_oaep.RsaesOaep(key, md, mgf, mgf_md)
    self.md = md
    self.mgf = mgf
    self.mgf_md = mgf_md
    # set the flags for the key
    self.key_flags = []
    self.footnotes = footnotes
    if self.key.n.bit_length() < 2048:
      self.key_flags.append(
          flag.Flag(
              label="SmallModulus",
              bug_type=flag.BugType.WEAK_PARAMS,
              description="The key for this test vector has a modulus of size < 2048."
          ))
    if md in ("MD5"):
      self.key_flags.append(
          flag.Flag(
              label="WeakHash",
              bug_type=flag.BugType.WEAK_PARAMS,
              description="The test vector uses a weak hash function."))

  @util.type_check
  def add_vector(self,
                 message: bytes,
                 label: Optional[bytes] = None,
                 ct: Optional[bytes] = None,
                 comment: str = "",
                 flags: Optional[list[flag.Flag]] = None):
    test = RsaesOaepTestVector()
    if flags is None:
      flags = []
    else:
      flags = flags[:]
    flags += self.key_flags
    if label is None:
      label = b""
    if ct is None:
      ct = self.crypter.encrypt(message, label)
    try:
      decrypted = self.crypter.decrypt(ct, label)
      if decrypted == message:
        test.result = "valid"
        if not flags:
          valid_encryption = flag.Flag(
              label="ValidCiphertext",
              bug_type=flag.BugType.FUNCTIONALITY,
              description="The test vector contains a valid ciphertext. "
              "Some valid ciphertext contain exceptional padding. "
              "The goal is to check the functionality of the decryption "
              "by testing such edge cases.")
      else:
        # The modification changed the plaintext, but everything else
        # is OK. This test vector is therefore not used.
        return
    except rsa_oaep.DecryptionError:
      # Decryption distinguishes between modified padding, which
      # throws DecryptionError invalid format, which throws a ValueError.
      # TODO: OpenJDK had a flaw that allowed this.
      #                 BouncyCastle had some minor flaw too.
      # TODO: Maybe returning flags from modified_encrypt would
      #                 allow better documentation.
      invalid_oaep_padding = flag.Flag(
          label="InvalidOaepPadding",
          bug_type=flag.BugType.CONFIDENTIALITY,
          description="The test vector and an invalid OAEP padding. "
          "Implementations must ensure that different error "
          "conditions cannot be distinguished, since otherwise "
          "Manger's attack against OAEP may be possible. ",
          links=["https://www.iacr.org/archive/crypto2001/21390229.pdf"],
          cves=["CVE-2020-26939"])
      flags.append(invalid_oaep_padding)
      test.result = "invalid"
    except ValueError:
      modified_ciphertext = flag.Flag(
          label="InvalidCiphertext",
          bug_type=flag.BugType.MISSING_STEP,
          description="The test vector contains an invalid ciphertext. "
          "The test vectors distinguish between InvalidOaepPadding "
          "(cases where returning information about the error can lead "
          "to Manger's attack) and InvalidCiphertext (cases where the "
          "ciphertext is malformed and a decryption should not even be "
          "attempted.)")
      flags.append(modified_ciphertext)
      test.result = "invalid"
    if label:
      flags.append(
         flag.Flag(
             label="EncryptionWithLabel",
             bug_type=flag.BugType.FUNCTIONALITY,
             description="RSA-OAEP allows an optional parameter label, that is "
             "associated with the message. This test vector contain a ciphertext "
             "that was encrypted with an non-empty label."))
    test.flags = self.footnotes.add_flags(flags)
    test.comment = comment
    test.msg = message
    test.ct = ct
    test.label = label
    self.add_test(test)

  def generate_modified(self, message: bytes, label: Optional[bytes]=None):
    """Generates modified ciphertext for message"""
    for ct, comment in modify.CaseIter(
      lambda case: self.crypter.modified_encrypt(message, label, case)):
      self.add_vector(message, label, ct, comment=comment)

  def generate_valid(self, label: Optional[bytes]=None):
    messages = [
        b"",
        bytes(20), b"Test", b"123400", b"Message", b"a",
        bytes(range(224, 256))
    ]
    if not label:
      flags = [flag.NORMAL]
    else:
      flags = []
    for m in messages:
      if len(m) < self.crypter.max_message_size():
        self.add_vector(m, label, flags=flags)
    max_msg = b"x" * self.crypter.max_message_size()
    self.add_vector(max_msg, label, comment="Longest valid message size", flags=flags)

  def generate_valid_with_labels(self, msg: bytes):
    labels = [
       bytes(8),
       bytes(range(20)),
       bytes(range(32))]
    for label in labels:
      self.add_vector(msg, label)

  def generate_edgecases(self):
    def try_em(em: bytes, cmt: str = "edgecase"):
      r = self.crypter.try_unpad(em)
      if r is not None:
        msg, label = r
        m = conversions.os2ip(em)
        c = pow(m, self.crypter.key.e, self.crypter.key.n)
        ct = conversions.i2osp(c, self.crypter.k)
        constructed = flag.Flag(
            label="Constructed",
            bug_type=flag.BugType.EDGE_CASE,
            description="The test vector (i.e. seed and label) has been "
            "constructed so that the padded plaintext em has some special "
            "properties.")
        self.add_vector(msg, label, ct=ct, comment=cmt, flags=[constructed])

    for i in range(256):
      em = bytearray(self.crypter.k)
      em[-1] = i
      try_em(bytes(em), "em represents a small integer")
    for i in range(self.crypter.k):
      em = bytearray(self.crypter.k)
      em[i] = 1
      try_em(bytes(em), "em has low hamming weight")
    a = bytearray([0])
    b = bytearray([0xff]*self.crypter.h_len)
    c = bytearray(self.crypter.h_len)
    d = bytearray([0xff]*(self.crypter.k - 2*self.crypter.h_len - 1))
    em = a+b+c+d
    for i in range(256):
      em[1]=i
      try_em(bytes(em), "em has a large hamming weight")

  def generate_all(self, message, label:Optional[bytes]=None, allow_labels:bool=True):
    self.generate_valid(label)
    self.generate_modified(message, label)
    if allow_labels:
      if label is None:
        self.generate_valid_with_labels(message)
      self.generate_edgecases()

  def jwk_alg(self):
    if self.md == self.mgf_md == "SHA-1" and self.mgf == "MGF1":
      return "RSA-OAEP"
    elif self.md == self.mgf_md == "SHA-256" and self.mgf == "MGF1":
      return "RSA-OAEP-256"
    else:
      return None

  def as_struct(self, sort_by=None):
    key = self.key
    group = {}
    group["type"] = self.testtype
    group["keySize"] = key.n.bit_length()
    group["sha"] = self.md
    group["mgf"] = self.mgf
    group["mgfSha"] = self.mgf_md
    group["privateKey"] = key.as_struct()
    # Note(bleichen): private keys use pkcs1algorithm = rsaEncryption
    group["privateKeyPkcs8"] = asn.encode_hex(self.crypter.privateKeyPkcs8())
    group["privateKeyPem"] = key.privateKeyPem()
    jwk_alg = self.jwk_alg()
    if jwk_alg:
      jwk_key = key.privateKeyJwk(jwk_alg)
      if jwk_key:
        group["privateKeyJwk"] = jwk_key
    group["tests"] = self.get_all_vectors(sort_by)
    return group

def gen_rsa_oaep(namespace):
  size = namespace.size
  md = namespace.sha
  mgf = namespace.mgf
  mgf_md = namespace.mgf_sha
  three_primes = getattr(namespace, "three_primes", False)

  # Sanity check: Size is in bits and must be defined
  assert size >= 512
  t = test_vector.Test("RSAES-OAEP")
  if mgf_md == "":
    mgf_md = md
  assert md
  # Precomputed three prime RSA keys do not have a hash function.
  # However, there are precomputed keys for common (size, hash) combinations
  # for two-prime keys.
  if three_primes:
    key = rsa_test_keys.get_test_key(size, three_primes=True)
    key.fill_crt()
  else:
    key = rsa_test_keys.get_test_key(size, md)
    key.fill_crt()
  g = RsaesOaepTestGroup(key, md, mgf, mgf_md, t.footnotes())
  g.generate_all(b"123400")
  t.add_group("g", g)
  return t

def gen_rsa_oaep_misc(hashes: list[str] = None):
  if hashes is None:
    hashes = HASHES
  t = test_vector.Test("RSAES-OAEP")
  for key in rsa_test_keys.rsa_signature_keys:
    md = key.md
    if md not in hashes:
      continue
    if key.n.bit_length() < 1024:
      continue
    for mgf in ["MGF1"]:
      for mgf_md in HASHES:
        g = RsaesOaepTestGroup(key, md, mgf, mgf_md, t.footnotes())
        g.generate_valid()
        idx = "rsa_%d_%s_%s%s" % (key.n.bit_length(), md, mgf, mgf_md)
        t.add_group(idx, g)
  # Special key sizes:
  for size, md in [
     (2688, "SHA-256"),
     (4032, "SHA-256"),
     (3104, "SHA-384")]:
    key = rsa_test_keys.get_test_key(size, md)
    g = RsaesOaepTestGroup(key, md, "MGF1", md, t.footnotes())
    g.generate_edgecases()
    idx = "special_%d_%s" % (key.n.bit_length(), md)
    t.add_group(idx, g)
  return t

def gen_rsa_oaep_experimental():
  for size in range(1024, 4096, 32):
    print()
    print("KEY SIZE:" + str(size))
    t = test_vector.Test("RSAES-OAEP")
    key = rsa_test_keys.get_test_key(size, "SHA-256")
    for md in HASHES:
      g = RsaesOaepTestGroup(key, md, "MGF1", md, t.footnotes())
      g.generate_edgecases()
      idx = "rsa_%d_%s" % (key.n.bit_length(), md)
      t.add_group(idx, g)
    return t


class RsaesOaepProducer(producer.Producer):

  def parser(self):
    res = self.default_parser()
    res.add_argument(
        "--mode",
        type=str,
        default="",
        choices=["", "misc", "search"],
        help="misc: Generate combinations of hash functions, edgecases, unused key sizes"
    )
    res.add_argument(
        "--size",
        type=int,
        default=0,
        help="the key size of the RSA key in bits")
    res.add_argument(
        "--sha",
        type=str,
        choices=HASHES,
        default="SHA-256",
        help="the hash function for hashing the message")
    res.add_argument(
        "--mgf",
        type=str,
        choices=["MGF1"],
        default="MGF1",
        help="the name of the mask generation function")
    res.add_argument(
        "--mgf_sha",
        type=str,
        choices=[""] + HASHES,
        default="",
        help="The hash function used in the mask generation function."
        " Default is to use the same hash function as for hashing"
        " the message")
    res.add_argument(
        "--three_primes",
        action="store_true",
        help="uses three prime RSA keys if set")

    return res

  def generate_test_vectors(self, namespace):
    mode = getattr(namespace, "mode", "")
    if mode == "misc":
      test = gen_rsa_oaep_misc()
    elif mode == "search":
      test = gen_rsa_oaep_experimental()
    else:
      assert mode == ""
      test = gen_rsa_oaep(namespace)
    return test


# DEPRECATED: Use Producer.produce() instead
def main(namespace):
  RsaesOaepProducer().produce(namespace)


"""Sample usages:

Generate test vectors for a secified paremeter set
$ python gen_rsa_oaep.py --size=2048 --sha=SHA-256 --mgf=MGF1 \
     --mgf_sha=SHA-256 --out=filename
Generate test vectors for combinations of parameters, and edgecases
$ python gen_rsa_oaep.py --mode=misc --out=filename
Search for edgecases. This typically takes a long time
$ python gen_rsa_oaep.py --mode=search
"""
if __name__ == "__main__":
  RsaesOaepProducer().produce_with_args()
