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

import argparse
import collections
import footnotes
import flag
from typing import Optional, Union, Any
from util import type_check

# TODO: This file is a replacement for test_vectors.py
#   with simpler structure:
#   A file with test vectors is a serialized instance of Test
#   Each instance of Test describes the algorithm tested, and contains
#   an array of TestGroup instances.
#   Each TestGroup contains an array of TestVectors and parameters
#   shared between all the TestVectors in the TestGroup.

# Format major.minor[dev_version]
# Goal: 1.0 means that the format for the test vectors are stable.
# After 1.0 we increment the minor version when the test vectors change.
# Changing the format should be done with major versions.
#
# Format changes:
# 0.0a5: Messages for digital signature schemes are now hexadecimal
# 0.0a6: Include the messages in the tests not in the group.
# 0.0a7: Adding keyPem to RSA signature tests.
# 0.0a8: keyAsn is an ASN encoding of RSAPublicKey (from RFC 3447)
# 0.0a9: Using our own JSON dumper (to sort fields better)
# 0.0a10: Nist compatible hashes (e.g. SHA-1 instead of sha1)
# 0.0a11: Adding keySize to all webcrypto public keys.
# 0.0a12: Refactoring the test generation code. Hopefully there are no changes.
# 0.0a13: Adding keySize to all public keys.
# 0.0a14: Small changes to jwk keys.
# 0.0a15: Removed ext field in jwk keys. Not necessary and not well defined.
# 0.0a16: Adding ASN.1 encoding of Eddsa keys.
# 0.0a17: Using https://tools.ietf.org/html/draft-ietf-curdle-pkix-06 for
#         ASN.1 encoding.
# 0.0a18: More consistent naming of key types for signature schemes:
#         I.e. "type" : "DSAPublicKey" for DSA public keys.
#              "type" : "EddsaKeyPair" for Eddsa key pairs.
# 0.0a19: Removed field "name" in test vectors.
# 0.0a20: Consistently using "msg" instead of "message".
# 0.0a21: ECDSA signatures with missing leading 0 in bigint encoding are now
#         "acceptable", because of openjdk.
#
# 0.1:    A version that we use internally
# 0.1.1:  ECDH test vectors are now generated pseudorandomly, so that
#         all test vector files have the same test vectors.
# 0.1.2:  Adding header to test files.
# 0.1.3:  Adding footnotes.
# 0.1.4:  Refactoring the code. Adding test vectors for MACs.
# 0.1.5:  Adding a class TestVector using __slots__. May reorder the fields.
# 0.1.6:  Adding test vectors for deterministic encryption.
# 0.2:    Simpler version of the code.
# 0.2.1:  Refactoring mac_test, aead_test and some derived classes.
#         This improves the order of the fields in the test vectors, but does
#         not change the test vectors itself (unless they are random).
# 0.2.2:  Refactoring ECDH test vector generation. The test vectors are
#         now sorted by group. Test group describes the group.
# 0.2.3:  Refactoring most other test vector generations.
#         This reorders the fields of most tests. Other changes include:
#         EcPublicKeyTest: adding field "encoding"
# 0.2.4:  Adding more test vectors to ECDSA (for testing uEcc).
#         Adding test vectors for ECDH with points of low order on the twist.
#         Splitting ECDSA test vectors into multiple files.
#         More values for extreme public keys.
# 0.2.5:  More test vectors for ASN parsing.
#         BER signatures for ECDSA and DSA are more strictly rejected.
#         A flag (asnparsing=der/ber) allows to set the behaviour during the
#         test vector generation. Signatures with correct BER encoding
#         are now better annotated. Changing syntax for footnotes to
#         [n] for the tag and [n]: for the referenced text. This may change
#         again.
# 0.3.0a: Adding flags to test vectors.
#         Changing the type of notes from a list of string to a dictionary.
#         No format for the flags is defined yet.
# 0.3.1:  Generating EC test vectors for edge cases on homomorphic groups.
# 0.3.2:  Refactoring ECDH test vectors.
# 0.3.3:  Adding flags to test vectors for AEAD, DAEAD and IND-CPA ciphers
#         as well as MACs.
# 0.4-a1  Alpha version for release 0.4
# 0.4     Version for release
# 0.4.1   ECDSA with non-DER encoding are invalid but now have the BER flag.
#         This version adds more faulty ASN encodings. ASN encodings are
#         truncated after the ASN tag. An invalid encoding of 0 was added.
#         A new format for key-wrapping was added. Test vectors for RFC 3349
#         and RFC 5469 (also NIST SP 800 38f) have been added.
# 0.4.2   Chaning the field names for key wrapping to msg and ct instead of
#         data and wrapping. (I.e. unifying with AEAD and IND-CPA as well
#         as a potential future DAE interface.)
# 0.4.3   More test vectors.
#         Most invalid ECDH test vectors now have a shared secret. This shared
#         secret is computed over the curve from the private key and the point
#         from the public key. This allows to check whether a modified public
#         key influences the computation.
#         (Formats have not changed)
# 0.4.4   Adding a field encoding to test_groups for ECDH.
# 0.4.5   Adding more test vectors for RSA signatures and splitting the test
#         vector in separate files.
# 0.4.6   Adding an uncompressed encoding of the public key point of an EC key
#         to the key representation.
# 0.4.7   Adding more test vectors for AES-GCM. (aes_gcm.py now uses bytearrays()
#         instead of strings internally. This does not affect the test vectors.)
# 0.4.8   Adding ECDH test vector where the public keys are using pem format and
#         X9.62 format respectively.
# 0.4.9   Removing duplicate field curve from ECDH test vectors. Each test group
#         only tests a single curve. Hence there is no need to repeate the field
#         in individual tests.
# 0.4.10  Adding AES-CCM
# 0.4.11  Adding alpha versions. Alpha versions may include unreleased test
#         vectors from buganizer entries. The version contais a postfix "a".
#         Alpha version test vectors are generated with the command line argument
#         --include_buganizer. E.g.
#           python gen_aes_eax.py --include_buganizer
#         Adding keysizes to online arguments: E.g.
#           python gen_aes_ccm.py --key_sizes 128 256
#         (Changed to --alpha in version 0.6)
# 0.4.12  Adding RSA-PSS
# 0.4.13  Adding RSA-OAEP
# 0.4.14  Testvector generation prints to files (--out=...) instead of printing to
#         output. Changed field name for hash from "sha" to "mgfSha".
# 0.5rc1  Adding ASN encoded private keys.
# 0.5rc2  Adding field privateKeyPem to test vectors for OAEP and PKCS 1.5
#         signatures, adding "d" to PKCS 1.5 signatures.
#         Changing pkcs1Algorithm of some ASN encodings of test vectors
# 0.5rc3  Changing pkcs1Algorithm back to rsaEncryption. BC, BoringSSL and
#         Conscrypt didn't accept the new keys.
# 0.5     release version
# 0.6rc1  Moving to Python 3. Some test vectors change some pseudorandom
#         parameters changes (E.g. some code kdf(.., hex(x:int)))
# 0.6rc2  Clearer distinction between str and bytes.
#         bytes (or bytearray) are used for inputs and results of primitives.
#         str is used for hexadecimal representations, text, base64 and pem.
# 0.6rc3  Adding type hints and type checks to some functions.
# 0.6rc4  Adding some documentation of the data structures in the JSON files.
#         ECDH test vectors uses distinct data structures for distinct formats.
# 0.6rc5  Adding more descriptions, refactoring and removing some classes.
#         No changes to the test vectors are expected.
# 0.6rc6  Adding test vectors for asymmetric key wrapping.
# 0.6rc7  Adding test vectors for AEAD-AES-CCM-SIV.
# 0.6rc8  Adding test vectors for P1363 encoded ECDSA signatures.
# 0.6     AEAD-AES-CCM-SIV and PKCS #11 will not be included since I don't
#         have enough confirmation.
#         Adding X448 and X25519 test vectors with ASN encoding.
#         Command line flag --include_buganizer changed to --alpha to reflect
#         change in meaning.
# 0.7rc1  Adding ED448
# 0.7rc2  Adding xchacha_poly1305 (draft)
#         Changing the name ByteString to HexBytes. The name is not yet used
#         in current test vectors. ByteString might lead to name confliction
#         with typing.ByteString.
# 0.7rc3  New search for edge cases for chacha and xchacha. The new search
#         generates more edge cases (e.g. 0-limbs). Some of the old test vectors
#         had incorrect IVs.
# 0.7rc4  Adding test vectors for HKDF.
# 0.7rc5  Adding documentation from the header of the test group into the test
#         vector. Renaming the testtypes, so that they include test purpose
#         and encoding.
# 0.7rc6  Adding a field schema, which defines the file name of a JSON schema
#         for the test vector file.
# 0.7rc7  Adding special cases for doubling EC points using projective or
#         Jacobian coordinates.
# 0.7rc8  Adding more edge cases for Xdh.
#         Splitting ec.py
# 0.7rc9  Changing some name of the algorithms, test vector, schemas etc.
#         RsaOaep -> RsaesOaep
#         RsaPss -> RsassaPss
#         RsaSignature -> RsassaPkcs1
# 0.7     Potential release.
#         Fixing documentation for ECDH test vectors.
#         Removing unnecessary labels from notes.
#         More precise type definitions.
#
#         Adding test vectors for timing attacks
# 0.8rc1-3 Internal only. (Later included in 0.7)
#         Adding crash tests for RSA private keys.
#         Changing format of bigints (i.e. length of hexadecimal string
#         is always even. Thus the bigint is a hexadecimal representation
#         of the bytes in ASN.1 encoding.
#         RSA keys now use structures that are based on ASN.
# 0.8rc4  Adding Aegis128, Aegis128L and Aegis256.
# 0.8rc5  Adding tests for MACs with IVs.
# 0.8rc6  Adding tests for VMAC
# 0.8rc7  Adding tests for GMAC
# 0.8rc8  Adding more Koblitz curves.
# 0.8rc9  Using RFC 8410 for the OIDs in EDDSA.
# 0.8rc10  Fixing XDH private key encoding bug. This was the same
#          as https://bugs.java.com/bugdatabase/view_bug.do?bug_id=8213493
# 0.8rc11 Adding test vectors for a arithmetic errors in X448.
# 0.8rc12 Splitting ecutil into ecutil (just keys) and ec_groups
# 0.8rc13 NIST and RFC for KW are different. The RFC allows encrypting
#         8 byte keys.
# 0.8rc14 Adding pem encoded public keys for XDH.
#         Changing format for ECDH test vectors using PEM.
#         Both public and private keys are using PEM.
#         PEM encoded test vectors are still in alpha. (i.e. not
#         checked in)
# 0.8rc15 Adding SHA-3 for RSA PKCS-1 signatures.
# 0.8rc16 Adding truncated SHA-2 signatures to RSA PKCS-1.
#         Generating test vectors for primality tests.
# 0.8rc17 Alphabetically sorting the flags in the footnotes.
# 0.8rc18 Switching to python 3.7:
#         TestVector.test_attributes can now be deprecated, since
#         dictionaries are sorted.
#         Minor format change: all test vectors have flags.
#         Adding P1363 encoded DSA signatures.
#         The field type in test groups is obsolete. It is now declared
#         optional.
# 0.8rc19 Fixing typos in test vectors fields names. This is now part of
#         the unit test. In particular, keySize was sometimes written
#         as keysize.
# 0.8rc20 JSON schemas now include required fields for groups and vectors.
# 0.8rc21 Additional test vectors:
#         longer input sizes for AEAD and DAEAD
#         Changing validity of short and long keys in KW and KWP wrappings
#         from "acceptable" to "valid". If an implementation does not accept
#         these test vectors then they can be excluded via flags.
#         Adding test vectors for HMAC.
# 0.8rc22 Adding HMAC with SHA-512/224 and SHA-512/256
# 0.8rc23 Adding SipHash
#         Adding test vectors with 8192 bit rsa keys.
# 0.8rc24 Test vectors can be generated from python instead of command line.
#         This will hopefully make the test vector generation more flexible.
# 0.8rc25 Footnotes are now local in Test.
#         Adding SHAKE to RSA-PSS and ECDSA.
# 0.8rc26 Adding ARIA-GCM and ARIA-CCM.
# 0.8rc27 Adding Camellia, SEED, SM4 to GCM and CCM
#         Making GCM and CCM algorithm independent.
#         More test vectors for invalid curve attacks.
#         Adding keywrap with Camellia and SEED.
# 0.8rc28 Adding EC private keys to test importing keys.
#         These keys have alpha status, since it is very unclear what
#         constitutes an invalid key. I.e., does it matter if a library
#         does not reject keys with additional garbage at the end?
#         Adding more checks with explicit tags. The validity of some
#         fuzzing results may change, because this affects the asn_parser.
# 0.8rc29 Better verification of PEM encoded private keys. The status of the
#         test vectors changes.
# 0.8rc30 Using strict encoding for PEM (i.e. adding "\n" at the end of the
#         encoding
# 0.8rc31 Test for private keys for XDH and EC now use the same schema.
#         XDH now uses the name of the curves (instead of the name of the
#         primitive).
# 0.8rc32 Adding producers.
# 0.8rc33 Adding faster binary multiplication and sparse reduction.
# 0.8rc34 Replacing asn_parse.py with asn_parser.py
#         asn_parser.py uses stricter rules for valid BER, based on X.690.
#         Error messages should be clearer.
# 0.8rc35 Adding FF1
# 0.8rc36 Code cleanup
# 0.8rc37 Adding more flags
#         The plan is to add more explanations to flags
# 0.9rc1  Changing format for footnotes/flags:
#         A flag is no longer just a single string, it now contains a dict
#         with at least the following entries:
#         "description": a short description of the test vector type.
#         "severity": a guess for the severity of the bug.
#         "cause": potential causes of the bug.
#         "effect": potential effects of the bug.
#         Maybe some indication of dominance. E.g., pseudorandom cases failing
#         dominates special cases failing.
# 0.9rc2  renaming ecutil to ec_key (since ecutil contains just definitions of
#         key.
#         splitting amd_sev.py into amd_sev_rsa.py and amd_sev_rsa.py, to
#         cleanup dependencies.
#         Adding new format for flags.
# 0.9rc3  "severity" replace by "bug_type", since I can only determine the type
#         of bugs that a test vector checks, but not the severity.
# 0.9rc4  info renamed to schema.
#         ECDSA uses publicKey instead of key, etc
# 0.9rc5  Switching to v1 schemas
# 0.9rc6  Adding more curves, bug fixes
# 0.9     Preliminary version for 1.0
#         This should mostly use v.1.0 formats.
#         I'm using version 0.9, so that changes are still possible.:x
GENERATOR_VERSION = "0.9"
ALPHA_VERSION_POSTFIX = "alpha"

LICENSE = """/**
 * @license
 * Copyright 2017 Google Inc. All rights reserved.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
"""

# TODO: needs work
#   This class isn't being used a lot.
#   In some cases the algorithm has no OID, but
#   the algorithm with parameters (e.g. keysize)
#   does have an OID for each variant.
class Algorithm:
  """A class for describing algorithms."""

  def __init__(self,
               name: str,
               description: Optional[str] = None,
               rfc: Optional[str] = None,
               g3doc: Optional[str] = None,
               oid: Optional[str] = None):
    """Defines an algorithm.

    Args:
      name: the name of the algorithm (e.g. "ECDSA")
      description: a short description of the algorithm
      rfc: an RFC if available (e.g. "rfc7253" or "RFC 7253")
      g3doc: a link to the Wycheproof documentation of an algorithm (e.g.
        "dsa.md")
      oid: the OID (e.g. "2.16.840.1.101.3.4.2.10" for SHA3-512)
    """
    self.name = name
    self.description = description
    self.rfc = rfc
    self.g3doc = g3doc
    self.oid = oid

  def __str__(self):
    return self.name


class TestType:
  """A description of the type of the test.

  Subclasses of TestType mainly contain a doc string describing a test.
  The description should contain the primitive that is tested (e.g. AEAD)
  and the operations for which the test vectors are intended.
  (e.g. encryption and/or decryption, signature generation and/or signature
  verification."""

  def get_header(self) -> list[str]:
    """Returns the header of the description of the test type.
       The default is to return the first paragraph of the doc string.
    """
    lines = self.__doc__.split("\n")
    if lines and not lines[0].strip():
      lines = lines[1:]
    c = 0
    while c < len(lines):
      if lines[c].strip() == "":
        break
      c += 1
    # TODO: maybe remove a fixed number of bytes.
    return [l.strip() for l in lines[:c]]

  def json(self):
    """Returns the JSON representation of a test type.
       Typically this is just the name of the subclass.
    """
    return self.__name__

# TODO: Consider to split test vectors into test-data and meta-data.
#   Meta-data would be tcId, comment and flags.
#   result and all additional data is part of the test-data.
#   All test-data could be stored as namedtuple, making this
#   data immutable and hashable.

class TestVector:
  """Base class for test vectors.
  
  TestVectors are essentially dataclasses. The fields of a test vector are
  described in the field schema. Eventually, I might be able to convert the
  code and actually use dataclasses. At the moment this is not possible because
  there is no easy way to add documentation to the fields. Some discussion
  are for example here: 
    https://github.com/python/cpython/issues/86580
    https://github.com/python/cpython/pull/27279

  A test vector contains two sets of fields. Some of the fields are included
  in the test group. I.e. test vectors with the same fields are collected in
  the same test group. Other fields are included in the test vector itself.

  All test vectors contain the fields described in this base class.
  """

  # Attributes that are included in the test cases
  # TODO: remove
  test_attributes = []

  # Attributes that are included in the test group
  group_attributes = []

  status = "base"

  # Description of the members of the subclasses.
  schema = {
    "tcId" : {
        "type" : int,
        "short" : "Identifier of the test case",
        "desc" : """A unique identifier of the test case in a test file.
                    The identifiers are continuous integers. The identifiers
                    of test vectors change between versions of the test file.
                    Hence, the triple (filename, version, tcId) uniquely
                    identifies a test vector."""
    },
    "comment" : {
         "type" : str,
         "desc" : "A brief description of the test case"
    },
    "result" : {
         "type" : str,
         "enum" : ["valid", "invalid", "acceptable"],
         "short" : "Test result",
         "desc" : """The test result. The value determines whether the test case
                     is valid, invalid or undefined. The value "acceptable" is
                     typically used for legacy cases and weak parameters (such as
                     key sizes not reaching 112-bit security).
                     The value "acceptable" has been leading to confusion.
                     Because of this it is no longer used in new test vectors and
                     slowly replaced in old test vectors. Legacy behaviour is
                     now marked with legacy flags. Test vectors with weak parameters
                     are marked with corresponding flags.
                   """
    },
    "flags" : {
        "type" : list[str],
        "short" : "A list of flags",
        "desc" : """A list of flags for a test case.
                    Flags are described in the header of the test file."""
    }
  }

  def __init__(self, **kwargs):
    for n in kwargs:
      setattr(self, n, kwargs[n])

  @classmethod
  def fields(self):
    """Returns the fields that are in the test case of a test vector.
    
     All test vectors have some fields in common. These fields are:
       tcId: an integer that is unique in the test file. The integers are
         contiguous and set when generating the output of a test vector file.
       comment: A short description of the test case.
       result: "valid", "invalid", "acceptable". Describes whether the
         test vector is valid. "acceptable" is used for legacy cases, weak
         parameters etc.
       flags: A list of flags, where the flags are described in the field
         notes in the top level."""
    if hasattr(self, "test_attributes"):
      attributes = self.test_attributes
    else:
      attributes = list(self.schema.keys())
    return (["tcId", "comment", "flags"] + attributes + ["result"])

  @classmethod
  def required_fields(self) -> list[str]:
    """Returns the fields that are required in the test case of a test vector.

    To simplify testing almost all fields are required. Optional fields must
    be marked with "optional" : True.
    """
    attributes = self.fields()
    required = []
    for n in attributes:
      optional = False
      if n in self.schema and "optional" in self.schema[n]:
        optional = self.schema[n]["optional"]
      if not optional:
        required.append(n)
    return required

  @classmethod
  def definition(self, name: str) -> dict:
    if name in self.schema:
      return self.schema[name]
    elif name in TestVector.schema:
      return TestVector.schema[name]
    raise ValueError("Undefined name {name} in {self!r}")

  def __repr__(self) -> str:
    fields = self.fields() + self.group_attributes
    fields = [f for f in fields if hasattr(self, f)]
    arglist = ", ".join(f"{x}={getattr(self, x)!r}" for x in fields)
    return f"{type(self).__name__}({arglist})"

  def testrep(self) -> str:
    """Representation of the test, without tcId and comment and flags.

       This representation is used to detect duplicates and remove them
    """
    fields = self.fields()
    relevant = [
        f for f in fields
        if hasattr(self, f) and f not in ("tcId", "comment", "flags")
    ]
    arglist = ", ".join(f"{f}={getattr(self, f)!r}" for f in relevant)
    return f"{type(self).__name__}({arglist})"


class TestGroup:
  """TestGroup is a base class for all test groups.

     Each test group contains a list of test vectors of the same
     type. The test group describes parameters that are
     common for all the test vectors. Often some parameters
     are given in multiple formats to simplify testing. For example,
     asymmetric private key are typically given in a raw format,
     PKCS #8 encoded and in PEM format. 

     All fields in a test group are corretly formatted.
     Incorrectly formatted inputs are always in the test vectors.

     The list below describes the fields that are common to all
     test groups, though generally a test group contains additional
     fields depending on the test for which the test vectors are
     intended for.
  """
  # static member that must be overwritten by the subclass
  algorithm = None  # None, string, or Algorithm (e.g. "ECDSA")
  vectortype = None  # A subclass of TestVector (Union is deprecated)
  testtype = None  # A subclass of TestType. (str is deprecated)

  status = "base"

  # If False then result == "acceptable" is no longer valid.
  allow_acceptable: bool = True

  schema = {
    "type" : {
      "type" : str,
      "short" : "The type of the test vectors.",
      "desc" : """The type of the test vectors.
                  This field is obsolete, since the type of the test vectors
                  are fixed by the field schema in the header of the file.
                  Every file contains test vectors of only one type. Hence
                  this field is now redundant.""",
      "optional" : True
    },
    "tests" : {
      "type" : list["JSON"],
      "short" : "A list of test vectors",
      "desc" : """A list of test vectors.
                  All test vectors in this list have the same type
                  as defined in the field type.""",
    }
  }

  def __init__(self):
    self.vectors = []  # list of test vectors
    self.tests = dict()  # testrep(x) -> x (used for detecting duplicates)

  @type_check
  def add_test(self, vector: TestVector) -> None:
    rep = vector.testrep()
    if rep in self.tests:
      return
    if vector.result == "acceptable" and not self.allow_acceptable:
      raise ValueError(f"{type(self)} does not allow result =\"acceptable\"")
    self.vectors.append(vector)
    self.tests[rep] = vector

  def group_vectors(self, attribute: str):
    """Sorts the test vector so that test vectors
       with equal values for the given attribute
       are grouped together. The attribute values
       are sorted in the order of their generation."""
    d = collections.defaultdict(list)
    values = []
    for v in self.vectors:
      a = getattr(v, attribute, None)
      if a not in d:
        values.append(a)
      d[a].append(v)
    for a in values:
      for v in d[a]:
        yield v

  def get_all_vectors(self, sort_by: Optional[str] = None):
    if sort_by is None:
      return self.vectors
    else:
      return list(self.group_vectors(sort_by))

  def as_struct(self, sort_by: Optional[str] = None) -> dict[str, Any]:
    raise NotImplementedError()

  def get_header(self) -> list[str]:
    """
    Returns information about this group, that is added to the
    test vector file.
    """
    if issubclass(self.testtype, TestType):
      return self.testtype.get_header(self.testtype)
    else:
      return []

  def schema_name(self) -> str:
    """Returns the name of the schema corresponding to this test."""
    res = ""
    for c in self.testtype.__name__:
      if res and "A" <= c <= "Z":
        res += "_"
      res += c.lower()
    return res + "_schema.json"

  @classmethod
  def required_fields(self) -> list[str]:
    """Returns the fields that are required in the test case of a test group.

    To simplify testing almost all fields are required. Optional fields must
    be marked with "optional" : True.
    """
    attributes = self.schema.keys()
    required = []
    for n in attributes:
      optional = False
      if n in self.schema and "optional" in self.schema[n]:
        optional = self.schema[n]["optional"]
      if not optional:
        required.append(n)
    required.append("tests")
    return required


class Test:
  """The root type of each JSON file with tests.
     Each file contains one ore more test groups.
     Each test group contains one ore more test vectors.
     All test vectors in the same file have the same
     type and test the same cryptographic primitive."""

  schema = {
    "numberOfTests" : {
        "type" : int,
        "short" : "the number of test vectors in this test",
        "desc" : """The number of test vectors in this test.
                    Each test vector has a unique tcId in the range
                    1 .. tcId.""",
    },
    "generatorVersion" : {
        "type" : str,
        "short" : "the version of the test vectors.",
        "desc" : """The version of the test vectors.
                    The version number has the format
                    major.minor (or major.minor[release candidate]).
                    The plan is to change the format of the test
                    vectors in major versions only, once version 1.0
                    has been reached. Conversely, version 1.0
                    will be published once we think the format for
                    the test vectors are sufficiently stable.""",
    },
    "algorithm" : {
        "type" : str,
        "short" : "the primitive tested in the test file",
        "desc" : """The primitive tested in the test file.
                    This is mainly a brief description of the
                    algorithm used. So far there is no formal
                    definition of this field and its description may change.""",
    },
    "header" : {
        "type" : list[str],
        "desc" : "additional documentation",
    },
    "schema" : {
        "type" : str,
        "short" : "the filename of the JSON schema for this test vector file",
        "desc"  : """The filename of the JSON schema that defines the format
                     of the test vectors in this file. If the format of the
                     test vectors changes then a new schema will be generate,
                     so that comparing the name of the schema with an expected
                     name can be used to check for compatibility between
                     test vectors and test code.""",
        "since" : "0.7",
    },
    "notes": {
         "type" : list[flag.Flag],
         "short" : "a description of the labels used in the test vectors",
         "desc" : """A description of the labels used in the test vectors.
                     Some test vectors contain labels that formally describe
                     the test vector. It can be helpful to make test more
                     precise. For example libraries differ in whether they
                     accept ASN encodings different from DER. Hence many
                     of the test vectors with alternative BER encoding are
                     rated as acceptable. Labels allow to decide whether
                     tests with alternatve BER encoding should be rejected
                     or accepted when testing a particular library.""",
    },
    "testGroups" : {
        "type" : list["JSON"],
        "desc" : "a list of test groups",
    },
  }


  def __init__(self,
               algorithm: Union[str, Algorithm],
               args: Optional[argparse.Namespace] = None):
    """Initializes a test.

    Args:
       algorithm: is a string describing the algorithm tested.
       args: if defined is a namespace with parameters.
             Typically these are the command line parameters.
    """
    self.groups = []
    if isinstance(algorithm, Algorithm):
      self.algorithm = algorithm.name
    else:
      self.algorithm = algorithm
    self.testgroups = {}
    self.args = args
    self.foot_notes = footnotes.FootNotes()
    self.header = []
    if args is not None:
      deprecated = getattr(args, "deprecated", None)
      if deprecated:
        self.header.append("Deprecated: " + deprecated)

  def footnotes(self) -> footnotes.FootNotes:
    return self.foot_notes

  def add_group(self, idx, group: TestGroup) -> None:
    self.testgroups[idx] = group
    self.groups.append(group)

  def get_header(self, add_group_headers: bool = True):
    """
    Returns the header of a test vector file.
    Args:
        add_group_headers: includes a description of the tests by including
                           the header of the groups.
    """
    res = self.header[:]
    if add_group_headers:
      done = []
      for g in self.groups:
        if type(g) not in done:
          res += g.get_header()
          done.append(type(g))
    return res

  def version_postfix(self):
    """
    Returns a postfix for the version.

    Mainly this is used to mark files containing test vectors with alpha status.
    Test vectors with alpha status are test vectors with open issues, in
    particular these are test vectors for known, unfixed, exploitable bugs.
    The command-line argument --alpha determines whether such test vectors
    are included.
    """
    if self.args and getattr(self.args, "alpha", False):
      return ALPHA_VERSION_POSTFIX
    return ""

  def schema_name(self) -> str:
    tests = set(g.schema_name() for g in self.groups)
    if len(tests) != 1:
      raise ValueError("Undefined schema for test" + str(tests))
    return list(tests)[0]

  def flags(self) -> set[str]:
    res = set()
    for g in self.groups:
      for tc in g.vectors:
        for l in getattr(tc, "flags", []):
          res.add(l)
    return res

  def as_struct(self,
                cntr: str = "tcId",
                sort_by: str = "comment") -> dict[str, Any]:
    """
    Returns this test group as a dictionary.

    Args:
        cntr: the name of the variable for the id of a test vector.
        sort_by: test vectors with the same value for the given field
                 are grouped together. Otherwise the order of the test
                 vectors is the order of their generation.
    """
    groups = [g.as_struct(sort_by) for g in self.groups]
    testcnt = 0
    for g in groups:
      if isinstance(g, dict) and "tests" in g:
        for tc in g["tests"]:
          testcnt += 1
          setattr(tc, cntr, testcnt)
    d = collections.OrderedDict()
    d["algorithm"] = self.algorithm
    d["schema"] = self.schema_name()
    d["generatorVersion"] =  GENERATOR_VERSION + self.version_postfix()
    d["numberOfTests"] = testcnt
    d["header"] = self.get_header()
    d["notes"] = self.footnotes().ref_list(self.flags())
    d["testGroups"] = groups
    return d

  def format_all_vectors(self, formatter) -> None:
    formatter.open()
    formatter.format_value(self.as_struct())
    formatter.close()

class TestGenerator:
  algorithm = None

  # TODO: Use flags
  def footnotes(self) -> footnotes.FootNotes:
    return self.test.footnotes()

  # TODO: Use flags
  def footnote(self, label: str, text: str) -> str:
    """Generates a footnote.

    Args:
      label: the desired label for the footnote
      text: the text for the footnote
    Returns:
      the actual label for the footnote. The returned label
      may be different from the required label, because of collisions.
    """
    return self.footnotes().ref(label, text)

  def add_flag(self, flag: flag.Flag) -> str:
    return self.footnotes().add_flag(flag)

  def add_flags(self, flags: Optional[list[flag.Flag]]) -> list[str]:
    if not flags:
      return []
    return [self.add_flag(flag) for flag in flags]

  @type_check
  def add_test(self, test: TestVector):
    idx = test.index()
    if idx not in self.test.testgroups:
      g = self.new_testgroup(idx)
      self.test.add_group(idx, g)
    else:
      g = self.test.testgroups[idx]
    g.add_test(test)
