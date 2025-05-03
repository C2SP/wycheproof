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

from typing import Union, Optional
import rsa_key
import ec_key
import test_vector
import AST

JwkPublicKey = Union[rsa_key.JwkRsaPublicKey, ec_key.JwkEcPublicKey]
JwkPrivateKey = Union[rsa_key.JwkRsaPrivateKey, ec_key.JwkEcPrivateKey]

class Recipient:
  """Recipient specific information Section 7.2.1 of RFC 7516"""
  schema = {
      "header" : {
          "type" : "object",
          "desc" : "header information that is not integrity protected"
      },
      "encrypted_key" : {
          "type" : AST.Base64Url,
          "desc" " "the encrypted key",
      }
  }

class JsonWebEncryptionSerialization:
  """General JWE JSON Serialization descripted in Section 7.2.1 of RFC 7516"""
  schema = {
          "type" : AST.Base64Url,
          "desc" : "an integrity protected header"
     },
     "unprotected" : {
          "type" : "object",
          "desc" : "unprotected header values"
     },
     "iv" : {
          "type" : AST.Base64Url,
          "desc" : "the IV"
     },
     "aad" : {
          "type" : AST.Base64Url,
          "desc" : "additional authenticated data"
     },
     "ciphertext" : {
          "type" : AST.Base64Url,
          "desc" : "the ciphertext"
     },
     "tag" : {
          "type" : AST.Base64Url,
          "desc" : "the authentication tag"
        },
     "recipients" : {
          "type" : list[Recipient],
          "desc" : "a list of recipients"
     }
   }


class JsonWebEncryptionTestVector(test_vector.TestVector):
  """A test vector for a key exchange using Json Web encryption from RFC 7516.

  """
  test_attributes = ["jwe", "pt"]
  group_attributes = ["public", "private", "enc"] 
  schema = {
      "enc": {
          "type": "string",
          "short": "the content encryption algorithm",
          "desc" : "The content encryption algorithm used in the test vector."
                   " This algorithm is part of the jwe header. The value is replicated"
                   " so that tests for libraries that restrict the list of algorithms"
                   " can determine if a test vector should pass or be rejected."
      },
      "jwe": {
          "type": Union[JsonWebEncryptionSerialization, str],
          "desc": "The JSOn serialization form"
      },
      "pt": {
          "type": AST.HexBytes,
          "desc": "[optional] Plaintext"
      }

  }
  def index(self):
    return (str(self.private), self.enc)

class JsonWebEncryptionTest(test_vector.TestType):
  """Test vectors of type JsonWebEncryptionTest are intended for tests that verify the
     decryption of JWE encrypted ciphertexts.
  """

class JsonWebEncryptionTestGroup(test_vector.TestGroup):
  algorithm = "XDH"
  vectortype = JsonWebEncryptionTestVector
  testtype = JsonWebEncryptionTest
  schema = {
      "comment": {
          "type": "string",
          "description": "a description of what these tests have in common"
      },
      "private": {
          "type": JwkPrivateKey,
          "desc": "the private key"
      },
      "public": {
          "type": JwkPublicKey,
          "desc": "the [optional] public key",
          "optional": True,
      }
  }

  def __init__(self, curve):
    super().__init__()
    self.curve = curve

  def as_struct(self, sort_by: Optional[str] = None):
    if sort_by is None:
      sort_by = "comment"
    group = {}
    group["type"] = self.testtype
    group["comment"] = self.comment
    group["private"] = self.private
    group["public"] = self.public
    group["tests"] = self.get_all_vectors(sort_by=sort_by)
    return group


