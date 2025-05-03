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

import AST
import test_vector

class SignatureTestVector(test_vector.TestVector):
  '''A test vector with a public key signature.

     This structure is used for public key signatures where the primitive
     specifies the encoding as an array of bytes (e.g. P1363 encoded
     ECDSA signatures.) Public key signatures with
     additional formatting (e.g. ASN.1 encoded ECDSA signatures) have their
     separate types.
  '''
  test_attributes = ['msg', 'sig']
  schema = {
     'msg' : {
         'type' : AST.HexBytes,
         'desc' : 'The message to sign',
     },
     'sig' : {
         'type' : AST.HexBytes,
         'desc' : 'A signature for msg',
     }
  }

  def testrep(self):
    return repr(self.sig) + repr(self.msg)

class AsnSignatureTestVector(test_vector.TestVector):
  '''A test vector with an ASN.1 encoded public key signature.
     
     For example, ECDSA and DSA signatures are a pair of integers (r,s).
     These integers can be encoded in different ways. A popular encoding
     is to represent the integers as an ASN Sequence.

     The expectation is that any library generates only DER encoded signatures.
     Some libraries are also strict in the sense that only DER encoded signautes
     are accepted. Other libraries accept some signatures where the pair (r,s)
     uses an alternative BER encoding assuming of course that the encoded (r,s)
     is valid.
  '''
  test_attributes = ['msg', 'sig']
  schema = {
     'msg' : {
         'type' : AST.HexBytes,
         'desc' : 'The message to sign',
     },
     'sig' : {
         'type' : 'Asn',
         'desc' : 'An ASN encoded signature for msg',
     }
  }

  def testrep(self):
    return repr(self.sig) + repr(self.msg)

