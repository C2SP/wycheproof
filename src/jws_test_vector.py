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

class JwsTestVector(test_vector.TestVector):
  """A test vector with a public key signature.

  The signature is in compact form.
  """
  test_attributes = ["msg", "jws"]
  schema = {
     "msg" : {
         "type" : AST.HexBytes,
         "short": "The payload that was signed in hexadecimal format",
         "desc" : "The payload that was signed in hexadecimal format. "
                  "A JWS signature is computed over the bytestring "
                  "BASE64URL(UTF8(header)) || '.' || BASE64URL(msg)"
     },
     "jws" : {
         "type" : str,
         "desc" : "The signature in compat format",
     }
  }

  def testrep(self):
    return repr(self.jws) + repr(self.msg)

