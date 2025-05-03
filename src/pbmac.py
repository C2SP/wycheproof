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

# RFC 8018
class Pbmac1:
  def __init__(self,
               kdf,
               mac,
               password: bytes,
               macsize: int,
               itercount: int,
               dklen: int):
    "Initializes Pbmac1"
    self.kdf = kdf
    self.password = password
    self.macsize = macsize
    self.itercount = itercount
 
  def mac(salt: bytes, msg: bytes) -> bytes:
    dk = self.kdf(self.password, salt, self.itercount, self.dklen)
    mac_instance = mac(dk)
    return mac_instance(msg)

# ASN (RFC 8018)
#
# PBMAC1Algorithms ALGORITHM-IDENTIFIER ::= {
#      {PBMAC1-params IDENTIFIED BY id-PBMAC1},
#      ...
#   }
#  id-PBMAC1 OBJECT IDENTIFIER ::= {pkcs-5 14}
#
#   PBMAC1-params ::=  SEQUENCE {
#       keyDerivationFunc AlgorithmIdentifier {{PBMAC1-KDFs}},
#       messageAuthScheme AlgorithmIdentifier {{PBMAC1-MACs}}
#   }
#   PBMAC1-KDFs ALGORITHM-IDENTIFIER ::= {
#      {PBKDF2-params IDENTIFIED BY id-PBKDF2},
#      ...
#   }
#   PBMAC1-MACs ALGORITHM-IDENTIFIER ::= { ... }

# Supported algorithms:
#   id-hmacWithSHA1 OBJECT IDENTIFIER ::= {digestAlgorithm 7}
#   id-hmacWithSHA224 OBJECT IDENTIFIER ::= {digestAlgorithm 8}
#   id-hmacWithSHA256 OBJECT IDENTIFIER ::= {digestAlgorithm 9}
#   id-hmacWithSHA384 OBJECT IDENTIFIER ::= {digestAlgorithm 10}
#   id-hmacWithSHA512 OBJECT IDENTIFIER ::= {digestAlgorithm 11}
#   id-hmacWithSHA512-224 OBJECT IDENTIFIER ::= {digestAlgorithm 12}
#   id-hmacWithSHA512-256 OBJECT IDENTIFIER ::= {digestAlgorithm 13}

def test():
  pass

if __name__ == "__main__":
  test()
