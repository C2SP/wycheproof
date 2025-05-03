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

import test_vector
import hashlib
import hmac

# TODO: There is a potential for name conflicts:
#   Names such as HMAC-SHA512-256 may either mean HMAC with SHA512/256 or
#   HMAC with SHA-512 trunctated to 256 bits. The goal would be to find such
#   cases, document them and check if the OIDS are used consistently.
#
# RFC 4868
#   defines HMAC-SHA-256-128, HMAC-SHA-384-192, and HMAC-SHA-512-256.
#   uses truncation and has test vectors
#
# RFC 8018
#   defines HMAC-SHA512-256 and HMAC-SHA-512-224
#   uses truncated hash functions (i.e. SHA-512/256 and SHA-512/224)
#   defines OIDs
#   no test vectors

# References:
#   RFC 2104
#   RFC 2202: Test vectors
HASHES = [
    "MD5",
    "SHA-1",
    "SHA-224",
    "SHA-256",
    "SHA-384",
    "SHA-512",
    "SHA3-224",
    "SHA3-256",
    "SHA3-384",
    "SHA3-512",
    "SHA-512/224",
    "SHA-512/256",
]


class HmacAlgorithm(test_vector.Algorithm):

  def __init__(self, md: str):
    self.md = md
    self.oid = None
    self.name = None
    self.hash_func = None
    if md == "MD5":
      self.hash_func = hashlib.sha1
      self.name = "HMACMD5"
      # RFC 8018 does not define an OID for HMAC with MD5 and does not include
      # HMAC with MD5 in the list of algorithms for PBKDF2. The OID below
      # is from openssl, not sure if it is defined somewhere else.
      self.oid = "1.2.840.113549.2.6"
      self.digestf_size = 16
      rfc = None
    elif md == "SHA-1":
      self.hash_func = hashlib.sha1
      self.name = "HMACSHA1"
      self.oid = "1.2.840.113549.2.7"
      self.digest_size = 20
      rfc = 8018
    # There is another OID "1.3.6.1.5.5.8.1.2" in RFC 2630, 3370 and 5911.
    elif md == "SHA-224":
      self.hash_func = hashlib.sha224
      self.name = "HMACSHA224"
      self.oid = "1.2.840.113549.2.8"
      self.digest_size = 28 
      rfc = 4231
    elif md == "SHA-256":
      self.hash_func = hashlib.sha256
      self.name = "HMACSHA256"
      self.oid = "1.2.840.113549.2.9"
      self.digest_size = 32
      rfc = 4231
    elif md == "SHA-384":
      self.hash_func = hashlib.sha384
      self.name = "HMACSHA384"
      self.oid = "1.2.840.113549.2.10"
      self.digest_size = 48
      rfc = 4231
    elif md == "SHA-512":
      self.hash_func = hashlib.sha512
      self.name = "HMACSHA512"
      self.oid = "1.2.840.113549.2.11"
      self.digest_size = 64
      rfc = 4231
    elif md == "SHA-512/224":
      # Algorithms names such as HMAC-SHA-512/224 are ambiguous, since they
      # can either refer to HMAC-SHA-512 truncated to 224 bits or HMAC with
      # SHA-512/224. Both versions exist.
      # This algorithm computes HMAC with SHA-512/224 as defined in RFC 8018.
      self.hash_func = lambda: hashlib.new("sha512-224")
      self.name = "HMACSHA512/224"
      self.oid = "1.2.840.113549.2.12"
      self.digest_size = 28
      rfc = 8018
    elif md == "SHA-512/256":
      # Algorithms names such as HMAC-SHA-512/256 are ambiguous, since they
      # can either refer to HMAC-SHA-512 truncated to 256 bits or HMAC with
      # SHA-512/256. Both versions exist.
      # This algorithm computes HMAC with SHA-512/256 as defined in RFC 8018.
      self.hash_func = lambda: hashlib.new("sha512-256")
      self.name = "HMACSHA512/256"
      self.oid = "1.2.840.113549.2.13"
      self.digest_size = 32
      rfc = 8018
    elif md == "SHA3-224":
      self.hash_func = hashlib.sha3_224
      self.name = "HMACSHA3-224"
      self.oid = "2.16.840.1.101.3.4.2.13"
      self.digest_size = 28
      rfc = None
    elif md == "SHA3-256":
      self.hash_func = hashlib.sha3_256
      self.name = "HMACSHA3-256"
      self.oid = "2.16.840.1.101.3.4.2.14"
      self.digest_size = 32
      rfc = None
    elif md == "SHA3-384":
      self.hash_func = hashlib.sha3_384
      self.name = "HMACSHA3-384"
      self.oid = "2.16.840.1.101.3.4.2.15"
      self.digest_size = 48
      rfc = None
    elif md == "SHA3-512":
      self.hash_func = hashlib.sha3_512
      self.oid = "2.16.840.1.101.3.4.2.16"
      self.name = "HMACSHA3-512"
      self.digest_size = 64
      rfc = None
    else:
      raise ValueError("Unknown algorithm:" + md)
    if isinstance(rfc, int):
      self.rfc = "rfc%d" % rfc
    else:
      self.rfc = rfc

  def new(self, key: bytes):
    return hmac.new(key, digestmod=self.hash_func)


OID_TABLE = None


def from_oid(oid):
  global OID_TABLE
  oid = str(oid)
  if OID_TABLE is None:
    OID_TABLE = {}
    for md in HASHES:
      alg = HmacAlgorithm(md)
      if alg.oid:
        OID_TABLE[alg.oid] = alg
  if oid in OID_TABLE:
    return OID_TABLE[oid]
  else:
    raise ValueError("Unknown OID:" + oid)
