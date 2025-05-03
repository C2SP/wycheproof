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

import hmac
import json
import jw_util

# Other MACs that I can find:
# HS224: jwt-core/pdi.jwt/JwtAlgorithm/HS224
# HMD5: jwt-core/pdi.jwt/JwtAlgorithm/HMD5

# The OID is for the HMAC algorithm and has nothing to do with JWS.

# RFC 7518 Section 3.2: key size must be the same or larger than
# the digest size. 
# But then why is the key size smaller for A128CBC-HS256?

MAC_ALGORITHMS = {
  "HS256" : {
    "md" : "SHA-256",
    "min_key_size" : 32,
    "digest_size" : 32,
    "oid" : "1.2.840.113549.2.9"
  },
  "HS384" : {
    "md" : "SHA-384",
    "min_key_size" : 48,
    "digest_size" : 48,
    "oid" : "1.2.840.113549.2.10"
  },
  "HS512" : {
    "md" : "SHA-512",
    "min_key_size" : 64,
    "digest_size" : 64,
    "oid" : "1.2.840.113549.2.11"
  }
}

class Hs:
  def __init__(self,
               alg: str,
               key: bytes,
               kid: str,
               validate: bool = True):
    """Constructs a HMAC instance.
    
    Args:
      alg: the algorithm (HS256, HS384 or HS512)
      key: the HMAC key
      kid: the kid
      validate: skips key validation if False
    """
    self.alg = alg
    self.key = key
    self.kid = kid
    if alg not in MAC_ALGORITHMS:
      raise ValueError("unknown algorithm:" + alg)
    params = MAC_ALGORITHMS[alg]
    self.md = params["md"]
    if validate:
      if len(key) < params["min_key_size"]:
        raise ValueError("key too short")

  def header(self) -> str:
    h = {"alg" : self.alg, "kid" : self.kid}
    return json.dumps(h, separators=(",", ":"))

  def raw_mac(self, data: bytes) -> bytes:
    return hmac.digest(self.key, data, self.md)

  def mac(self, payload: bytes) -> bytes:
    h = self.header()
    data : bytes = jw_util.encode_str(h) + b"." + jw_util.encode(payload)
    mac : bytes = self.raw_mac(data)
    return data + b"." + jw_util.encode(mac)

  def decode_and_verify(self, mac: bytes) -> bytes:
    parts = mac.split(b".")
    if len(parts) != 3:
      raise ValueError("Expected 3 parts")
    header = json.loads(jw_util.decode_str(parts[0]))
    if "alg" not in header:
      raise ValueError("Missing alg")
    if header["alg"] != self.alg:
      raise ValueError("Wrong alg")
    if "kid" in header:
      if header["kid"] != self.kid:
        raise ValueError("Wrong kid")
    if "crit" in header:
      raise ValueError("No crit parameter implemented")
    data = parts[0] + b"." + parts[1]
    mac = self.raw_mac(data)
    if not hmac.compare_digest(mac, jw_util.decode(parts[2])):
      raise ValueError("Mac verification failed")
    return jw_util.decode(parts[1])      
    
  def as_struct(self):
    res = {
      "kty" : "oct",
      "use" : "sig",
      "kid" : self.kid,
      "alg" : self.alg,
      "k" : jw_util.encode(self.key).decode("ascii")
    }
    return res

