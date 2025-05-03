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
from typing import Optional

# The ECDSA algorithm parameters
# The name of the algorithm is the JWK name
# The parameter names are the Wycheproof names.
ECDSA_ALGORITHMS = {
  "ES256" : {
    "md" : "SHA-256",
    "crv": "secp256r1",
    "field_size": 32,
  },
  "ES384" : {
    "md" : "SHA-384",
    "crv": "secp384r1",
    "field_size": 48,
  },
  "ES521" : {
    "md": "SHA-512",
    "crv": "secp521r1",
    "field_size": 66
  },
  "ES256K": {
    "md": "SHA-256",
    "crv": "secp256k1",
    "field_size" : 32
  }
}

RSASSA_PKCS1_ALGORITHMS = {
  "RS256" : {
    "md" : "SHA-256"
  },
  "RS384" : {
    "md" : "SHA-384"
  },
  "RS512" : {
    "md" : "SHA-512"
  }
}

RSASSA_PSS_ALGORITHMS = {
  "PS256" : {
    "md" : "SHA-256",
    "mgf" : "MGF1",
    "mgf_md" : "SHA-256",
    "s_len" : 32,
  },
  "PS384" : {
    "md" : "SHA-384",
    "mgf" : "MGF1",
    "mgf_md" : "SHA-384",
    "s_len" : 48,
  },
  "PS512" : {
    "md" : "SHA-512",
    "mgf" : "MGF1",
    "mgf_md" : "SHA-512",
    "s_len" : 64,
  }
}

def ecdsa_algorithm(curve: str, md: str) -> Optional[str]:
  for alg, params in ECDSA_ALGORITHMS.items():
    if params["crv"] == curve and params["md"] == md:
      return alg

def rsassa_pkcs1_algorithm(md: str) -> Optional[str]:
  for alg, params in RSASSA_PKCS1_ALGORITHMS.items():
    if params["md"] == md:
      return alg

def rsassa_pss_algorithm(md: str, mgf: str, mgf_md: str, s_len: int) -> Optional[str]:
  for alg, params in RSASSA_PSS_ALGORITHMS.items():
    if (params["md"] == md and 
        params["mgf"] == mgf and
        params["mgf_md"] == mgf_md and
        params["s_len"] == s_len): return alg

def jws_header(alg:str, kid: Optional[str]) -> bytes:
    if kid is not None:
      h = f'"alg":"{alg}","kid":"{kid}"'
    else:
      h = f'"alg":"{alg}"'
    hs = "{" + h + "}"
    return hs.encode("utf-8")


