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

import rsa_pss
from rsa_key import RsaPrivateKey

"""Implements some functions from AMD SEV.

The implementation here is based on:

[SEV Spec]
Secure Encrypted Virtualization API Version 0.24
https://www.amd.com/system/files/TechDocs/55766_SEV-KM_API_Specification.pdf

More documentation can be found here:
https://developer.amd.com/sev/
"""

def le_encode(val: int, length: int, signed: bool = False):
  return val.to_bytes(length, 'little', signed=signed)

def encode_rsa_public(key: RsaPrivateKey) -> bytes:
  """Defined in Appendix C.3.1"""
  size = le_encode(key.n.bit_length(), length=4)
  pubexp = le_encode(key.e, length=512)
  modulus = le_encode(key.n, length=512)
  return size + pubexp + modulus

def encode_rsa_pss_signature(sig: bytes) -> bytes:
  """Encodes |s| in little endian."""
  s = rsa_pss.os2ip(sig)
  return le_encode(s, length=512)
