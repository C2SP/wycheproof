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

import ec_key
import ec_groups
"""Implements some functions from AMD SEV.

The implementation here is based on:

[SEV Spec]
Secure Encrypted Virtualization API Version 0.24
https://www.amd.com/system/files/TechDocs/55766_SEV-KM_API_Specification.pdf

More documentation can be found here:
https://developer.amd.com/sev/
"""

# See also:
#
# https://github.com/AMDESE/AMDSEV

amd_sev_curves = [ec_groups.curveP256,
                  ec_groups.curveP384,
                  ec_groups.secp256k1]

def le_encode(val: int, length: int, signed: bool = False):
  return val.to_bytes(length, 'little', signed=signed)

def group_id(group: ec_groups.EcGroup):
  """Returns the id of an EC group.

  This is defined in Section C.2."""
  if group.name == "secp256r1": return 1
  elif group.name == "secp384r1": return 2
  elif group.name == "secp256k1": return 3
  else: return None


def encode_ec_public(pub: ec_key.EcPublicKey) -> bytes:
  '''Defined in Section C.3.3'''
  group = pub.group
  gid = group_id(group)
  if not pub.verify_named_curve():
    raise ValueError("Unnamed groups are not supported")
  if gid is None:
    raise ValueError("Unsupported group:" + group.name)
  if not pub.w:
    raise ValueError("Point w of public key is missing")
  wx = le_encode(pub.w[0], length=72)
  wy = le_encode(pub.w[1], length=72)
  reserved = bytes(364)
  return bytes([gid, 0, 0, 0]) + wx + wy + reserved

def encode_ec_private(priv: int, strict: bool = False) -> bytes:
  # TODO: Check if length=72 in the encding below is correct.
  return le_encode(priv, length=72, signed=priv < 0 and not strict)

def ecdsa_sig(r: int, s: int, allow_invalid: bool=True) -> bytes:
  """Encodes ECDSA signatures

  The format of an ECDSA signature is defined in Section C 4.2.

  Args:
     r: the value r of the signature
     s: the value s of the signature
     allow_invalid: if True then negative values for r and s are allowed.
       Negative integers are encoded using two's complement.
  """
  rb = le_encode(r, length=72, signed=allow_invalid and r < 0)
  sb = le_encode(s, length=72, signed=allow_invalid and s < 0)
  reserved = bytes(368)
  return rb + sb + reserved
