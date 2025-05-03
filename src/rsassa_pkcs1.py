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

import asn
import asn_fuzzing
import AST
import hashlib
import rsa_key
import util
from typing import Optional, Union
from util import type_check
import conversions


# TODO:
# - move most functions into corresponding classes
# - generate test vectors with leading 00
# - generate special case RSA keys (i.e. it is possible to
#   generate RSA keys where half of the leading bits are
#   predetermined. Similarly half of the trailing bits
#   can be fixed.

# ===== ASN =====
@type_check
def asn_padding_struct(
    message: bytes,
    md: str,
    digest: Optional[bytes] = None) -> list:
  """Returns the ASN encoded digest of a message.

     message : Ascii string of the message
     md : name of the message digest ("SHA-1", "SHA-256", etc.)
     digest: the digest to use. Either a hexadecimal string or a bytearray.
       This argument is optional and can be used to generate encoding with
       incorrect digests.
  """
  if digest is None:
    digest = util.hash(md, message)
  oid = asn.oid_from_hash(md)
  return [[oid, asn.Null()], asn.OctetString(digest, description="digest")]


def named_asn_padding_struct(message: bytes,
                             md: str,
                             digest: Optional[bytes] = None) -> list:
  """Returns the ASN encoded digest of a message.

     message : Ascii string of the message
     md : name of the message digest ("SHA-1", "SHA-256", etc.)
     digest: the digest to use. Either a hexadecimal string or a bytearray.
       This argument is optional and can be used to generate encoding with
       incorrect digests.
  """
  if digest is None:
    digest = util.hash(md, message)
  oid = asn.oid_from_hash(md)
  return asn.Named("digestInfo", [
      asn.Named("digestAlgorithm", [oid, asn.Null()]),
      asn.OctetString(digest, description="digest")
  ])

# ===== RSA signature class =====
class RsassaPkcs1:
  """A class for generating RSASSA-PKCS1 test vectors.
     This class adds functionality for generating weak signatures.
     The class must only be used for testing, since some of these signatures
     may leak the private key."""
  @type_check
  def __init__(self, key: rsa_key.RsaPrivateKey, md: str):
    self.key = key
    self.md = md
    self.keysize = (self.key.n.bit_length() + 7) // 8

  @type_check
  def sign_padding(self, p: bytes)->int:
    """p is the asn encoded digest"""
    pad_len = self.keysize - len(p) - 3
    pad = bytes([0, 1]) + bytes([0xff]) * pad_len + bytes(1) + p
    return self.key.private_exp(conversions.os2ip(pad))

  @type_check
  def sign(self, message: bytes) -> bytes:
    pad_struct = asn_padding_struct(message, self.md)
    pad = asn.encode(pad_struct)
    sig = self.sign_padding(pad)
    return sig.to_bytes(self.keysize, "big")

  def modified_sign(self, message: bytes, case) -> bytes:
    pass
