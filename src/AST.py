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

# ===== Syntax tree =====
# Allowed:
#   string, integer, None, array, bytearray
#   BigInt
#
# TODO: Since TestVectors have types, it is no longer
#   necessary that the caller wraps BigIntegers into this
#   BigInt class. The TestVector could do this.


def _int2hex(n: int) -> str:
  """Converts an integer into a hexadecimal representation.

  This function uses two's complement representation and bigendian ordering.
  The size of the result is divisible by 0.
  Args:
    n: the integer to convert.
  """
  if n == 0:
    nbytes = 1
  elif n > 0:
    nbytes = 1 + n.bit_length() // 8
  elif n < 0:
    nbytes = 1 + (~n).bit_length() // 8
  return n.to_bytes(nbytes, "big", signed=True).hex()


# TODO: Unify the type here and the type in the JSON schemas.
class BigInt:
  """A class to represent BigIntegers.

  Wycheproof represents BigIntegers as hexadecimal strings.

  A possible JSON schema for this type is:
  "BigInt": {
    "type": "string",
    "pattern: "^[0-9a-fA-F]{2}*$",
    "description": "An BigInteger encoded using twos complement hexadecimal encoding"
  }
  """
  reference = ("formats", "Data types")
  def __init__(self, n: int):
    self.n = n

  def json(self):
    return _int2hex(self.n)

  def __repr__(self):
    return "BigInt(%s)" % repr(self.n)

  __str__ = __repr__


class HexBytes(str):
  """The JSON representation for an array of bytes.

  A possible JSON schema for this type is:

  "HexBytes": {
    "type": "string",
    "pattern": "^([0-9a-fA-F]{2})*$",
    "description": "A hexadecimal encoded array of bytes"
  }
  """
  reference = ("formats", "Data types")

  def json(self):
    return self


class Base64Url(str):
  """A byte array encoded in base64url.

    "Base64Url": {
      "type": "string",
      "pattern": "^([-_0-9a-zA-Z=])*$", (needs checking)
      "description": "A base64url encoded array of bytes"
    }
  """
  reference = ("formats", "Data types")

  def json(self):
    return self

class EcCurve(str):
  """The name of an elliptic curve.

  A possible JSON schema for this type is:

  "EcCurve": {
    "type": "string",
    "enum" : [
      "secp256r1",
      ...
    "description": "The name of an elliptic curve"
  }
  """

  reference = ("formats", "Elliptic curves")

  def json(self):
    return self

# TODO: make generic. E.g.,
#   S = typing.TypeVar['S']
#   class Asn(typing.Generic[S]):
#     def __init__(asn: bytes):
#       self.asn = asn
#     def json(self):
#       return self.asn.hex()
#
# PublicKeyAsn = Asn[asn1crypto.SubjectPublicKeyInfo]
class Asn(str):
  """Hexadecimal encoded ASN.

  The ASN value in the test vector might be invalid.
  The only guarantee given is that it is a hexadecimal
  encoded string. I.e. possible JSON schema for this type is:

  "ASN": {
    "type": "string",
    "pattern": "^([0-9a-fA-F]{2})*$",
    "description":
       "A hexadecimal encoded string, which is valid or currupted ASN"
  }
  """
  reference = ("formats", "Data types")
  def json(self):
    return self

class Der(str):
  """Hexadecimal encoded ASN.

  This field contains a valid DER encoded value.
  ASN parsing of this value is not part of the test.

  "DER": {
    "type": "string",
    "pattern": "^([0-9a-fA-F]{2})*$",
    "description": 
       "A valid DER encoded value in hexadecimal representation"
  }
  """
  reference = ("formats", "Data types")
  def json(self):
    return self


# TODO: PEM should be a generic type.
#   Arguments are the ASN type, reference, header & footer.
class Pem(str):
  """A PEM encoded key.
  """
  reference = ("formats", "Data types")

  def json(self):
    return self

class MdName(str):
  """The name of a hash function:

  A possible JSON schema for this type is:

  "MdName": {
    "type": "string",
    "enum" : [
      "SHA-1", "SHA-224", ... , "SHA3-256"
        ...
    "description": "The name of a hash function"
  }
  """
  reference = ("formats", "Hash functions")
  def json(self):
    return self
