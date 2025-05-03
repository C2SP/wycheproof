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
import AST
import base64
import ec
import ec_groups
import pem_util
from typing import Optional, Union, Any
import util

# TODO:
#   RFC 5758 defines ECDSA signature algorithms
#   ecdsa-with-SHA224 OBJECT IDENTIFIER ::= { iso(1) member-body(2)
#        us(840) ansi-X9-62(10045) signatures(4) ecdsa-with-SHA2(3) 1 }
#
#   ecdsa-with-SHA256 OBJECT IDENTIFIER ::= { iso(1) member-body(2)
#       us(840) ansi-X9-62(10045) signatures(4) ecdsa-with-SHA2(3) 2 }
#
#  ecdsa-with-SHA384 OBJECT IDENTIFIER ::= { iso(1) member-body(2)
#       us(840) ansi-X9-62(10045) signatures(4) ecdsa-with-SHA2(3) 3 }
#
#   ecdsa-with-SHA512 OBJECT IDENTIFIER ::= { iso(1) member-body(2)
#        us(840) ansi-X9-62(10045) signatures(4) ecdsa-with-SHA2(3) 4 }

class EcPrivateKey:
  @util.type_check
  def __init__(self, group: ec_groups.EcGroup, s: int):
    """Constructs an EC private key.

    Args:
      group: the elliptic curve of the key
      s: the private key
    """
    self.group = group
    self.s = s
    self.pub = None

  def public(self) -> "EcPublicKey":
    """Returns the public key of this key."""
    if self.pub is None:
      y = self.s * self.group.generator()
      self.pub = EcPublicKey(self.group, y.affine())
    return self.pub

  def asn_struct(self,
                 *,
                 use_name: bool = True,
                 include_public: bool = False) -> asn.AsnStructure:
    """Returns the ASN structure of this key.

    This structure is defined in https://tools.ietf.org/html/rfc5915.

    Args:
      use_name: if True then the oid for a named curve is used (if possible), if
        False then the parameters of the elliptic curve are used to represent
        the key:
      include_public: if True then the public key is included in the ASN
        structure.
    """
    oid = asn.Oid("2a8648ce3d0201")
    ecparams = self.group.asn_struct(use_name=use_name)
    if use_name:
      ecparams = asn.Named("parameters", ecparams)
    bytes = self.group.encoding_length
    # ECPrivateKey from Section 3 or Section A of RFC 5915
    priv_bytes = asn.OctetString(asn.encode_bigint_fixedlength(self.s, bytes))
    if include_public:
      pub_point = asn.BitString(self.public().encode_pub_point())
      pub_key = asn.Explicit(1, pub_point, asn.CONTEXT_SPECIFIC, True)
      priv = asn.Sequence(version=1, privateKey=priv_bytes, publicKey=pub_key)
    else:
      priv = asn.Sequence(version=1, privateKey=priv_bytes)
    # TODO: I need a reference for this.
    privkey_struct = [0, [oid, ecparams], asn.OctetStringFromStruct(priv)]
    return privkey_struct

  def encode(self,
             use_name: bool = True,
             include_public: bool = False) -> bytes:
    """Encodes this key.

    The encoding uses RFC 5915.

    Args:
      use_name: if True then the oid for a named curve is used (if possible),
          if False then the parameters of the elliptic curve are encoded.
      include_public: if True then the public key is included in the ASN
          encoding.
    """
    return asn.encode(
        self.asn_struct(use_name=use_name, include_public=include_public))

  def encode_b64(self,
                 use_name: bool = True,
                 include_public: bool = False) -> str:
    """Returns a base64 encoding of this key.

    This is a base 64 encoding of the ASN encoding defined in RFC 5915.

    Args:
      use_name: if True then the oid for a named curve is used (if possible),
          if False then the parameters of the elliptic curve are encoded.
      include_public: if True then the public key is included in the ASN
          encoding.
    """
    return asn.encode_b64(
        self.asn_struct(use_name=use_name, include_public=includ_public))

  def pem(self) -> str:
    """Returns a pem encoding of this key."""
    return pem_util.private_key_pem(self.encode())

  def jwk(self) -> dict[str, str]:
    """Returns a jwk representation of this key."""
    c = self.group
    length = (c.p.bit_length() + 7) // 8
    pub = self.public()
    return {
      "kty" : "EC",
      "crv" : c.jwk(),
      "d" : util.uint2urlsafe64(self.s, length),
      "x" : util.uint2urlsafe64(pub.w[0], length),
      "y" : util.uint2urlsafe64(pub.w[1], length),
      "kid" : "none",
    }

class JwkEcPublicKey:
  schema = {
    "kty" : {
        "type" : str,
        "enum" : ["EC"],
        "desc" : "the algorithm",
    },
    "use" : {
        "type" : str,
        "desc" : " the purpose of the key"
    },
    "kid" : {
        "type" : str,
        "desc" : "the key id",
    },
    "crv" : {
        "type" : str,
        "enum" : ec_groups.JWK_CURVES,
        "desc" : "the curve",
    },
    "x" : {
        "type" : AST.Base64Url,
        "desc" : "The x-coordinate of the public point",
    },
    "y" : {
        "type" : AST.Base64Url,
        "desc" : "The y-coordinate of the public point",
    }
  }

class JwkEcPrivateKey:
  schema = {
    "kty" : {
        "type" : str,
        "enum" : ["EC"],
        "desc" : "the algorithm",
    },
    "use" : {
        "type" : str,
        "desc" : " the purpose of the key"
    },
    "kid" : {
        "type" : str,
        "desc" : "the key id",
    },
    "crv" : {
        "type" : str,
        "enum" : ec_groups.JWK_CURVES,
        "desc" : "the curve",
    },
    "x" : {
        "type" : AST.Base64Url,
        "desc" : "The x-coordinate of the public point",
    },
    "y" : {
        "type" : AST.Base64Url,
        "desc" : "The y-coordinate of the public point",
    },
    "d" : {
        "type" : AST.Base64Url,
        "desc" : "The private multiplier",
    }
  }

class EcPublicKey:
  """An EC public key.

  The EC public key can specify the underlying curve
  parameters in two ways. (1) as a named curve
  (2) as a structure containing the curve parameters
  generator, order and cofactor.
  """
  schema = {
    "type" : {
       "type" : str,
       "enum" : ["EcPublicKey"],
       "desc" : "the key type",
    },
    "curve" : {
       "type" : Union[ec_groups.EcUnnamedGroup, ec_groups.EcNamedGroup],
       "desc" : "the EC group used by this public key",
    },
    "keySize": {
       "type" : int,
       "desc" : "the key size in bits",
    },
    "uncompressed" : {
       "type" : AST.HexBytes,
       "short" : "encoded public key point",
       "desc" : "X509 encoded public key point in hexadecimal format"
    },
    "wx" : {
       "type" : AST.BigInt,
       "desc" : "the x-coordinate of the public key point",
    },
    "wy" : {
       "type" : AST.BigInt,
       "desc" : "the y-coordinate of the public key point",
    },
  }

  @util.type_check
  def __init__(self,
               group: ec_groups.EcGroup,
               w=None,
               use: Optional[str] = "sign",
               compressed: Optional[bool] = False,
               encoded_point: Optional[bytes] = None):
    """Constructs a new EcPublic key.

    Args:
      w: the point of the public key as a pair of integer coordinates.
         This point can be None if the encoding is given.
      use: used for jwk
      compressed: whether the public key should be compressed
      encoded_point: the encoding of the point. This argument can
         be specified instead of w. This allows to specify invalid
         public keys.
    """
    assert w is not None or encoded_point is not None
    self.group = group
    self.w = w
    self.use = use
    self.compressed = compressed
    self.encoded_point = encoded_point

  def point(self):
    """Returns the point of the public key"""
    if self.w is None:
      raise ValueError("public point is unknown")
    wx, wy = self.w
    return self.group.get_point(wx, wy)

  def affine(self):
    """Returns the affine coordinate of the public point"""
    if self.w is None:
      raise ValueError("public point is unknown")
    return self.w

  def flags(self, footnotes):
    """Returns a number of flags that indicate why this public key
       might be special. This helps to identify bugs in libraries."""
    flags = []
    if self.compressed:
      flags.append(footnotes.ref("CompressedPoint",
          """The point in the public key is compressed.
             Not every library supports points in compressed format."""))
    if not self.verify_named_curve():
      flags.append(footnotes.ref("UnnamedCurve",
          """The public key does not use a named curve.
             RFC 3279 allows to encode such curves by
             explicitly encoding, the parameters of the curve equation,
             modulus, generator, order and cofactor.
             However, many crypto libraries only support named curves.
             Modifying some of the EC parameters and encoding the
             corresponding public key as an unnamed curve is a potential
             attack vector."""))
    if self.encoded_point and self.encoded_point != self.encode_pub_point():
      flags.append(footnotes.ref("InvalidPointEncoding",
        """The point of the public key uses an invalid encoding."""))
    return flags

  def verify_named_curve(self):
    """returns true if this is the curve that self.group.name claims to be"""
    c = self.group
    return ec_groups.named_curve(self.group.name) == c

  def encode_pub_point(self) -> bytes:
    """Encodes the point of the public key.

    The format is 0x04 || x || y  for uncompressed points and
    0x02 || x or 0x03 || x for compressed points.
    """
    if self.encoded_point is not None:
      return self.encoded_point
    if self.compressed:
      return self.group.encode_compressed(self.w)
    else:
      return self.group.encode_uncompressed(self.w)

  def asEcPublicKeyOnNamedCurve(self):
    if isinstance(self, EcPublicKeyOnNamedCurve):
      return self
    elif self.verify_named_curve():
      return EcPublicKeyOnNamedCurve(
          self.group, self.w, self.use, self.compressed, self.encoded_point)
    else:
      raise ValueError("public key is not on a named curve")

  # TODO: Add some form of typing.
  #   Maybe rename the function to subject_public_key_info to reflext the
  #   type of the result.
  def asn_struct(self, use_name: bool = True):
    """Returns a structure of type SubjectPublicKeyInfo"

    RFC 3280, Section 4.1 defines SubjectPublicKeyInfo
    RFC 3279, defines the structure of EC keys.
       Section 2.3.5 defines id-ecPublicKey
    RFC 5758 updates RFC 3279
       Section 3.2 defines algorithm identifiers for ECDSA.
    RFC 5754 updates algorithm identifier for SHA-2.
       Section 3.3 defines the algorithm identifier for ECDSA.
       Not sure if this is a repetition of RFC 5758.
    """

    # id-ecPublicKey ({ iso(1) member-body(2) us(840) 10045 2 1})
    # defined in section 2.3.5 of RFC 3279
    oid = asn.Oid([1, 2, 840, 10045, 2, 1])
    ecparams = self.group.asn_struct(use_name)
    pub = asn.BitString(self.encode_pub_point())
    return [[oid, ecparams], pub]

  def encode(self, use_name: bool = True):
    return asn.encode(self.asn_struct(use_name))

  def encode_hex(self, use_name: bool = True):
    return asn.encode_hex(self.asn_struct(use_name))

  def encode_b64(self, use_name: bool = True):
    return asn.encode_b64(self.asn_struct(use_name))

  def jwk(self):
    """Returns a jwk structure of the curve.

    This is based on RFC 7518 and RFC 8812.
    RFC 8812 adds secp256k1.
    There is a distinction between JOSE keys and COSE keys.
    JOSE uses key type kty: EC and COSE uses kty: EC2.
    This function uses the JOSE naming.

    Returns: the jwk structure or None if the curve is not known.
    """
    c = self.group
    if not self.verify_named_curve() or not c.jwk():
      return None
    length = (c.p.bit_length() + 7) // 8
    return {
        "kty": "EC",
        "crv": c.jwk(),
        "x": util.uint2urlsafe64(int(self.w[0]), length),
        "y": util.uint2urlsafe64(int(self.w[1]), length),
        "kid": "none",
    }

  def as_struct(self, use_name: bool = True):
    return {
        "type": "EcPublicKey",
        "curve": self.group.as_struct(use_name=use_name),
        "keySize": (self.group.field_size() - 1).bit_length(),
        "uncompressed": self.group.encode_uncompressed(self.w),
        "wx": AST.BigInt(int(self.w[0])),
        "wy": AST.BigInt(int(self.w[1])),
    }

  def pem(self):
    return pem_util.public_key_pem(self.encode())


class EcPublicKeyOnNamedCurve(EcPublicKey):
  """An EC public key.

     This data type allows only named curves to specify
     the underlying EC parameters.
  """
  schema = {
      "type": {
          "type": str,
          "enum": ["EcPublicKey"],
          "desc": "the key type",
      },
      "curve": {
          "type": ec_groups.EcNamedGroup,
          "desc": "the EC group used by this public key",
      },
      "keySize": {
          "type": int,
          "desc": "the key size in bits",
      },
      "uncompressed": {
          "type": AST.HexBytes,
          "short": "encoded public key point",
          "desc": "X509 encoded public key point in hexadecimal format"
      },
      "wx": {
          "type": AST.BigInt,
          "desc": "the x-coordinate of the public key point",
      },
      "wy": {
          "type": AST.BigInt,
          "desc": "the y-coordinate of the public key point",
      },
  }

  @util.type_check
  def __init__(self,
               group: ec_groups.EcNamedGroup,
               w = None,
               use: str = "sign",
               compressed: bool = False,
               encoded_point: Optional[bytes] = None):
    """Constructs a new EcPublic key.

    There is no check whether the key is valid. It is even
    possible to pass in alternative of invalid encodings.
    This allows to construct keys for the generation of
    test vectors with invalid keys.

    Args:
       group: the EC group of this public key
       w: the public point. This is a point on the curve if the
          public key is valid. However, this implementation allows
          invalid public keys with malformed w
       use: used for jwk
       compressed: determines whether the encoding should be compressed.
       encoded_point: can be used to generate public keys with
            malformed encoding.
    """
    if w is None and encoded_point is None:
      raise ValueError("either w or encoded_point must be defined")
    self.group = group
    self.w = w
    self.use = use
    self.compressed = compressed
    self.encoded_point = encoded_point


if __name__ == "__main__":
  pass
