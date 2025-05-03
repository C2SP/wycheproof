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
import base64
import edwards
import hashlib
import pem_util
from typing import Union
import util

# REQUIRES: Python 3.9

# This is slow code that is only used to compute test vectors.
# The code has not been checked for flaws.

# Things to check in unit tests:
# - reaction to invalid points
# - the scheme is deterministic, bugs in det. signature generation can leak the
#   secret key.
# - check for signature size is important
# - the R in the signature is a point in the large prime order subgroup.
# - decodepoint assumes that the point is on the curve:
#   generate signatures where this is not the case.
#   (Not every implementation decodes R)
# - S > order
# - check for malleability

# Type hints:
EddsaCurve = Union[edwards.Edwards, edwards.TwistedEdwards]
EddsaPoint = Union[edwards.EdwardsPoint, edwards.TwistedEdwardsPoint]

def bit(h: bytes, i: int) -> int:
  """Extracts the i-th bit.

  Args:
    h: the byte from which we extract the bit
    i: the bit number

  Returns:
    0 or 1
  """
  return (h[i // 8] >> (i % 8)) & 1

def encodeint(y: int, size: int) -> bytes:
  """Encodes an unsigned integer using little endian ordering.

  Args:
    y: the integer to encode
    size: the size of the encoding in bytes
  """
  return y.to_bytes(size, "little")

def decodeint(s: bytes) -> int:
  """Decodes an unsigned integer using little endian ordering.

  Args:
    s: the encoded integer

  Returns:
    s converted to an integer using little endian ordering.
  """
  return int.from_bytes(s, "little")

class EddsaGroup:
  @util.type_check
  def __init__(self, curve: EddsaCurve, order: int, B: EddsaPoint,
               elem_size: int):
    if B.curve != curve:
      raise ValueError("Invalid point")
    self.curve = curve
    self.order = order
    self.mod = curve.mod
    self.B = B
    self.elem_size = elem_size
    self.b = 8 * self.elem_size

class Ed25519Group(EddsaGroup):
  def __init__(self):
    curve = edwards.edwards25519
    mod = curve.mod
    B = curve.point_from_y(4 * pow(5, -1, mod) % mod)
    super().__init__(curve = curve,
                     order = 2**252 + 27742317777372353535851937790883648493,
                     B = B,
                     elem_size = 32)
    # Jwk uses the algorithm name for crv
    # https://tools.ietf.org/id/draft-ietf-jose-cfrg-curves-02.html
    # Section 3.1.1
    self.jwk_name = "Ed25519"
    self.low_order_points = [
      "0000000000000000000000000000000000000000000000000000000000000000",
      "0000000000000000000000000000000000000000000000000000000000000080",
      "0100000000000000000000000000000000000000000000000000000000000000",
      "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
      "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
      "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
      "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
      "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85"]


  def int2sk(self, s: int) -> int:
    s -= s % 8
    s %= 2 ** 254
    s += 2 ** 254
    return s

  def Hpriv(self, m: bytes)-> bytes:
    return hashlib.sha512(m).digest()

  def H(self, m: bytes)-> bytes:
    return hashlib.sha512(m).digest()

  def Hint(self, m: bytes) -> int:
    b = self.H(m)
    assert len(b) == 64
    return decodeint(b)

  def encodeelem(self, x:int) -> bytes:
    return encodeint(x, 32)

  def encodepoint(self, P: edwards.EdwardsPoint):
    return encodeint(P.y + ((P.x & 1) << 255), 32)

  def decodepoint(self, s: bytes) -> int:
    if len(s) != self.elem_size:
      raise ValueError("s has wrong size")
    xbit, y = divmod(decodeint(s), 2**255)
    return self.curve.point_from_y(y, xbit)

#TODO: check elem_size
class Ed448Group(EddsaGroup):

  def __init__(self, phflag: int, context: bytes = b""):
    curve = edwards.edwards448
    B = curve.point(
       int("22458004029592430018760433409989603624678964163256413424612"
           "54616869504154674060329090291928693579532825780320751464461"
           "73674602635247710"),
       int("29881921007848149267601793044393067343754404015408024209592"
           "82413723315061898358760035368786554187847339823032335034625"
           "00531545062832660"))
    order = (2 ** 446 -
       int("1381806680989511535200738674851542688033669247488217860989"
           "4547503885"))
    super().__init__(curve = curve,
                     order = order,
                     B = B,
                     elem_size = 57)
    # Ed448ph is not yet implemented
    assert phflag in [0]
    self.phflag = phflag
    self.C = context
    self.d = -39081
    self.dom4 = b"SigEd448" + bytes([self.phflag, len(self.C)]) + self.C
    # Jwk uses the algorithm name for crv
    # https://tools.ietf.org/id/draft-ietf-jose-cfrg-curves-02.html
    # Section 3.1.1
    self.jwk_name = "Ed448"

  def int2sk(self, s: int) -> int:
    s -= s % 4
    s %= 2 ** 447
    s += 2 ** 447
    return s

  def Hpriv(self, pk: bytes) -> bytes:
    return hashlib.shake_256(pk).digest(114)

  def H(self, m: bytes)-> bytes:
    return hashlib.shake_256(self.dom4 + m).digest(114)

  def Hint(self, m: bytes) -> int:
    b = self.H(m)
    assert len(b) == 114
    return decodeint(b)

  def encodeelem(self, x:int) -> bytes:
    return encodeint(x, 57)

  def encodepoint(self, P: edwards.EdwardsPoint) -> bytes:
    return encodeint(P.y, 56) + bytes([(P.x & 1) << 7])

  def decodepoint(self, s: bytes) -> int:
    assert len(s) == self.elem_size
    q, y = divmod(decodeint(s), 2**448)
    xbit = q >> 7
    assert xbit in [0, 1]
    u = (y ** 2 - 1) % self.mod
    v = (y ** 2 * self.d - 1) % self.mod
    quot = pow(v, -1, self.mod) * u % self.mod
    x = pow(quot, (self.mod + 1) // 4, self.mod)
    assert v * x**2 % self.mod == u
    if x == 0:
      assert xbit == 0
    if x % 2 != xbit:
      x = self.mod - x
    return self.curve.point(x, y)

ed25519_group = Ed25519Group()
ed448_group = Ed448Group(phflag = 0)
# ed448ph_group = Ed448Group(phflag = 1)

class EddsaPrivateKey:

  @util.type_check
  def __init__(self, priv: bytes, group: EddsaGroup):
    self.group = group
    self.priv = priv
    self.h = self.group.Hpriv(priv)
    self.a = group.int2sk(decodeint(self.h[:group.elem_size]))
    self.pk = group.encodepoint(self.a * self.group.B)
    self.pubkey = EddsaPublicKey(self.pk, self.group)

  def raw(self) -> bytes:
    """Returns the raw bytes representing this key."""
    return self.priv

  def publickey(self) -> "EddsaPublicKey":
    """Returns the public key corresponding to this key."""
    return self.pubkey

  @util.type_check
  def sign(self, m: bytes) -> bytes:
    """Signs a message.
 
    Args:
      m: the message to sign
    """
    group = self.group
    elem_size = group.elem_size
    r = group.Hint(self.h[elem_size:2 * elem_size] + m)
    R = r * group.B
    S = (r + group.Hint(group.encodepoint(R) + self.pk + m) * self.a) % group.order
    return group.encodepoint(R) + encodeint(S, elem_size)

  def get_r(self, m: bytes) -> int:
    group = self.group
    elem_size = group.elem_size
    return group.Hint(self.h[elem_size:2 * elem_size] + m)

  def jwk(self):
    """See https://tools.ietf.org/html/rfc8037"""
    return {
      "kty" : "OKP",
      "crv" : self.group.jwk_name,
      "d" : util.bytes2urlsafe64(self.priv),
      "x" : util.bytes2urlsafe64(self.pk),
      "kid" : "none"
    }

class EddsaPublicKey:
  def __init__(self, pk: bytes, group):
    assert len(pk) == group.elem_size
    assert isinstance(pk, bytes)
    self.pk = pk
    self.group = group
    self.A = group.decodepoint(pk)

  def raw(self) -> bytes:
    """Returns the raw public key."""
    return self.pk

  def asn_struct(self, use_name: bool = True):
    """Returns the ASN structure of the EDDSA key.
    
    Args:
      use_name: this argument is ignored. Unlike EC keys where a key can
        be encoded by explicitly specifying the curve parameters, there is no
        such encoding for EDDSA keys.
    Returns: the ASN structure describing the public key.
    """
    # There are distinct proposals for the ASN structure of EDDSA public keys.
    # The structure is defined in RFC 8410 Section 3:
    #  AlgorithmIdentifier  ::=  SEQUENCE  {
    #   algorithm   OBJECT IDENTIFIER,
    #   parameters  ANY DEFINED BY algorithm OPTIONAL
    #  }
    # and Section 4:
    # SubjectPublicKeyInfo  ::=  SEQUENCE  {
    #   algorithm         AlgorithmIdentifier,
    #   subjectPublicKey  BIT STRING
    # }
    # Section 4 also defines that the encoding of subjectPublicKey always
    # is a multiple of 8 bits.
    #
    # https://tools.ietf.org/html/draft-ietf-curdle-pkix-06
    # [[Oid("2b6570")], BitString(self.raw()), 0)]
    # (Same as above)
    #
    # Some alternatives I've found are as follows:
    # https://tools.ietf.org/html/draft-ietf-curdle-pkix-01
    # [[Oid("2b6564")], BitString(self.raw()), 0)]
    # https://tools.ietf.org/html/draft-josefsson-pkix-eddsa-04
    # Uses [[Oid, algorithm], where algorithm is asn.Enumerated(1)
    #
    # TODO:  Both [RFC7748] and [RFC8032] define the public key value
    #    as being a byte string. The public key is computed
    #    differently for each of these. Hence the same private key produces
    #    different public keys. Some projects want to share keys for EdDSA and
    #    Xdh. This might lead to problem.
    if self.group.curve == edwards.edwards25519:
      oid = asn.Oid("2b6570")
    elif self.group.curve == edwards.edwards448 and self.group.phflag == 0:
      oid = asn.Oid("2b6571")

    pub = asn.BitString(self.raw(), 0)
    return [[oid], pub]

  def encode(self, use_name: bool = True) -> bytes:
    return asn.encode(self.asn_struct(use_name))

  def encode_b64(self, use_name: bool = True) -> bytes:
    return asn.encode_b64(self.asn_struct(use_name))

  def pem(self) -> str:
    return pem_util.public_key_pem(self.encode())

  def jwk(self):
    """See https://tools.ietf.org/html/rfc8037"""
    return {
        "kty": "OKP",
        "crv": self.group.jwk_name,
        "kid": "none",
        "x": util.bytes2urlsafe64(self.pk)
    }

  @util.type_check
  def verify(self, m: bytes, sig: bytes) -> None:
    """Checks a signature.

    The signature verification is described in Section 6 of RFC 8032.

    Args:
      m: the message to verify
      sig: the signature

    Raises:
      ValueError: it the input has invalid format.
      Exception: if the signature is invalid
    """
    group = self.group
    if len(sig) != 2 * group.elem_size:
      raise ValueError("signature length is wrong")
    if len(self.pk) != group.elem_size:
      raise ValueError("public-key length is wrong")
    R = group.decodepoint(sig[:group.elem_size])
    S = decodeint(sig[group.elem_size:])
    if S >= group.order:
      raise Exception("S too large")
    h = group.Hint(sig[:group.elem_size] + self.pk + m) % group.order
    if group.B * S != R + self.A * h:
      raise Exception("signature verification failed")

  def verify_alt(self, m: bytes, sig: bytes):
    """This is an alternative way to verify a signature.

       Instead of decoding the point R, the verification
       recomputes a point R' from S and the hash, encodes
       R" and compares the enoded point with the first
       half of the signature.

    Args:
      m: the message to verify
      sig: the signature

    Raises:
      ValueError: it the input has invalid format.
      Exception: if the signature is invalid
    """
    group = self.group
    if len(sig) != 2 * group.elem_size:
      raise ValueError("signature length is wrong")
    if len(self.pk) != group.elem_size:
      raise ValueError("public-key length is wrong")
    S = decodeint(sig[group.elem_size:])
    if S >= group.order:
      raise Exception("S too large")
    h = Hint(sig[:group.elem_size] + self.pk + m) % group.order
    R = group.B * S - self.A * h
    if group.encodepoint(R) != sig[:group.elem_size]:
      raise Exception("signature verification failed")
