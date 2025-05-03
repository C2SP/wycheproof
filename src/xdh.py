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
import edwards
import mod_arith
import pem_util
import util
import prand

from typing import Optional

# BouncyCastle and jdk used different encodings for xdh keys.
# RFC 8410 defines the possible encodings.
#
# == BouncyCastle X25519 privat key ==
# format:PKCS#8 encoded:
# 3051020101300506032b656e04220420b0133d068310a879ff6334b00ca7293f
# 3757465110eb24b42dbb1cb00ad25b65812100d8151c45bb0adce0e1321f3169
# d7adf952e0a2be184f8e9b2bf73e8d0fead904
#
# SEQUENCE {
#    INTEGER 0x01 (1 decimal)
#    SEQUENCE {
#       OBJECTIDENTIFIER 1.3.101.110
#    }
#    OCTETSTRING
#        0420b0133d068310a879ff6334b00ca7293f3757465110eb24b42dbb1cb00ad25b65
#    [1] 00d8151c45bb0adce0e1321f3169d7adf952e0a2be184f8e9b2bf73e8d0fead904
# }
#
# - BC includes the public key. Because of this the version is 1.
# - The private key is encoded as Octetstring of Octetstring. This is
#   consistent with RFC 8410.
# - There is no NULL parameter after the OID. This is consistent with RFC 8410.
#
# == jdk11 X25519 privat key ==
# format:PKCS#8
# encoded:
# 302e020100300706032b656e050004206a79bb81f4a2f716aefa54d804b3f5c8
# 47a2c844bafe6cc25cdc4729acc2d3da
#
# SEQUENCE {
#    INTEGER 0x00 (0 decimal)
#    SEQUENCE {
#       OBJECTIDENTIFIER 1.3.101.110
#       NULL
#    }
#    OCTETSTRING
#        6a79bb81f4a2f716aefa54d804b3f5c847a2c844bafe6cc25cdc4729acc2d3da
# }
#
# - jdk does not include the public key. (this allows version 0)
# - There is a NULL after the OID (RFC 8410 does not include a NULL).
# - The key is only encoded as Octetstring. This is a bug.
#
# == BouncyCastle X25519 public key ==
# format:X.509
# encoded:
# 302a300506032b656e032100d8151c45bb0adce0e1321f3169d7adf952e0a2be
# 184f8e9b2bf73e8d0fead904
#
# SEQUENCE {
#    SEQUENCE {
#       OBJECTIDENTIFIER 1.3.101.110
#    }
#    BITSTRING
#        0xd8151c45bb0adce0e1321f3169d7adf952e0a2be184f8e9b2bf73e8d0fead904
#        : 0 unused bit(s)
# }
#
# - There is no Null after the OID. This is consistent with RFC 8410.
#
# == jdk11 X25519 public key ==
# format:X.509
# encoded:
# 302c300706032b656e05000321002fac0a8de6a1423ee0405592ac0fdc0ff884
# 4be781cb91183111334fa5c8b21e
#
# SEQUENCE {
#    SEQUENCE {
#       OBJECTIDENTIFIER 1.3.101.110
#       NULL
#    }
#    BITSTRING
#        0x2fac0a8de6a1423ee0405592ac0fdc0ff8844be781cb91183111334fa5c8b21e
#        : 0 unused bit(s)
# }
#
# - There is a NULL after the OID. This seems to be a bug.
#

def _is_pseudoprime(p) -> bool:
  return p in (2,3) or pow(3, p, p) == 3


def decode_little_endian(b: bytes, bits: int) -> int:
  """Decodes an integer.

  Defined on page 7 of RFC 7748

  Args:
    b: the bytes to decode
    bits: the number of bits of the result.
  """
  return sum([b[i] << 8*i for i in range((bits+7)//8)])


def encode_little_endian(n: int, bits: int) -> bytes:
  return bytes((n >> 8*i) & 0xff for i in range((bits+7)//8))

class JwkXdhPrivateKey:
  schema = {
    "kty" : {
       "type" : str,
       "enum" : ["OKP"],
       "desc" : "the key type",
    },
    "crv" : {
       "type" : str,
       "enum" : ["X25519", "X448"],
       "desc" : "the DH function",
    },
    "kid" : {
       "type" : str,
       "desc" : "the key identifier",
    },
    "d" : {
       "type" : AST.Base64Url,
       "desc" : "the private key value",
    },
    "x" : {
       "type" : AST.Base64Url,
       "desc" : "the public key value",
    }
  }

class JwkXdhPublicKey:
  schema = {
    "kty" : {
       "type" : str,
       "enum" : ["OKP"],
       "desc" : "the key type",
    },
    "crv" : {
       "type" : str,
       "enum" : ["X25519", "X448"],
       "desc" : "the DH function",
    },
    "kid" : {
       "type" : str,
       "desc" : "the key identifier",
    },
    "x" : {
       "type" : AST.Base64Url,
       "desc" : "the public key value",
    }
  }

class Xdh:
  def __init__(self, p:int, a24:int, A:int,
               order:int, cofactor:int,
               cofactor_twist:int,
               pu:int, pv:int, name:str, curve:str,
               oid):
    self.p = p
    # bits needed to encode integers in the range 0 .. p-1
    self.bits = (p - 1).bit_length()
    # bytes needed to encode integers in the range 0 .. p-1
    self.bytes = (self.bits + 7) // 8

    self.a24 = a24
    self.A = A
    # the order of the generator
    self.order = order
    self.cofactor = cofactor
    # the order of the group
    self.group_order = cofactor * order
    self.group_order_twist = 2 * p + 2 - self.group_order
    self.cofactor_twist = cofactor_twist
    self.order_twist = self.group_order_twist // cofactor_twist
    self.pu = pu
    self.pv = pv
    self.name = name
    self.curve = curve
    self.oid = oid

    self.selftest()

  def selftest(self):
    # p should be prime (just do a pseudoprime test)
    assert _is_pseudoprime(self.p)
    assert _is_pseudoprime(self.order)

    # order_twist = cofactor_twist * prime
    assert self.order_twist * self.cofactor_twist == self.group_order_twist
    assert _is_pseudoprime(self.order_twist)

    # (pu, pv) is a generator of the group
    assert self.is_on_curve(self.pu)
    assert self.is_point_on_curve(self.pu, self.pv)
    assert self.point_mult(self.pu, self.order) == 0

    # relation between A and a24
    assert self.a24 * 4 + 2 == self.A

  def jwk_curve(self) -> str:
    """The jwk name of the curve as defined in RFC 8037.

       I.e. RFC 8037 uses the algorithm name to denote the
       curve.
    """
    return self.name.upper()

  def decode_u_coordinate(self, u: bytes) -> int:
    """Decodes a coordinate.

    Defined on page 6 of RFC 7748. The definition given there specifies
    that u can contain unused bits. These bits are silently ignored.

    Args:
      u: a coordinate in little endian order.

    Returns:
      the coordiante as an integer. The result is in the range
      0 .. 2**(self.bits) - 1.
    """
    if self.bits % 8 > 0:
      assert len(u) > 0
      last_byte = u[-1] & ((1 << (self.bits % 8)) - 1)
      u = u[:-1] + bytes([last_byte])
    return decode_little_endian(u, self.bits)

  def encode_u_coordinate(self, u: int) -> bytes:
    """Encodes a coordinate.

    Args:
      u: the coordinate to encode

    Returns:
      u encoded in little endian order.
    """
    return encode_little_endian(u % self.p, self.bits)

  def is_point_on_curve(self, u: int, v: int) -> bool:
    """Determines if (u, v) is a point on the curve.

    Args:
      u: the first coordinate of the point.
      v: the second coordinate of the point.

    Returns:
      True if (u, v) is a point on the curve.
    """
    return (u**3 + self.A*u**2 + u - v**2) % self.p == 0

  def is_on_curve(self, u: int) -> bool:
    """Determines whether there is a point with coordinate u on the curve.

    This function is slow, because it performs a modular multiplication.
    It could be sped up by implementing the Jacobi symbol.

    Args:
      u: the coordinate.

    Returns:
      True if there is a point with coordinate u on the curve.
    """
    m = (u**3 + self.A*u**2 + u) % self.p
    return pow(m, (self.p + 1) // 2, self.p) == m

  def get_v(self, u: int) -> Optional[int]:
    """Returns a coordinate v if there is a point u,v on the curve.

    Args:
      u: a coordinate of a point

    Returns:
      v such that (u, v) is a point on the curve or None if no point exists.
    """
    m = (u**3 + self.A*u**2 + u) % self.p
    return mod_arith.modsqrt(m, self.p)

  def order_u(self, u:int) -> int:
    """Determines the order of points with coordinate u."""
    if self.is_on_curve(u):
      L = [x for x in range(1, self.cofactor + 1) if self.cofactor % x == 0]
      L += [x * self.order for x in L]
    else:
      L = [x for x in range(1, self.cofactor_twist + 1)
          if self.cofactor_twist % x == 0]
      L += [x * self.order_twist for x in L]
    for x in L:
      # Here we need to distinguish between points at infinity and points with
      # u-coordinate 0.
      if self.point_mult(u, x, infinity= -1) == -1:
        return x
    raise Exception("Failed to compute order_u(%d)" % u)

  def point_mult(self,
                 u:int,
                 k:int,
                 infinity: int = 0,
                 randomize: bool = False,
                 log: bool = False) -> int:
    """Does a point multiplication.

    Args:
      u: the point to multiply
      k: the multiplicant
      infinity: the representation of a point at infinity. The default is 0.
        This default is motivated by RFC 7748, which uses x_2 * pow(z_2, p-2, p)
        % p to convert a projective representation (x, z) into an affine
        representation. This means that the point at infinity is mapped to 0.
      randomize: if True then the point multiplication is randomized. This is
        mostly done for experimentation.
      log: print intermediate results
    """
    def cswap(bit, x, y):
      mask = -bit
      y ^= x
      x ^= y & mask
      y ^= x
      return x,y

    p = self.p
    a24 = self.a24

    x_1 = u
    if randomize:
      # Randomizes the point k by this random value**(2^b * (2^b-k))
      # where b is the bit-length of k.
      x_2 = util.randomint(1, p)
      z_2 = 0
      # Randomizes the point k by this random value**(2^b * k)
      # where b is the bit-length of k.
      z_3 = util.randomint(1, p)
      x_3 = u * z_3 % p
    else:
      x_2 = 1
      z_2 = 0
      x_3 = u
      z_3 = 1
    swap = 0

    bits = k.bit_length()
    for t in range(bits - 1, -1, -1):
      if log:
        print(t)
        print("x2", hex(x_2))
        print("x3", hex(x_3))
        print("z2", hex(z_2))
        print("z3", hex(z_3))
      k_t = (k >> t) & 1
      swap ^= k_t
      (x_2, x_3) = cswap(swap, x_2, x_3)
      (z_2, z_3) = cswap(swap, z_2, z_3)
      swap = k_t
      A = (x_2 + z_2) % p
      AA = A**2 % p
      B = (x_2 - z_2) % p
      BB = B**2 % p
      E = (AA - BB) % p
      C = (x_3 + z_3) % p
      D = (x_3 - z_3) % p
      DA = D * A % p
      CB = C * B % p
      if log:
        print("A", hex(A))
        print("AA", hex(AA))
        print("BB", hex(BB))
        print("DA", hex(DA))
        print("CB", hex(CB))
      x_3 = (DA + CB)**2 % p
      z_3 = x_1 * (DA - CB)**2 % p
      x_2 = AA * BB % p
      z_2 = E * (AA + a24 * E) % p

    (x_2, x_3) = cswap(swap, x_2, x_3)
    (z_2, z_3) = cswap(swap, z_2, z_3)
    u_2 = None
    if z_2 == 0:
      # If x_2 != 0 then this is a point at infinity. RFC 7748 returns
      # x_2 * pow(z_2, p-2, p), which means that it returns 0.
      if x_2 != 0:
        return infinity
      # TODO: unclear is the situation (x_2, z_2) == (0, 0)
      #   This happens for point_mult(0, 1) which should return 0
      #   and point_mult(0, 2) which should return infinity.
      if u % p==0:
        return infinity if k % 2 == 0 else 0
      raise Exception("Undefined point multiplication u=%d, k=%d" % (u, k))
    else:
      u_2 = x_2 * pow(z_2, -1, p) % p
    # check that points are colinear
    V = u * u_2
    W = 4 * ((u + u_2 + self.A) * z_3 + x_3) * (V * x_3)
    X = ((V - 1) * z_3 + x_3 * (u + u_2))**2
    assert (W - X) % p == 0
    return u_2

  def public_key(self, priv: bytes) -> bytes:
    """Converts an encoded private key into a public key.

    Args:
      priv: encoded private key

    Returns:
      the encoded public key
    """
    k = self.decode_scalar(priv)
    r = self.point_mult(self.pu, k)
    return self.encode_u_coordinate(r)

  def key_pair(self, k: int) -> tuple[bytes, bytes]:
    """Returns private key and public key generated from an integer k.

    Args:
      k: an integer for the public key. This integer will be reduced to the
        range allowed for private keys.
    Returns: a pair containing the encoded private key and the encoded public
      key.
    """
    k = self.reduce_private(k)
    pub = self.point_mult(self.pu, k)
    return self.encode_scalar(k), self.encode_u_coordinate(pub)

  def pseudorandom_priv_key(self, seed: bytes, label: bytes) -> int:
    """Returns a pseudorandom private key.

    Args:
      seed: the seed for the pseudorandom number generator
      label: an additional argument for the pseudorandom number generator

    Returns:
      the generated private key. This key is not encoded.
    """
    s = prand.randrange(0, 2**self.bits, seed=seed, label=label)
    return self.reduce_private(s)

  def pseudorandom_key_pair(self, seed: bytes,
                            label: bytes) -> tuple[bytes, bytes]:
    """Returns a pseudorandom key pair.

    Args:
      seed: the seed for the pseudorandom number generator
      label: an additional argument for the pseudorandom number generator

    Returns:
      the generated key pair. Private key and public key are encoded.
    """
    k = self.pseudorandom_priv_key(seed, label)
    return self.key_pair(k)

  def pseudorandom_pub_key(self, seed: bytes, label: bytes) -> bytes:
    """Returns a pseudorandom public keyr.

    Args:
      seed: the seed for the pseudorandom number generator
      label: an additional argument for the pseudorandom number generator

    Returns:
      the generate public key. This public key is encoded.
    """
    return self.pseudorandom_key_pair(seed, label)[1]

  @util.type_check
  def shared_secret(self, priv: bytes, pub: bytes)-> bytes:
    """Computes the XDH shared secret.

    The XDH computation does not perform checks on the values
    of the private key or public key.

    Args:
      priv: an encoded private key
      pub: an encoded public key

    Returns:
      the shared secret
    """
    u = self.decode_u_coordinate(pub)
    k = self.decode_scalar(priv)
    r = self.point_mult(u, k)
    return self.encode_u_coordinate(r)

  # References:
  # RFC 8410: defines the OID in section 9
  # There is no NULL parameter afther the OID.
  def public_key_struct(self, pub:bytes):
    """Returns the ASN structure of a public key.

    This structure is defined in Section 9 of RFC 8410.

    Args:
      pub: the public key

    Returns:
      an ASN sequence containing OID and public key.
    """
    return [[self.oid], asn.BitString(pub)]

  # RFC 8410 Section 10.3:
  # - The private key is encoded as an OCTET STRING of an
  #   OCTET STRING.
  # - There is no NULL parameter after the OID
  # - It is possible to add the public key as an attribute.
  #   This has not been done here.
  # https://bugs.java.com/bugdatabase/view_bug.do?bug_id=8213493
  def private_key_struct(self, priv: bytes, pub: Optional[bytes] = None):
    """Returns the ASN structure of a private key.

    The structure is defined in Section 10.3 of RFC 8410.

    Some potentially confusing details:
    * The private key is encoded as an OCTET STRING of an
      OCTET STRING.
    * There is no NULL parameter after the OID.
    * It is possible to add the public key as an attribute.
      (This has not been done here).

    See: https://bugs.java.com/bugdatabase/view_bug.do?bug_id=8213493

    Args:
      priv: the encoded private key
      pub: optionally the corresponding public key. If the public key is given
        then it is added to the result. Otherwise no public key is included.
    """
    if pub is not None:
      return [
          1, [self.oid],
          asn.OctetStringFromStruct(asn.OctetString(priv)),
          asn.Implicit(1, asn.BitString(pub), asn.CONTEXT_SPECIFIC, False)
      ]
    else:
      return [0, [self.oid], asn.OctetStringFromStruct(asn.OctetString(priv))]

  def asn_encode_pub(self, pub:bytes)->bytes:
    """Returns an ASN encoded public key.

    The encoding is defined in Section 9 of RFC 8410.

    Args: the public key

    Returns:
       the ASN encoding
    """
    return asn.encode(self.public_key_struct(pub))

  def asn_encode_priv(self, priv: bytes, pub: Optional[bytes] = None) -> bytes:
    """Returns an ASN encoded private key.

    The encoding is defined in Section 10.3 of RFC 8410.

    Args:
      priv: the encoded private key
      pub: optionally the corresponding public key. If the public key is given
        then it is added to the result. Otherwise no public key is included.

    Returns:
      the ASN encoding
    """
    return asn.encode(self.private_key_struct(priv, pub))

  def jwk_private_key(self, priv:bytes):
    """Returns a JWK encoded private key.

    Args:
      priv: the private key

    Returns:
      the JWK encoding
    """
    pub = self.public_key(priv)
    return {"kty": "OKP",
            "crv" : self.jwk_curve(),
            "d" : util.bytes2urlsafe64(priv),
            "x" : util.bytes2urlsafe64(pub),
            "kid" : "none"}

  def jwk_public_key(self, pub:bytes):
    """Returns a JWK encoded public key.

    Args:
      pub: the public key

    Returns:
      the JWK encoded public key.
    """
    return {"kty": "OKP",
            "crv" : self.jwk_curve(),
            "x" : util.bytes2urlsafe64(pub),
            "kid" : "none"}

  # TODO: Is this used?
  def encode_b64(self, use_name: bool = True):
    return asn.encode_b64(self.asn_struct(use_name))

  def pem_encode_pub(self, pub:bytes) -> str:
    """Returns a PEM encoded public key."""
    return pem_util.public_key_pem(self.asn_encode_pub(pub))

  def pem_encode_priv(self, priv:bytes) -> str:
    """Returns a PEM encoded private key."""
    return pem_util.private_key_pem(self.asn_encode_priv(priv))


class X25519(Xdh):
  # U-coordinates of points of with low order
  low_order_points = [0, 1,
    57896044618658097711785492504343953926634992332820282019728792003956564819948,
    39382357235489614581723060781553021112529911719440698176882885853963445705823,
    325606250916557431795983626356110631294008115727848805560023387167927233504]

  # prime factors of p-1
  pm1_factors = [2, 2, 3, 65147,
      74058212732561358302231226437062788676166966415465897661863160754340907]

  def __init__(self):
    super().__init__(
      p = 2**255 - 19,
      A = 486662,
      a24 = 121665,
      order = 2 ** 252 + 0x14def9dea2f79cd65812631a5cf5d3ed,
      cofactor = 8,
      cofactor_twist = 4,
      pu = 9,
      pv = int("14781619447589544791020593568409986887264606134616"
               "475288964881837755586237401"),
      name = "x25519",
      curve = "curve25519",
      oid = asn.Oid("2b656e"),  # RFC 8410, section 9
    )

  def public_keys_with_low_order(self):
    """Returns the public key k encodings with the property that

       decode_u_coordinate(k) is a point of low order
    >>> L = public_keys_with_low_order()
    >>> set(point_mult(decode_u_coordinate(k), 8) for k in L)
    {0}
    """
    p = self.p
    L = self.low_order_points
    L += [x + p for x in L if x + p < 2**255]
    L += [x + 2**255 for x in L]
    return [encode_little_endian(x, 256) for x in L]

  def reduce_public(self, k: int)-> int:
    k %= 2**255
    k %= self.p
    return k

  def reduce_private(self, k: int)-> int:
    k = k % 2**254
    k -= k % 8
    k |= 2**254
    return k

  def decode_scalar(self, k: bytes)-> int:
    k_list = bytearray(k)
    k_list[0] &= 248
    k_list[31] &= 127
    k_list[31] |= 64
    return decode_little_endian(bytes(k_list), 255)

  def encode_scalar(self, k):
    return encode_little_endian(k, 255)

class X448(Xdh):
  low_order_points = [0, 1, 2**448 - 2**224 - 2]
  def __init__(self):
    super().__init__(
      p = 2**448 - 2**224 - 1,
      A = 156326,
      a24 = 39081,
      order = (2 ** 446 -
               0x8335dc163bb124b65129c96fde933d8d723a70aadc873d6d54a7bb0d),
      cofactor = 4,
      cofactor_twist = 4,
      pu = 5,
      pv =
        int("3552939267855681752641275020637833348089763993877142718318808984"
            "3516908878696741000293267376586455091014277414726810583898559529"
            "0606362"),
      name = "x448",
      curve = "curve448",
      oid = asn.Oid("2b656f"),   # RFC 8410, section 9

    )

  def reduce_private(self, k:int)-> int:
    k %= 2**447
    k -= k % 4
    k |= 2**447
    return k

  def reduce_public(self, k:int)-> int:
    k %= 2**448
    k %= self.p
    return k

  def decode_scalar(self, k:bytes)-> int:
    k_list = bytearray(k)
    k_list[0] &= 252
    k_list[55] |= 128
    return decode_little_endian(bytes(k_list), 448)

  def encode_scalar(self, k:int)-> bytes:
    return encode_little_endian(k, 448)

  def public_keys_with_low_order(self):
    p = self.p
    L = self.low_order_points
    L += [x + p for x in L if x + p < 2**447]
    L += [x + 2**447 for x in L]
    return [encode_little_endian(x, 448) for x in L]

# Some singletons
x25519 = X25519()
x448 = X448()

# ===== ISOMORPHISMS AND OTHER MAPPINGS =====
# Differences to ec_group.Isomorphism are:
#   A has type Xdh nor EcGroup
#   B is an Edwards curve not an EcGroup
#   inputs to conversions are coordinates not points.
class X25519Isomorphism:
  def __init__(self):
    self.A = x25519
    self.B = edwards.edwards25519
    self.p = self.A.p
    self.sqrtD = int("51042569399160536130206135233146329284152202253034"
                     "631822681833788666877215207")

    # Some relations between the definitions above.
    p = self.A.p
    curveA = self.A.A
    assert self.sqrtD**2 % p == (-curveA - 2) % p

  def convert_uv2xy(self, u, v):
    x = self.sqrtD * u * pow(v, -1, self.p) % self.p
    y = (u-1) * pow(u+1, -1, self.p) % self.p
    return x,y

  def convert_xy2uv(self, x, y):
    u = (1 + y) * pow(1 - y, -1, self.p) % self.p
    v = self.sqrtD * u * pow(x, -1, self.p) % self.p
    return u, v
x25519isomorphism = X25519Isomorphism()

class X448Isomorphism:
  """An isomorphism define Section 4.2 of RFC 7748."""
  def __init__(self):
    self.A = x448
    self.B = edwards.edwards448Rfc7748
    self.p = self.A.p
    self.sqrtD = int("19788846729546443953835400975385803825683515259105"
                     "98021481997791960874042320025157136042631277930307"
                     "47855424464185691766453844835192428")
    # Some relations between the definitions above.
    p = self.A.p
    curveA = self.A.A

  def convert_uv2xy(self, u, v):
    assert self.A.is_point_on_curve(u, v)
    x = self.sqrtD * u * pow(v, -1, self.p) % self.p
    y = (1 + u) * pow(1 - u, -1, self.p) % self.p
    assert self.B.is_on_curve(x, y)
    return x, y

  def convert_xy2uv(self, x, y):
    assert self.B.is_on_curve(x, y)
    u = (y - 1) * pow(y + 1, -1, self.p) % self.p
    v = self.sqrtD * u * pow(x, -1, self.p) % self.p
    assert self.A.is_point_on_curve(u, v)
    return u, v
# Make an instance
x448isomorphism = X448Isomorphism()

class X448Mapping:
  """A mapping between points on x448 and edwards448 defined

     in RFC 7748. It is not an isomorphism. Not sure what it is.
  """
  def __init__(self):
    self.A = x448
    self.B = edwards.edwards448
    self.p = self.A.p

  def convert_uv2xy(self, u: int, v: int) -> tuple[int, int]:
    assert self.A.is_point_on_curve(u, v)
    xnum = 4 * v * (u**2 - 1) % self.p
    xden = (u**4 - 2 * u**2 + 4 * v**2 + 1) % self.p
    x = xnum * pow(xden, -1, self.p) % self.p
    ynum = (-u**5 + 2 * u**3 + 4 * u * v**2 - u) % self.p
    yden = (u**5 - 2 * u**2 * v**2 - 2 * u**3 - 2 * v**2 + u) % self.p
    y = ynum * pow(yden, -1, self.p) % self.p
    assert self.B.is_on_curve(x, y)
    return x, y

  def convert_xy2uv(self, x: int, y: int) -> tuple[int, int]:
    assert self.B.is_on_curve(x, y)
    xinv = pow(x, -1, self.p)
    u = (y * xinv)**2 % self.p
    vnum = (2 - x**2 - y**2) * y % self.p
    vden = xinv ** 3 % self.p
    v = vnum * vden % self.p
    assert self.A.is_point_on_curve(u, v)
    return u, v
# Make an instance
x448mapping = X448Mapping()

# The list of implemented primitives
# So far the two curves defined in RFC 7748 are implemented.
# Other groups have been proposed, but I haven't seen a standard
# proposal yet.
XDH_GROUPS = [x25519, x448]
