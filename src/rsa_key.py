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
import asn_parser
import AST
import base64
import collections
import hashlib
import math
import modify
import oid
import os
import pseudoprimes
import test_primes
import util
import prand
import pem_util

from typing import Optional, Any

def factor_modulus(n: int, mult: int) -> list[int]:
  """Tries to factor n given a multiple of the order of n.
     
  Returns a list of prime factors of n.

  Args:
    n: an RSA modulus. Must be odd and squarefree.
    mult: a multiple of lambda(n). 
  """
  if n <= 0:
    raise ValueError("n must be positive")
  if n == 1:
    return []
  if pseudoprimes.is_probable_prime(n):
    return [n]
  if mult <= 0:
    raise ValueError("m must be positive")
  exp = 0
  m = mult
  while m % 2 == 0:
    m //= 2
    exp += 1
  for j in range(1000):
    b = pow(prand.randrange(2, n, b"%d" % j), m, n)
    for i in range(exp):
      b, c = b * b % n, b
      if b == 1 and c != n - 1:
        g = math.gcd(c - 1, n)
        if 1 < g < n:
          return factor_modulus(g, mult) + factor_modulus(n // g, mult)
        else:
          break
  if pow(2, mult, n) != 1:
    raise ValueError("m must be a multiple of the order")
  raise ValueError("Could not factor modulus")

# ===== PEM =====
def fromPem(pem):
  lines = pem.split("\n")
  if lines[0] == "-----BEGIN RSA PRIVATE KEY-----":
    if lines[-1] != "-----END RSA PRIVATE KEY-----":
      raise ValueError("Invalid PEM: terminator not found")
    bytes = base64.b64decode("".join(lines[1:-1]))
    L = asn_parser.parse(bytearray(bytes))
    if len(L) not in (9, 10):
      raise ValueError("Invalid PEM: expected list of size 9 or 10")
    version, n, e, d, p, q, dp, dq = L[9:]
    if len(L) == 9:
      other = []
      primes = [p, q]
      if version != 0:
        raise ValueError("Invalid PEM: expected version 0")
    else:
      other = L[9]
      primes = [p, q] + [r for r, dr, cr in other]
      if version != 1:
        raise ValueError("Invalid PEM: expected version 1")
    prod = 1
    for p in primes:
      prod *= p
    if prod != n:
      raise ValueError("Invalid PEM: product of primes not equal to n")
    for i,p in enumerate(primes):
      if e * d % (p - 1) != 1:
        raise ValueError(
            "Invalid PEM: d mod prime_%d not inverse of e" % (i+1))
    if d % (p - 1) != dp:
      raise ValueError("Invalid PEM: incorrect dp")
    if d % (q - 1) != dq:
      raise ValueError("Invalid PEM: incorrect dq")
    if q * iqmp % p != 1:
      raise ValueError("Invalid PEM: incorrect iqmp")
    for r, dr, cr in other:
      if d % (r - 1) != dr:
        raise ValueErrro("Invalid PEM: exponent is incorrect")
    return RsaPrivateKey(n=n, e=e, primes=primes)
  raise ValueError("Invalid PEM: format is incorrect")

# ===== JWK
class JwkRsaPublicKey:
  schema = {
    "kty" : {
      "type" : str,
      "enum" : ["RSA"],
      "desc" : "the algorithm",
    },
    "use" : {
      "type" : str,
      "enum" : ["sig", "enc"],
      "desc" : "the purpose of the key",
    },
    "kid" : {
      "type" : str,
      "desc" : "the key identifier",
    },
    "e" : {
      "type" : AST.Base64Url,
      "desc" : "the public exponent",
    },
    "n" : {
      "type" : AST.Base64Url,
      "desc" : "the modulus of the key",
    }
  }

class JwkRsaPrivateKey:
  schema = {
    "kty" : {
      "type" : str,
      "enum" : ["RSA"],
      "desc" : "the algorithm",
    },
    "use" : {
      "type" : str,
      "enum" : ["sig", "enc"],
      "desc" : "the purpose of the key",
    },
    "kid" : {
      "type" : str,
      "desc" : "the key identifier",
    },
    "n" : {
      "type" : AST.Base64Url,
      "desc" : "the modulus of the key",
    },
    "e" : {
      "type" : AST.Base64Url,
      "desc" : "the public exponent",
    },
    "d" : {
      "type" : AST.Base64Url,
      "desc" : "the private exponent",
    },
    "p" : {
      "type" : AST.Base64Url,
      "desc" : "a prime factor of the modulus",
    },
    "q" : {
      "type" : AST.Base64Url,
      "desc" : "a prime factor of the modulus",
    },
    "dp" : {
      "type" : AST.Base64Url,
      "desc" : "the value d % (p-1)",
    },
    "dq" : {
      "type" : AST.Base64Url,
      "desc" : "the value d % (q-1)",
    },
    "qi" : {
      "type" : AST.Base64Url,
      "desc" : "the CRT value q^(-1) % p",
    },
  }



# ===== PKCS1Algorithms
def asnRsaEncryption(*, named: bool = False):
  """Returns the ASN structure for rsaEncryption.
     >>> asn.encode_hex(asnRsaEncryption())
     "300d06092a864886f70d0101010500"
  """
  oid_enc = oid.Oid([1, 2, 840, 113549, 1, 1, 1])
  pkcs1_algorithm = [asn.Oid(oid_enc), asn.Null()]
  if named:
    return asn.Named("PKCS1Algorithm", pkcs1_algorithm)
  else:
    return pkcs1_algorithm

def oidForPkcs1WithHash(md):
  """Returns the OID for RSA PKCS 1 signatures with a given hash

     Defined in RFC 8017:
     md2WithRSAEncryption         OBJECT IDENTIFIER ::= { pkcs-1 2 }
     md5WithRSAEncryption         OBJECT IDENTIFIER ::= { pkcs-1 4 }
     sha1WithRSAEncryption        OBJECT IDENTIFIER ::= { pkcs-1 5 }
     sha224WithRSAEncryption      OBJECT IDENTIFIER ::= { pkcs-1 14 }
     sha256WithRSAEncryption      OBJECT IDENTIFIER ::= { pkcs-1 11 }
     sha384WithRSAEncryption      OBJECT IDENTIFIER ::= { pkcs-1 12 }
     sha512WithRSAEncryption      OBJECT IDENTIFIER ::= { pkcs-1 13 }
     sha512-224WithRSAEncryption  OBJECT IDENTIFIER ::= { pkcs-1 15 }
     sha512-256WithRSAEncryption  OBJECT IDENTIFIER ::= { pkcs-1 16 }

     https://csrc.nist.rip/groups/ST/crypto_apps_infra/csor/algorithms.html
     nistAlgorithms ::= {2 16 840 1 101 3 4}
     sigAlgs OBJECT IDENTIFIER ::= { nistAlgorithms 3 }
     id-rsassa-pkcs1-v1_5-with-sha3-224 ::= { sigAlgs 13 }
     id-rsassa-pkcs1-v1_5-with-sha3-256 ::= { sigAlgs 14 }
     id-rsassa-pkcs1-v1_5-with-sha3-384 ::= { sigAlgs 15 }
     id-rsassa-pkcs1-v1_5-with-sha3-512 ::= { sigAlgs 16 }
  """
  pkcs1 = [1, 2, 840, 113549, 1, 1]
  nist_algorithms = [2, 16, 840, 1, 101, 3, 4]
  sig_algs = nist_algorithms + [3]
  oidtab = {
     "MD2" : ("md2WithRSAEncryption", pkcs_1 + [2]),
     "MD5" : ("md5WithRSAEncryption", pkcs_1 + [4]),
     "SHA-1" : ("sha1WithRSAEncryption", pkcs_1 + [5]),
     "SHA-224" : ("sha224WithRSAEncryption", pkcs_1 + [14]),
     "SHA-256" : ("sha256WithRSAEncryption", pkcs_1 + [11]),
     "SHA-384" : ("sha384WithRSAEncryption", pkcs_1 + [12]),
     "SHA-512" : ("sha512WithRSAEncryption", pkcs_1 + [13]),
     "SHA-512/224" : ("sha512-224WithRSAEncryption", pkcs_1 + [15]),
     "SHA-512/256" : ("sha512-256WithRSAEncryption", pkcs_1 + [16]),
     "SHA3-224" : ("id-rsassa-pkcs1-v1_5-with-sha3-224", sig_algs + [13]),
     "SHA3-256" : ("id-rsassa-pkcs1-v1_5-with-sha3-256", sig_algs + [14]),
     "SHA3-384" : ("id-rsassa-pkcs1-v1_5-with-sha3-384", sig_algs + [15]),
     "SHA3-512" : ("id-rsassa-pkcs1-v1_5-with-sha3-512", sig_algs + [16]),
  }
  name, nodes = oidtab[md]
  return oid.Oid(nodes, name)

#TODO: this is a test.
def asnRsaPkcs15Signature(md: str) -> list[Any]:
  """Returns the PKCS1Algorithm for PKCS1 v 1.5 signatures
     >>> asn.encode_hex(asnRsaPkcs15Signature("SHA-1"))
     "300d06092a864886f70d0101050500"
     >>> asn.encode_hex(asnRsaPkcs15Signature("SHA-256"))
     "300d06092a864886f70d01010b0500"
  """
  return [asn.Oid(oidForPkcs1WithHash(md)), asn.Null()]

# ===== RSA key generation


def new_prime_in_interval(lower: int, upper: int, e: int, seed: bytes = None):
  cnt = 0
  if seed is None:
    seed = os.urandom(16)
  while True:
    cnt += 1
    p = prand.randrange(lower, upper, seed + cnt.to_bytes(4, "big")) | 1
    for d in range(3, 200, 2):
      if p % d==0:
        continue
    if math.gcd(p-1, e) != 1:
      continue
    if pow(2, p, p) != 2:
      continue
    for i in range(40):
      if not pseudoprimes.is_strong_pseudoprime(p, i**2 + i + 41):
        break
    else:
      return p

def new_prime(bits, e):
  upper = 2**(bits)
  lower = upper * 29 // 41
  return new_prime_in_interval(lower, upper, e)

def new_three_prime_rsa_key(bits, e=2**16+1):
  if bits % 3 == 0:
    while True:
      upper = 2**(bits//3)
      lower = upper * 77 // 97
      primes = [new_prime_in_interval(lower, upper, e) for i in range(3)]
      assert len(set(primes)) == 3
      p,q,r = primes
      n = p*q*r
      return RsaPrivateKey(n=n, primes=sorted(primes), e=e)
  else:
    pbits = (bits + 2) // 3
    upper = 2**pbits
    lower = 2**(pbits - 1)
    primes = []
    while True:
      primes.append(new_prime_in_interval(lower, upper, e))
      primes = sorted(set(primes))
      for j in range(len(primes)):
        for i in range(j):
          for k in range(i):
            p,q,r = primes[k], primes[j], primes[i]
            n = p*q*r
            if n.bit_length() == bits:
              return RsaPrivateKey(n=n, primes=[p,q,r], e=e)


def newRsaKey(bits, e=2**16 + 1, md=None):
  assert bits%2==0
  assert e > 1 and e % 2==1
  primes = set()
  while len(primes) < 2:
    primes.add(new_prime(bits // 2, e))
  primes = sorted(primes)
  p, q = primes
  return RsaPrivateKey(n=p * q, e=e, primes=primes, md=md)


class RsaPrivateKey:
  """Describes an RSA private key.

     The data type is based on the RSAPrivateKey type defined
     in Section A.1.2 of RFC 8017."""

  schema = {
      "version": {
          "type": int,
          "enum": (0, 1),
          "short": "the private key version",
          "desc":
              "The version of the private key. This is 0 for keys "
              "with no otherPrimeInfos and 1 for keys with otherPrimeInfos, "
              "i.e. multiprime keys."
      },
      "modulus": {
          "type": AST.BigInt,
          "desc": "the modulus of the key",
      },
      "publicExponent": {
          "type": AST.BigInt,
          "desc": "the public exponent",
      },
      "privateExponent": {
          "type": AST.BigInt,
          "desc": "the private exponent",
      },
      "prime1": {
          "type": AST.BigInt,
          "desc": "p: a prime factor of the modulus",
      },
      "prime2": {
          "type": AST.BigInt,
          "desc": "q: a prime factor of the modulus",
      },
      "exponent1": {
          "type": AST.BigInt,
          "desc": "the value d % (p-1)",
      },
      "exponent2": {
          "type": AST.BigInt,
          "desc": "the value d % (q-1)",
      },
      "coefficient": {
          "type": AST.BigInt,
          "desc": "the CRT value q^(-1) % p",
      },
      "otherPrimeInfos": {
          "type": list[list[AST.BigInt]],
          "desc": "list of triples [prime, exponent, coefficient]",
      }
  }

  def __init__(self,
               n: int,
               e: int,
               d: Optional[int] = None,
               primes: Optional[list[int]] = None,
               id: str = "",
               pkcs1params = None,
               md = None):
    self.n = n
    self.e = e
    if primes is not None and not isinstance(primes, list):
      print(primes)
      raise ValueError("Invalid primes")
    self.primes = primes
    self.d = d
    self.id = id
    self.pkcs1params = pkcs1params
    # TODO: md is deprecated here.
    #   md is part of the algorithm not part of the key material
    self.md = md
    # Computing CRT parameters is somewhat expensive.
    # Hence the computation is delayed until this is necessary.
    # The main reason is that rsa_test_keys contains a large number of
    # Rsakeys. We don"t want to compute all the CRT parameters in cases
    # where this is not necessary.
    self.has_crt = False
    self.public = None

  def key_size_in_bytes(self):
    return (self.n.bit_length() + 7) // 8

  def prime_factors(self):
    if self.primes is None:
      self.fill_crt()
    return self.primes

  def private_exp(self, m: int) -> int:
    if not self.d:
      self.fill_crt()
    return pow(m, self.d, self.n)


  def fill_crt(self, sort_primes=True):
    if self.has_crt:
      return

    if self.primes:
      pass
    elif self.d:
      self.primes = factor_modulus(self.n, self.d * self.e - 1)
    else:
      raise ValueError("Either d or primes must be specified")

    if sort_primes:
      primes = sorted(self.primes)
      if len(primes) < 2:
        raise ValueError("RSA key is prime")
      primes[0], primes[1] = primes[1], primes[0]
      self.primes = primes

    # FIPS 186-4 requires d to be smaller than lcm(p-1, q-1).
    # PKCS #1 rsp. RFC 8017 only requires 0 < d < n.
    if self.d is None:
      order = 1
      for p in self.primes:
        gcd = math.gcd(order, p - 1)
        order = order * (p - 1) // gcd
      d = pow(self.e, -1, order)
      self.d = d

    # Recomputes exponents and coefficients
    # For i > 0:
    # coefficients[i] = (primes[1]* ... primes[i-1])^(-1) mod primes[i]
    # Hence, coefficients[1] = primes[0]^(-1) mod primes[1] = p^(-1) mod q.
    # The ASN representation however needs q^(-1) mod p.
    # For this we use coefficients[0] = q^(-1) mod p.
    #
    # Section 5.1.2 in RFC 8017 explains that the reordering p and q would
    # simplify the definitions, but that the order was kept for consistency
    # with PKCS #1 v2.0.
    self.exponents = []
    self.coefficients = []
    prod = 1
    for p in self.primes:
      self.exponents.append(self.d % (p - 1))
      self.coefficients.append(pow(prod, -1, p))
      prod *= p
    self.coefficients[0] = pow(self.primes[1], -1, self.primes[0])

    #  A free sanity check.
    if prod != self.n:
      raise ValueError("Incorrect list of primes")
    self.has_crt = True

  def check(self):
    self.fill_crt()
    if len(self.primes) < 2:
      raise ValueError("not enough primes")
    for p in self.primes:
      if pow(3, p, p) != 3:
        raise ValueError("%d is not prime" % p)
    if pow(3, self.d * self.e, self.n) != 3:
      raise ValueError("d is wrong")

  def publicKey(self):
    if self.public is None:
      self.public = RsaPublicKey(self.n, self.e, id=self.id,
                                 pkcs1params=self.pkcs1params)
    return self.public

  def privateKeyJwk(self, use:str, md:str = None):
    """Returns a JWK representation of the key or None.
 
    JWK does not seem to support multiprime RSA keys.
    """

    if len(self.primes) > 2:
      return None
    self.fill_crt()
    res = self.publicKey().publicKeyJwk(use, md)
    if res:
      res["d"] = util.uint2urlsafe64(self.d)
      res["p"] = util.uint2urlsafe64(self.primes[0])
      res["q"] = util.uint2urlsafe64(self.primes[1])
      res["dp"] = util.uint2urlsafe64(self.exponents[0])
      res["dq"] = util.uint2urlsafe64(self.exponents[1])
      res["qi"] = util.uint2urlsafe64(self.coefficients[0])
    return res

  def privateKeyPem(self):
    keymaterial = self.keymaterial_as_asn()
    return pem_util.private_key_pem(asn.encode(keymaterial))

  def pkcs1algorithm(self):
    """Returns the pkcs1algorithm that will be used in ASN encodings of this
       key. In many cases, libraries do not encode any algorithms and simply
       use rsaEncryption() independently of what the key is used.
       This is probably the result of implementing RSA keys without including
       a specific purpose."""
    if self.pkcs1params is not None:
      return self.pkcs1params
    else:
      return asnRsaEncryption()

  def keymaterial_as_asn(self, *, named: bool = False):
    self.fill_crt()
    assert len(self.primes) >= 2
    if len(self.primes) == 2:
      keymaterial = asn.Sequence(
          version = 0,
          modulus = self.n,
          publicExponent = self.e,
          privateExponent = self.d,
          prime1 = self.primes[0],
          prime2 = self.primes[1],
          exponent1 = self.exponents[0],
          exponent2 = self.exponents[1],
          coefficient = self.coefficients[0])
    else:
      otherinfo = collections.OrderedDict()
      for i in range(2, len(self.primes)):
        otherprime = asn.Sequence(
            prime = self.primes[i],
            exponent = self.exponents[i],
            coefficient = self.coefficients[i])
        otherinfo["otherPrimeInfo%d" % (i+1)] = otherprime
      otherprimeinfos = asn.Sequence(**otherinfo)
      keymaterial = asn.Sequence(
          version = 1,
          modulus = self.n,
          publicExponent = self.e,
          privateExponent = self.d,
          prime1 = self.primes[0],
          prime2 = self.primes[1],
          exponent1 = self.exponents[0],
          exponent2 = self.exponents[1],
          coefficient = self.coefficients[0],
          otherPrimeInfos = otherprimeinfos
      )
    return keymaterial

  def modifyPkcs8(self, case: modify.CaseIter, pkcs1algorithm=None):
    """Returns the ASN structure of a modified key with given parameters.
    """
    self.fill_crt()
    if pkcs1algorithm is None:
      pkcs1algorithm = self.pkcs1algorithm()
    version = 0
    n = self.n
    e = self.e
    d = self.d
    primes = self.primes[:]
    size = len(primes)
    exponents = self.exponents[:]
    coeffs = self.coefficients[:]
    phi_n = 1
    for p in primes:
      phi_n *= p - 1

    if case("e = 1"):
      e = 1
      d = 1
      exponents = [1] * size
    if case("d larger than n"):
      d += 2**64 * phi_n
    if case("dp is larger than p"):
      exponents[0] = d
    if case("dq is larger than q"):
      exponents[1] = d
    if case("iqmp is not reduced"):
      coeffs[0] += primes[0]
    if case("iqmp is negative"):
      coeffs[0] -= primes[0]

    for i in range(2, size):
      if case("exponent_%d is larger than the prime" % (i + 1)):
        exponents[i] = d
      if case("coefficients_%d is not reduced" % (i + 1)):
        coeffs[i] += primes[i]
      if case("coefficients_%d is negative" % (i + 1)):
        coeffs[i] -= primes[i]

    if case("p = 1"):
      exponents[1] = d % ((primes[0] - 1) * (primes[1] - 1))
      primes[0] = 1
      primes[1] = n
      coeffs[0] = 0
    if case("d is negative"):
      d -= phi_n
    if case("dp and dq are negative"):
      exponents[0] -= primes[0] - 1
      exponents[1] -= primes[1] - 1
    if case("all coefficients are negative"):
      d -= phi_n
      for i in range(size):
        exponents[i] -= primes[i] - 1
    if case("exceptionally large d"):
      d += 2**17000 * phi_n
    if case("exceptionally large invalid prime"):
      primes[-1] = 2**17000 // 173
    for i in range(size):
      if case("exceptionally large private exponent"):
        exponents[i] += 2**17000 * (primes[i] - 1)
    for i in range(size):
      if i == 1:
        continue
      if case("exceptionally large coefficient"):
        coeffs[i] += 2**17000* primes[i]
    if case("adding factor 1 in otherPrimeInfos"):
      primes.append(1)
      exponents.append(1)
      coeffs.append(0)
    for size, p in test_primes.LARGE_PRIMES:
      if size < 8192 or size > 16384:
        continue
      # Adds a large prime with CRT coefficient 0 to the list
      # of primes. If the CRT algorithm from RFC 8017 is used then
      # this addition computes the same result, it just uses
      # more time. This might be used for a denial of service
      # attack with primes much larger than the other primes.
      if case("adding unused %d-bit prime to otherPrimeInfos" % size):
        primes.append(p)
        if math.gcd(e, p - 1) == 1:
          dp = pow(e, -1, p - 1)
        else:
          # dp doesn"t matter, it just has to be large.
          dp = p - 2
        exponents.append(dp)
        coeffs.append(0)
    if case("adding 257 elements to otherPrimeInfos"):
      primes += [1]*257
      exponents += [1] * 257
      coeffs += [0] * 257
    otherinfo = [[p, e, c] for p, e, c in zip(primes, exponents, coeffs)]
    otherinfo = otherinfo[2:]

    # Checks for permutations
    for i in range(1, len(primes)):
      if case("primes are permuted"):
        primes[0], primes[i] = primes[i], primes[0]
        key = RsaPrivateKey(n=self.n, e=self.e, primes=primes)
        key.fill_crt(sort_primes=False)
        exponents = key.exponents
        coeffs = key.coefficients

    if len(otherinfo) == 0:
      version = 0
      if case("version 1 for a key with no otherPrimeInfos"):
        version = 1
    else:
      version = 1
      if case("version 0 for a key with no otherPrimeInfos"):
        version = 0
    if case("using invalid version 2"):
      version = 2

    if len(otherinfo) == 0:
      keymaterial = asn.Sequence(
          version = version,
          modulus = self.n,
          publicExponent = self.e,
          privateExponent = self.d,
          prime1 = self.primes[0],
          prime2 = self.primes[1],
          exponent1 = self.exponents[0],
          exponent2 = self.exponents[1],
          coefficient = self.coefficients[0])
    else:
      keymaterial = asn.Sequence(
          version = version,
          modulus = n,
          publicExponent = e,
          privateExponent = d,
          prime1 = primes[0],
          prime2 = primes[1],
          exponent1 = exponents[0],
          exponent2 = exponents[1],
          coefficient = coeffs[0],
          otherPrimeInfos = otherinfo)
    return [version, pkcs1algorithm, asn.OctetStringFromStruct(keymaterial)]

  def modifiedPkcs8(self, pkcs1algorithm = None):
    yield from modify.CaseIter(lambda case: self.modifyPkcs8(case, pkcs1algorithm))

  def privateKeyPkcs8(self, pkcs1algorithm=None):
    """Returns the ASN structure of this key with given parameters.
       pkcs1algorithm is an algorithm-identifier as defined in section
       A.2 of RFC 8017.
       E.g. [asn.Oid("2a864886f70d010101"), asn.Null()]
       would be used for encryption keys with PKCS #1 padding."""
    if pkcs1algorithm is None:
      pkcs1algorithm = self.pkcs1algorithm()
    keymaterial = self.keymaterial_as_asn()
    # RFC 5208, page 4
    return asn.Sequence(
        version=0,
        privateKeyAlgorithm=pkcs1algorithm,
        privateKey=asn.OctetStringFromStruct(keymaterial))

  def as_struct(self):
    res = collections.OrderedDict()
    self.fill_crt()
    res["modulus"] = AST.BigInt(self.n)
    res["privateExponent"] = AST.BigInt(self.d)
    res["publicExponent"] = AST.BigInt(self.e)
    res["prime1"] = AST.BigInt(self.primes[0])
    res["prime2"] = AST.BigInt(self.primes[1])
    res["exponent1"] = AST.BigInt(self.exponents[0])
    res["exponent2"] = AST.BigInt(self.exponents[1])
    res["coefficient"] = AST.BigInt(self.coefficients[0])
    otherinfos = []
    for i in range(2, len(self.primes)):
      p = AST.BigInt(self.primes[i])
      exp = AST.BigInt(self.exponents[i])
      coeff = AST.BigInt(self.coefficients[i])
      otherinfos.append([p, exp, coeff])
    if otherinfos:
      res["otherPrimeInfos"] = otherinfos
    return res

  def __repr__(self):
    arglist = "%s, %s, %s" % (self.n, self.primes, self.e)
    if self.md is not None:
      arglist += ", md=%s" % repr(self.md)
    if self.pkcs1params is not None:
      argslist += ", pkcs1params=%s" % repr(self.pkcs1params)
    return "RsaPrivateKey(%s)" % arglist

  def __str__(self):
    def hexstr(n, indent):
      nl = "\n" + indent + "    "
      s = hex(n)[2:].replace("L", "")
      res = "int("
      for j in range(0, len(s), 64):
        if j: res += nl
        res += repr(s[j:j+64])
      res += "," + nl + "16)"
      return res

    def hexlist(L, indent):
      res = "[\n" + indent
      for i,p in enumerate(L):
        res += hexstr(p, indent)
        if i < len(L) - 1:
          res += ",\n" + indent
      res += "]"
      return res

    indent = "  "
    args = []
    args.append("n = " + hexstr(self.n, indent=indent + 4 * " "))
    plist = hexlist(self.prime_factors(), indent=indent + 4 * " ")
    args.append("primes = " + plist)
    args.append("e = %d" % self.e)
    if self.md:
      args.append("md = %s" % repr(self.md))
    if self.id:
      args.append("id = %s" % repr(self.id))
    if self.pkcs1params:
      args.append("pkcs1params = %s" % repr(self.pkcs1params))
    argsstr = (",\n" + indent).join(args)
    return "RsaPrivateKey(\n" + indent + argsstr + ")"


class RsaPublicKey:
  """Describes an RSA public key.

  The data type is based on RSAPublicKey defined in
  Section A.1.1. of RFC 8017.
  """

  schema = {
      "modulus": {
          "type": AST.BigInt,
          "desc": "the modulus of the key",
      },
      "publicExponent": {
          "type": AST.BigInt,
          "desc": "the public exponent",
      },
  }

  def __init__(self, n, e, id = "", pkcs1params = None):
    self.n = n
    self.e = e
    self.id = id
    self.pkcs1params = pkcs1params

  def key_size_in_bytes(self):
    return (self.n.bit_length() + 7) // 8

  def publicKey(self):
    return self

  def fill_crt(self):
    pass  # Nothing to do

  def publicKeyAsn(self, params=None):
    if params is None:
      params = self.pkcs1algorithm()
    keymaterial = asn.BitString([self.n,self.e])
    return [params, keymaterial]

  def publicKeyPem(self):
    der = asn.encode(self.publicKeyAsn())
    return pem_util.public_key_pem(der)

  def publicKeyJwk(self, use: str, md: str = None):
    assert use in ["sig", "RSA1_5", "RSA-OAEP", "RSA-OAEP-256"]
    if use == "sig":
      alg_names = {
        "SHA-256": "RS256",
        "SHA-384": "RS384",
        "SHA-512": "RS512"}
      if md in alg_names:
        alg = alg_names[md]
      else:
        return None
    else:
      alg = use
    return { "kty" : "RSA",
             "alg" : alg,
             "n" : util.uint2urlsafe64(self.n),
             "e" : util.uint2urlsafe64(self.e),
             "kid" : "none" }

  def pkcs1algorithm(self):
    """Returns the pkcs1algorithm that will be used in ASN encodings of this
       key. In many cases, libraries do not encode any algorithms and simply
       use rsaEncryption() independently of what the key is used.
       This is probably the result of implementing RSA keys without including
       a specific purpose."""
    if self.pkcs1params is not None:
      return self.pkcs1params
    else:
      return asnRsaEncryption()

  def as_struct(self):
    return {
        "modulus": AST.BigInt(self.n),
        "publicExponent": AST.BigInt(self.e),
    }

  def __repr__(self):
    arglist = "%s, %s" % (self.n, self.e)
    if self.id:
      argslist += ", id=%s" % repr(self.id)
    if self.pkcs1params is not None:
      argslist += ", pkcs1params=%s" % repr(self.pkcs1params)
    return "RsaPublicKey(%s)" % arglist

  def __str__(self):
    def hexstr(n, indent):
      nl = "\n" + indent + "    "
      s = hex(n)[2:].replace("L", "")
      res = "int("
      for j in range(0, len(s), 64):
        if j: res += nl
        res += repr(s[j:j+64])
      res += "," + nl + "16)"
      return res

    indent = "  "
    args = []
    args.append("n = " + hexstr(self.n, indent=indent + 4 * " "))
    args.append("e = %d" % self.e)
    if self.id:
      args.append("id = %s" % repr(self.id))
    if self.pkcs1params:
      args.append("pkcs1params = %s" % repr(self.pkcs1params))
    argsstr = (",\n" + indent).join(args)
    return "RsaPublicKey(\n" + indent + argsstr + ")"

if __name__ == "__main__":
  import doctest
  doctest.testmod()
