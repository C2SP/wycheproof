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

from asn1crypto.core import Sequence, OctetString, BitString, OctetBitString, Integer, ObjectIdentifier, Any, Null


class AlgorithmIdentifier(Sequence):
  asn_definition = """
    AlgorithmIdentifier  ::=  SEQUENCE  {
     algorithm               OBJECT IDENTIFIER,
     parameters              ANY DEFINED BY algorithm OPTIONAL  }
                                -- contains a value of the type
                                -- registered for use with the
                                -- algorithm object identifier value
  """
  _fields = [('algorithm', ObjectIdentifier),
             ('parameters', Any, {
                 'optional': True
             })]
  reference = 'RFC 3280, Section 5'


class SubjectPublicKeyInfo(Sequence):
  asn_definition = """
  SubjectPublicKeyInfo  ::=  SEQUENCE  {
     algorithm            AlgorithmIdentifier,
     subjectPublicKey     BIT STRING  }
  """
  _fields = [('algorithm', AlgorithmIdentifier),
             ('subjectPublicKey', OctetBitString)]
  reference = 'RFC 3280, Section 4.1'


# TODO: Attributes is SET of Attribute, but I can't find a definition
#   of attribute.
PrivateKeyAlgorithmIdentifier = Any
Attributes = Any


class PrivateKeyInfo(Sequence):
  asn_definition = """
      PrivateKeyInfo ::= SEQUENCE {
        version                   Version,
        privateKeyAlgorithm       PrivateKeyAlgorithmIdentifier,
        privateKey                PrivateKey,
        attributes           [0]  IMPLICIT Attributes OPTIONAL }
  """
  _fields = [('version', Integer),
             ('privateKeyAlgorithm', PrivateKeyAlgorithmIdentifier),
             ('privateKey', OctetString),
             ('attributes', Attributes, {
                 'explicit': 0,
                 'optional': True
             })]
  reference = 'RFC 5208, Section 5'


class RSAPublicKey(Sequence):
  asn_definition = """
    RSAPublicKey ::= SEQUENCE {
        modulus           INTEGER,
        publicExponent    INTEGER
    }
  """
  _fields = [('modulus', Integer), ('publicExponent', Integer)]
  reference = 'RFC 8017, Section A.1.1'


OtherPrimeInfos = Sequence


class RSAPrivateKey(Sequence):
  asn_definition = """     RSAPrivateKey ::= SEQUENCE {
             version           Version,
             modulus           INTEGER,  -- n
             publicExponent    INTEGER,  -- e
             privateExponent   INTEGER,  -- d
             prime1            INTEGER,  -- p
             prime2            INTEGER,  -- q
             exponent1         INTEGER,  -- d mod (p-1)
             exponent2         INTEGER,  -- d mod (q-1)
             coefficient       INTEGER,  -- (inverse of q) mod p
             otherPrimeInfos   OtherPrimeInfos OPTIONAL
         }
  """
  _fields = [('version', Integer), ('modulus', Integer),
             ('publicExponent', Integer), ('privateExponent', Integer),
             ('prime1', Integer), ('prime2', Integer), ('exponent1', Integer),
             ('exponent2', Integer), ('coefficient', Integer),
             ('otherPrimeInfos', OtherPrimeInfos, {
                 'optional': True
             })]
  reference = 'RFC 8017, Section A.1.2'

# TODO: add the definition if needed.
ECParameters = Any

class ECPrivateKey(Sequence):
  asn_definition = """
    ECPrivateKey ::= SEQUENCE {
      version        INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
      privateKey     OCTET STRING,
      parameters [0] ECParameters {{ NamedCurve }} OPTIONAL,
      publicKey  [1] BIT STRING OPTIONAL
    }"""
  _fields = [
      ('version', Integer),
      ('privateKey', OctetString),
      ('parameters', ECParameters, {'explicit': 0, 'optional': True}),
      ('publicKey', OctetBitString, {'explicit': 1, 'optional': True})]
  # Also ECDSA PRIVATE Key
  # TODO: maybe the mapping is not 1 to 1. Hence pem_label
  #   should be removed here.
  reference = 'RFC 5915, Section 3'

class DssParms(Sequence):
  asn_definition = """
    Dss-Parms  ::=  SEQUENCE  {
          p             INTEGER,
          q             INTEGER,
          g             INTEGER  }"""
  reference = "RFC 3278, Section 2.3.2"
  _fields = [
      ('p', Integer),
      ('q', Integer),
      ('q', Integer)]

class DsaPublicKey(Sequence):
  _fields = [
      ('y', Integer),
      ('p', Integer),
      ('q', Integer),
      ('q', Integer)]
  reference = "reverse engineered from OpenSSL"

class EcpkParameters(Sequence):
  asn_definition = """ EcpkParameters ::= CHOICE {
        ecParameters  ECParameters,
        namedCurve    OBJECT IDENTIFIER,
        implicitlyCA  NULL }"""
  reference = "RFC 3278, Section 2.3.5"""
  _fields = [
    ("ecParameters", ECParameters),
    ("nameCurve", ObjectIdentifier),
    ("implicitlyCA", Null)]


# Other formats (from code search):
# AAA PRIVATE Key
#   looks like an RSA key: [0, n, e, d, ...]
#   WiMax private keys
# CERTIFICATE
# CERTIFICATE REQUEST
# DH PARAMETERS
#   [p, g]
# DSA PARAMETERS
#   [p, q, g]
# DSA PRIVATE KEY
#   apparently this is just OpenSSL specific
#   maybe: [version(0), p, q, g, y, x]
# DSA PUBLIC Key
#   apparently this is just OpenSSL specific
#   maybe: [y, p, q, g]
# EC PARAMETERS
#   OID of named curve e.g. 1.2.840.10045.3.1.7)
# ECDSA PRIVATE KEY
#   [version(1), priv:OctetString, [0] Oid of curve, [1] Bitstring of public?
#   same as ECPrivateKey?
# ENCRYPTED PRIVATE KEY
# NEW CERTIFICATE REQUEST
# PKCS7
# TRUSTED CERTIFICATE
# X9.42 DH PARAMETERS
#   maybe [p,g,q]
# OPENSSH PRIVATE KEY
# OpenVPN Static Key V1
# PGP MESSAGE
# PGP PRIVATE KEY BLOCK
# PGP PUBLIC KEY BLOCK
# PGP SIGNATURE
# SSH SIGNATURE
# TACK BREAK SIG


