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

from pyasn1.type.univ import BitString, OctetString, Integer, Sequence, Boolean
from pyasn1.type.univ import SetOf
from pyasn1.type.namedtype import NamedTypes, NamedType, OptionalNamedType
from pyasn1.type.namedtype import DefaultedNamedType
from pyasn1.type import tag
from pyasn1.codec.der import encoder

# Deprecated: I'm probably going to use asn1crypto

"""
 ECParameters ::= CHOICE {
    namedCurve      CURVE.&id({NamedCurve})
    -- implicitCurve   NULL
      -- implicitCurve MUST NOT be used in PKIX
    -- specifiedCurve  SpecifiedCurve
      -- specifiedCurve MUST NOT be used in PKIX
      -- Details for specifiedCurve can be found in [X9.62]
      -- Any future additions to this CHOICE should be coordinated
      -- with ANSI X.9.
   }
   -- If you need to be able to decode ANSI X.9 parameter structures,
   -- uncomment the implicitCurve and specifiedCurve above, and also
   -- uncomment the following:
   --(WITH COMPONENTS {namedCurve PRESENT})

   -- Sec 2.1.1.1 Named Curve

   CURVE ::= CLASS { &id OBJECT IDENTIFIER UNIQUE }
    WITH SYNTAX { ID &id }

   NamedCurve CURVE ::= {
   { ID secp192r1 } | { ID sect163k1 } | { ID sect163r2 } |
   { ID secp224r1 } | { ID sect233k1 } | { ID sect233r1 } |
   { ID secp256r1 } | { ID sect283k1 } | { ID sect283r1 } |
   { ID secp384r1 } | { ID sect409k1 } | { ID sect409r1 } |
   { ID secp521r1 } | { ID sect571k1 } | { ID sect571r1 },
   ... -- Extensible
   }

   -- Note in [X9.62] the curves are referred to as 'ansiX9' as
   -- opposed to 'sec'.  For example, secp192r1 is the same curve as
   -- ansix9p192r1.

   -- Note that in [PKI-ALG] the secp192r1 curve was referred to as
   -- prime192v1 and the secp256r1 curve was referred to as
   -- prime256v1.

   -- Note that [FIPS186-3] refers to secp192r1 as P-192,
   -- secp224r1 as P-224, secp256r1 as P-256, secp384r1 as P-384,
   -- and secp521r1 as P-521.

   secp192r1 OBJECT IDENTIFIER ::= {
    iso(1) member-body(2) us(840) ansi-X9-62(10045) curves(3)
    prime(1) 1 }

   sect163k1 OBJECT IDENTIFIER ::= {
    iso(1) identified-organization(3) certicom(132) curve(0) 1 }

   sect163r2 OBJECT IDENTIFIER ::= {
    iso(1) identified-organization(3) certicom(132) curve(0) 15 }

   secp224r1 OBJECT IDENTIFIER ::= {
    iso(1) identified-organization(3) certicom(132) curve(0) 33 }

   sect233k1 OBJECT IDENTIFIER ::= {
    iso(1) identified-organization(3) certicom(132) curve(0) 26 }

   sect233r1 OBJECT IDENTIFIER ::= {
    iso(1) identified-organization(3) certicom(132) curve(0) 27 }

   secp256r1 OBJECT IDENTIFIER ::= {
    iso(1) member-body(2) us(840) ansi-X9-62(10045) curves(3)
    prime(1) 7 }

   sect283k1 OBJECT IDENTIFIER ::= {
    iso(1) identified-organization(3) certicom(132) curve(0) 16 }

   sect283r1 OBJECT IDENTIFIER ::= {
    iso(1) identified-organization(3) certicom(132) curve(0) 17 }

   secp384r1 OBJECT IDENTIFIER ::= {
    iso(1) identified-organization(3) certicom(132) curve(0) 34 }

   sect409k1 OBJECT IDENTIFIER ::= {
    iso(1) identified-organization(3) certicom(132) curve(0) 36 }

   sect409r1 OBJECT IDENTIFIER ::= {
    iso(1) identified-organization(3) certicom(132) curve(0) 37 }

   secp521r1 OBJECT IDENTIFIER ::= {
    iso(1) identified-organization(3) certicom(132) curve(0) 35 }

   sect571k1 OBJECT IDENTIFIER ::= {
    iso(1) identified-organization(3) certicom(132) curve(0) 38 }

   sect571r1 OBJECT IDENTIFIER ::= {
    iso(1) identified-organization(3) certicom(132) curve(0) 39 }
"""
class EcParameters:
  pass

class EcPrivateKey(Sequence):
  """Implements ECPrivateKey defined in RFC 5915

  ECPrivateKey ::= SEQUENCE {
     version        INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
     privateKey     OCTET STRING,
     parameters [0] ECParameters {{ NamedCurve }} OPTIONAL,
     publicKey  [1] BIT STRING OPTIONAL
   }
  """

class Record(Sequence):
  _id_type = NamedType('id', Integer())
  _room_type = OptionalNamedType('room',
      Integer().subtype(
          explicitTag=tag.Tag(
              tag.tagClassContext,
              tag.tagFormatSimple, 0)))
  _house_type = DefaultedNamedType("house",
      Integer(0).subtype(
          explicitTag=tag.Tag(
               tag.tagClassContext,
               tag.tagFormatSimple, 1)))
  componentType = NamedTypes(_id_type, _room_type, _house_type)


def test():
  record = Record()
  record['id'] = 123
  record['room'] = 3
  record['house'] = 2

  b = encoder.encode(record)
  print(b.hex())
  print(asn_parse.parse(b))
  
if __name__ == "__main__":
  test()
  
