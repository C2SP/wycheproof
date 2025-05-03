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

# DEPRECATED: USE certificate.py

import asn
import asn_parser
import base64
import certificate_collection


def extract_certs_pem(s: str, debug=False) -> bytes:
  '''Tries to extract a list of PEM encoded keys from s.
     Yields the pem strings.
     Args:
       s: the string to parse
       debug: print the string that cannot be parsed
  '''
  pos = 0
  prefix = '-----BEGIN CERTIFICATE-----'
  postfix = '-----END CERTIFICATE-----'
  maxsize = 8000
  while True:
    start = s.find(prefix, pos)
    if start == -1:
      break
    stop = s.find(postfix, start)
    if stop == -1:
      break
    b64 = s[start + len(prefix):stop]
    pos = start + len(prefix)
    try:
      bytes = base64.b64decode(b64.encode('ascii'))
      yield bytes
    except Exception as ex:
      # This is not a PEM key or the code doesn't know to handle it.
      if debug:
        print('Cannot parse', b64, ex)


def print_asn(name: str, asn_struct):
  from pprint import PrettyPrinter
  pp = PrettyPrinter(indent=2)
  print(name + '=')
  pp.pprint(asn_struct)

def test_subject_public_key_info(subject_public_key_info):
  """
     SubjectPublicKeyInfo  ::=  SEQUENCE  {
        algorithm            AlgorithmIdentifier,
        subjectPublicKey     BIT STRING  }
  """
  algorithm, subject_public_key = subject_public_key_info
  print_asn("algorithm", algorithm)
  b = subject_public_key.val
  assert b[0] == 0
  pub_key_struct = asn_parser.parse(b[1:])
  print_asn("pub_key", pub_key_struct)

def test_tbs_certificate(tbs_cert):
  """
  TBSCertificate  ::=  SEQUENCE  {
        version         [0]  EXPLICIT Version DEFAULT v1,
        serialNumber         CertificateSerialNumber,
        signature            AlgorithmIdentifier,
        issuer               Name,
        validity             Validity,
        subject              Name,
        subjectPublicKeyInfo SubjectPublicKeyInfo,
        issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
                             -- If present, version MUST be v2 or v3
        subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
                             -- If present, version MUST be v2 or v3
        extensions      [3]  EXPLICIT Extensions OPTIONAL
                             -- If present, version MUST be v3
        }

   Version  ::=  INTEGER  {  v1(0), v2(1), v3(2)  }

   CertificateSerialNumber  ::=  INTEGER

   Validity ::= SEQUENCE {
        notBefore      Time,
        notAfter       Time }

   Time ::= CHOICE {
        utcTime        UTCTime,
        generalTime    GeneralizedTime }

   UniqueIdentifier  ::=  BIT STRING

   SubjectPublicKeyInfo  ::=  SEQUENCE  {
        algorithm            AlgorithmIdentifier,
        subjectPublicKey     BIT STRING  }

   Extensions  ::=  SEQUENCE SIZE (1..MAX) OF Extension

   Extension  ::=  SEQUENCE  {
        extnID      OBJECT IDENTIFIER,
        critical    BOOLEAN DEFAULT FALSE,
        extnValue   OCTET STRING
                    -- contains the DER encoding of an ASN.1 value
                    -- corresponding to the extension type identified
                    -- by extnID
        }
  """
  if not isinstance(tbs_cert, list):
    raise ValueError("Expecting a list for tbs_certificate")
  if tbs_cert[0].tag == 160:
    version = tbs_cert[0]
    tbs_cert = tbs_cert[1:]
  else:
    version = None
  ( serialNumber,           # CertificateSerialNumber,
    signature,              # AlgorithmIdentifier,
    issuer,                 # Name,
    validity,               # Validity,
    subject,                # Name,
    subjectPublicKeyInfo    # SubjectPublicKeyInfo,
  ) = tbs_cert[:6]
  print_asn("signature alg:", signature)
  test_subject_public_key_info(subjectPublicKeyInfo)

  issuerUniqueID = None
  subjectUniqueID = None
  extensions = None     
  for f in tbs_cert[6:]:
    if f.tag == 129:
      issuerUniqueId = f
    elif f.tag == 130:
      subjectUniqueID = f
    elif f.tag == 163:
      extensions = None
    else:
      raise ValueError("unknown element" + repr(f))
  
  for i,v in enumerate(tbs_cert):
    print_asn("[%d]" % i, v)
    print(asn.encode(v).hex())
    
def test_certificate(cert: bytes):
  """
  From RFC 5280
  Certificate  ::=  SEQUENCE  {
    tbsCertificate       TBSCertificate,
    signatureAlgorithm   AlgorithmIdentifier,
    signatureValue       BIT STRING  }
  """
  struct = asn_parser.parse(cert)
  if not isinstance(struct, list):
    raise ValueError("Expecting a list")
  if len(struct) != 3:
    raise ValueError("Expecting list of length 3")
  tbs_certificate, sig_alg, signature = struct
  print_asn("signatureAlgorithm", sig_alg)
  print_asn("signatureValue", signature)
  test_tbs_certificate(tbs_certificate)

def test():
  errors = 0
  for sample in certificate_collection.samples():
    for cert in extract_certs_pem(sample):
      try:
        test_certificate(cert)
      except Exception as ex:
        print(ex)
        errors += 1
  assert not errors

if __name__ == "__main__":
  test()

