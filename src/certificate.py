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

import base64
import pem
import pem_samples
import pem_util
import json
import asn1crypto.x509
import asn1crypto.algos
import hashlib
import ec_groups
import typing

""" 
Experimental code for analyzing certificates.
This code is not complete: the main goal here is to explore if some goals
in project paranoid are achievable.

Some of these goals are:
(1) It might be difficult to track down the public keys of an issuer, since
    these public keys are not included in the certificate. For ECDSA signatures
    it is possible to recompute possible public keys from the signature.
    Hence it might be possible to generate a table:
       public_key, r, s, hash(tbs_certificate)
    Then analyze public keys with more than one signature.

From RFC 5280
  Certificate  ::=  SEQUENCE  {
    tbsCertificate       TBSCertificate,
    signatureAlgorithm   AlgorithmIdentifier,
    signatureValue       BIT STRING  }

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

class PprintEncoder(json.JSONEncoder):
  """A JSONEncoder used in pprint.
  
  The pprint function used in this file uses JSON encoding instead of 
  python"s pprint. This seems to give a bit more readable results.
  The JSONEncoder needs to be extended to types that are not natively
  encodable in JSON. This conversion is done in this class."""

  def default(self, val):
    if isinstance(val, bytes):
      # Uses hex representation for bytes, since this is more readable than b64.
      return val.hex()
    try:
      # Just try the default encoding first
      return json.JSONEncoder.default(self, val)
    except Exception:
      # Unknown types are converted to their representation
      return repr(val)

def format_asn(struct):
  """A pretty printer based on JSON.

  Unfortunately, pprint does not give readable results. Converting the
  certificate to JSON and dumping this, seems to be more useful.
  """
  return json.dumps(struct.native, indent=2, cls=PprintEncoder)

def pprint(struct):
  print(format_asn(struct))


class Certificate:
  def __init__(self, asn: asn1crypto.x509.Certificate):
    self.struct = asn
    self.algorithm = self.get_algorithm()

  def __str__(self):
    return format_asn(self.struct)

  def get_subject_public_key_info(self):
    return self.struct["tbs_certificate"]["subject_public_key_info"]

  def get_algorithm(self) -> str:
    """Return the algorithm of the public key.
    
    Returns:
      the algorithm of the public key. E.g. ("rsa", "ec")
    """
    pk = self.get_subject_public_key_info()
    return pk["algorithm"]["algorithm"].native

  def get_sig_algorithm(self) -> str:
    """Returns the signature algorithm used in the certificate
    
    Returns:
      the signature algorithm. E.g., ("sha1_rsa", "sha256_ecdsa")
    """
    return self.struct["signature_algorithm"]["algorithm"].native


  def tbs_der(self) -> bytes:
    """Returns the DER encoded tbs_certificate.
    
    These are the bytes that are signed. I.e. a certificate has the structure
      Certificate  ::=  SEQUENCE  {
         tbsCertificate       TBSCertificate,
         signatureAlgorithm   AlgorithmIdentifier,
         signatureValue       BIT STRING  }
    where signatureValue is a signature of tbsCertificate using the algorithm
    specified in signatureAlgorithm.
    
    TODO: what happens when the tbsCertificate is not DER encoded?
    """
    tbs_certificate = self.struct["tbs_certificate"]
    return tbs_certificate.dump()

  def signature_algorithm(self):
    # pprint(cert["signature_algorithm"])
    # {
    #   "algorithm": "sha256_ecdsa",
    #   "parameters": null
    # }
    algorithms = {
        "md5_rsa": ("rsa", "md5"),
        "sha1_rsa": ("rsa", "sha1"),
        "sha256_rsa": ("rsa", "sha256"),
        "sha384_rsa": ("rsa", "sha384"),
        "sha512_rsa": ("rsa", "sha512"),
        "sha1_ecdsa": ("ecdsa", "sha1"),
        "sha224_ecdsa": ("ecdsa", "sha224"),
        "sha256_ecdsa": ("ecdsa", "sha256"),
        "sha384_ecdsa": ("ecdsa", "sha384"),
        "sha512_ecdsa": ("ecdsa", "sha512"),
    }
    sig_alg = self.struct["signature_algorithm"]["algorithm"].native
    if sig_alg not in algorithms:
      raise ValueError("Unsupported algorithm:" + sig_alg)
    return algorithms[sig_alg]

  def analyze_rsa(self):
    alg, mdname = self.signature_algorithm()
    if alg != "rsa":
      raise ValueError("Signature algorithm is not RSA")
    der = self.tbs_der()
    # pk is a ParsableOctetBitString
    pk = self.get_subject_public_key_info()
    pk_nat = pk.native
    n = pk_nat["public_key"]["modulus"]
    print("n", n)
    e = pk_nat["public_key"]["public_exponent"]
    print("e", e)
    sig = self.struct["signature_value"].native

    # Assuming that the certificate is self-signed.
    s = int.from_bytes(sig, "big")
    padded = pow(s, e, n)
    print("padded", hex(padded))

    md = hashlib.new(mdname)
    md.update(der)
    digest = md.digest().hex()
    print(mdname)
    print("digest", digest)
    print("      ", hex(padded)[-len(digest):])

  def ecdsa_signature(self):
    """Returns the values r,s of the ECDSA signature"""
    alg, md = self.signature_algorithm()
    if alg != "ecdsa":
      raise ValueError("Not an ECDSA signature")

    sig_asn = self.struct["signature_value"].native
    sig = asn1crypto.algos.DSASignature().load(sig_asn)
    r = sig["r"].native
    s = sig["s"].native
    return r,s

  def ec_public_keys(self):
    for v in ec_public_keys_extended():
      yield v[0]

  def ec_public_keys_extended(self):
    """Yields guesses for the EC public key used to sign this message.
    """
    alg, md = self.signature_algorithm()
    if alg != "ecdsa":
      raise ValueError("Not an ECDSA signature")

    ctx = hashlib.new(md)
    ctx.update(self.tbs_der())
    digest = ctx.digest()
    r,s = self.ecdsa_signature()
    bit_size = max(r, s).bit_length()

    # Heuristic assumption: r,s are typically close to max
    for size in [192, 224, 256, 384, 521]:
      if bit_size <= size:
        field_size = size
        break
    else:
      field_size = None
    # Guessing groups:
    if field_size == 224:
      groups = ["secp224r1"]
    elif field_size == 256:
      groups = ["secp256r1"]
    elif field_size == 384:
      groups = ["secp384r1"]
    elif field_size == 521:
      groups = ["secp521r1"]
    else:
      groups = []

    for gr in groups:
      curve = ec_groups.named_curve(gr)
      info = {"curve": gr, "r": r, "s": s, "md": md, "digest": digest.hex()}

      for y in curve.get_ys(r):
        G = curve.generator()
        R = curve.get_point(r, y)
        z = int.from_bytes(digest, "big")
        Y = (R * s - G * z) * pow(r, -1, curve.n)
        pt = Y.affine()
        yield curve.encode_uncompressed(pt), info


  def analyze_ec(self):
    der = self.tbs_der()
    # pk is a ParsableOctetBitString
    # { "algorithm": {
    #       "algorithm": "ec",
    #       "parameters": "secp224r1"},
    #   "public_key": "045b648240adfa1468269e8b..." }
    #
    pk = self.get_subject_public_key_info()
    pprint(pk)
    pk_point = pk["public_key"].native
    # Assumes cert is self signed (otherwise the keys don"t match.
    assert isinstance(pk_point, bytes)
    print("public  :", pk_point.hex())
    for pub in self.ec_public_keys():
      print("computed:", pub.hex())



def from_pem(pem: str):
  cert = pem_util.parse_to_struct(pem)
  if not isinstance(cert, asn1crypto.x509.Certificate):
    raise ValueError("Not a certificate")
  return Certificate(cert)
