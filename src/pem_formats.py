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

import asn_defs
from pem_util import PemFormat

# Maybe merge with asn_defs
PublicKeyFormat = PemFormat(
    label = "PUBLIC KEY",
    structure = asn1crypto.keys.PublicKeyInfo,
    alt_structure = asn_defs.SubjectPublicKeyInfo)


PrivateKeyFormat = PemFormat(
   label = "PRIVATE KEY",
    structure = asn1crypto.keys.PrivateKeyInfo,
    alt_structure = asn_defs.PrivateKeyInfo)


# used in gen_rsa_pub_key
RsaPrivateKeyFormat = PemFormat(
    label = "RSA PRIVATE KEY",
    structure = asn1crypto.keys.RSAPrivateKey,
    alt_structure = asn_defs.RSAPrivateKey)

RsaPublicKeyFormat = PemFormat(
    label = "RSA PUBLIC KEY",
    structure = asn1crypto.keys.RSAPublicKey,
    alt_structure = asn_defs.RSAPublicKey)


EcPrivateKeyFormat = PemFormat(
    label = "EC PRIVATE KEY",
    structure = asn1crypto.keys.ECPrivateKey,
    alt_structure = asn_defs.ECPrivateKey)


# TODO: Where is this defined?
#   Shouldn't there be an algorithm included?
EcdsaPrivateKeyFormat = PemFormat(
    label = "ECDSA PRIVATE KEY",
    structure = asn_defs.ECPrivateKey)


# Reverse engineered:
AaaPrivateKeyFormat = PemFormat(
    label = "AAA PRIVATE KEY",
    structure = asn1crypto.keys.RSAPrivateKey)

DhParametersFormat = PemFormat(
    label = "DH PARAMETERS",
    structure = asn1crypto.keys.DomainParameters)

DsaParameterFormat = PemFormat(
    label = "DSA PARAMETERS",
    structure = asn1crypto.keys.DSAParams)

DsaPrivateKeyFormat = PemFormat(
    label = "DSA PRIVATE KEY",
    structure = asn1crypto.keys.DSAPrivateKey)

DsaPublicKeyFormat = PemFormat(
    label = "DSA PUBLIC KEY",
    structure = asn_defs.DsaPublicKey)

EcParameterFormat = PemFormat(
    label = "EC PARAMETERS",
    structure = asn1crypto.keys.ECDomainParameters)

EncryptedPrivateKey = PemFormat(
    label = "ENCRYPTED PRIVATE KEY",
    structure = asn1crypto.keys.EncryptedPrivateKeyInfo)

Certificate = PemFormat(
    label = "CERTIFICATE",
    structure = asn1crypto.x509.Certificate)
 
TrustedCertificate = PemFormat(
    label = "TRUSTED CERTIFICATE",
    structure = asn1crypto.x509.TrustedCertificate)

_pem_formats = None

def get_pem_formats():
  global _pem_formats
  if _pem_formats is None:
    _pem_formats = {}
    for n, f in globals().items():
      if isinstance(f, PemFormat):
        _pem_formats[f.label] = f
  return _pem_formats

get_pem_formats()

def format_for_label(label: str):
  pf = get_pem_formats()
  if label not in pf:
    raise ValueError('Unknown label:' + label)
  return pf[label]


def parse_to_struct(pem: str):
  label, b64, header_info, checksum = parse(pem)
  pem_format = format_for_label(label)
  asn = base64.b64decode(b64)
  return pem_format.structure.load(asn)


