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

# This is experimental code with the following goals:
#
# - Comparing openssl encrypted files against a reference implementation
# - Collecting references
# - Generating special case encrypted pem files for test vector generation
# - Generating special case encrypted pem files for CTF

import asn
import asn_parser
import base64
import pbkdf
import os
import oid
import hmac_algorithms
import pem_algorithms
from typing import Optional
import util


def get_oid(val: str) -> oid.Oid:
  """Returns an OID from a string.
    
  Args:
    val: a string representation of the OID. E.g. "1.2.840.113549.2.9"
  Returns:
    an OID
  """
  o = oid.fromstr(val)
  # More information can be found like this:
  # oid_util.lookup(o)
  return o

# OIDs
id_PBES2 = get_oid("1.2.840.113549.1.5.13")  # RFC 8018
id_PBKDF2 = get_oid("1.2.840.113549.1.5.12")  # RFC 3370, RFC 5911, RFC 8018

# TODO: are these definitions still necessary.
#   They should be moved into the ciphers
id_aes128_ECB = get_oid('2.16.840.1.101.3.4.1.1')

rsaEncryption = get_oid("1.2.840.113549.1.1.1")


def xor(a: bytes, b:bytes) -> bytes:
  assert len(a) == len(b)
  return bytes(x ^ y for x, y in zip(a, b))

def UnknownOid(b:bytes):
  return ValueError("Unknown Oid:" + str(oid.frombytes(b)) + ';' + b.hex())


def check_type(struct, tag):
  if isinstance(struct, asn.Element):
    if struct.tag == tag:
      return
    else:
      raise ValueError("wrong tag", struct.tag)
  raise ValueError("wrong type", type(struct))

def check_null(struct):
  check_type(struct, asn.NULL)
  if struct.val:
    raise ValueError("null can't have a value")

def get_octets(struct):
  check_type(struct, asn.OCTET_STRING)
  return struct.val


def get_oid_val(struct):
  check_type(struct, asn.OBJECT_IDENTIFIER)
  return struct.val


@util.type_check
def asn_to_oid(struct) -> oid.Oid:
  check_type(struct, asn.OBJECT_IDENTIFIER)
  return oid.frombytes(struct.val)


def check_alg(struct, expected_oid: oid.Oid):
  if not isinstance(struct, list) or len(struct) != 2:
    raise ValueError("expecting [Oid(), null] got:" + str(struct))
  oid2 = get_oid_val(struct[0])
  if expected_oid.bytes() != oid2:
    raise ValueError("expecting Oid:" + expected_oid.hex() + " got:" + oid2.hex())
  check_null(struct[1])

def check_rsa_key(key):
  version, n, e, d, p, q, dp, dq, qinvp = key
  assert version == 0
  assert n == p*q
  assert pow(3, p, p) == 3
  assert pow(3, q, q) == 3
  assert d % (p-1) == dp
  assert d % (q-1) == dq
  assert e * dp % (p-1) == 1
  assert e * dq % (q-1) == 1
  assert q * qinvp % p == 1

header = "-----BEGIN ENCRYPTED PRIVATE KEY-----"
footer = "-----END ENCRYPTED PRIVATE KEY-----"


def get_key(password, salt, c, dklen: int, md: str):
  kdf = pbkdf.PBKDF2(md)
  return kdf(password, salt, c, dklen)

def pem_pkcs8_decrypt_raw(pem: str, password: bytes, log:bool = False):
  start = pem.find(header)
  if start == -1:
    raise ValueError("Could not find header")
  else:
    start += len(header)
  end = pem.find(footer)
  if end == -1:
    raise ValueError("Could not find footer")
  encoding = base64.b64decode(pem[start:end])
  struct = asn_parser.parse(encoding)
  if not isinstance(struct, list) or not len(struct) == 2:
    if log:
      print("parsed pem")
      print(struct)
    raise ValueError("Expecting [algorithm, ciphertext]")
  alg_struct = struct[0]
  if log:
    print(alg_struct)
  ciphertext = get_octets(struct[1])
  if not isinstance(alg_struct, list) or not len(struct) == 2:
    raise ValueError("Expecting [Oid, params]")
  oid1 = get_oid_val(alg_struct[0])
  if oid1 != id_PBES2.bytes():
    raise ValueError("only PBES2 is implemented:"+oid1.hex())
  pbes_params = alg_struct[1]
  if not isinstance(pbes_params, list) or not len(pbes_params) == 2:
    raise ValueError("Expecting [kdf, enc]")
  kdf = pbes_params[0]
  enc = pbes_params[1]
  if not isinstance(kdf, list) or not len(kdf) == 2:
    raise ValueError("Expecting [oid, params]")
  kdf_oid = get_oid_val(kdf[0])
  if kdf_oid != id_PBKDF2.bytes():
    raise ValueError("Only PBKDF2 is implemented")
  kdf_params = kdf[1]
  # TODO: Is the default for prf HMAC-SHA1?
  if not isinstance(kdf_params, list):
    raise ValueError("Expecting a list of KDF parameters")
  if len(kdf_params) not in (2, 3):
    raise ValueError("Invalid number of KDF parameters: %d" % len(kdf_params))
  salt = get_octets(kdf_params[0])
  c = kdf_params[1]
  if log:
    print('c =',c)
    print('salt =', salt.hex())
  if not isinstance(c, int):
    raise ValueError("iteration count is not an integer")
  if len(kdf_params) >= 3:
    mac = kdf_params[2]
    if not isinstance(mac, list) or not len(mac) == 2:
      raise ValueError("expecting [prf, param]")
    prf_oid = asn_to_oid(mac[0])
    prf_param = mac[1]
    hmac_alg = hmac_algorithms.from_oid(prf_oid)
    check_null(prf_param)
  else:
    hmac_alg = hmac_algorithms.HmacAlgorithm("SHA-1")
  if not isinstance(enc, list) or not len(enc) == 2:
    raise ValueError("expecting [algorithm, param]")
  alg_oid = asn_to_oid(enc[0])
  iv = get_octets(enc[1])
  pem_alg = pem_algorithms.get_algorithm(alg_oid)
  keysize = pem_alg.key_size() // 8
  dk = get_key(password, salt, c, keysize, hmac_alg.md)
  cipher = pem_alg.cipher(dk)
  iv_size = cipher.iv_size
  if iv_size is None:
    key_der = cipher.decrypt(ciphertext)
  else:
    key_der = cipher.decrypt(iv, ciphertext)
  if log:
    print('key_der', key_der.hex())
  key = asn_parse.parse(key_der)
  if log:
    print(key)
  # TODO: 
  if not isinstance(key, list) or len(key) != 3:
    raise ValueError("Expecting [version, alg, keymat]")
  version = key[0]
  if version != 0:
    # Version 1 is a multi-prime RSA key
    raise ValueError("Expecting version 0")
  check_alg(key[1], rsaEncryption)
  keymat = get_octets(key[2])
  rsa = asn_parse.parse(keymat)
  check_rsa_key(rsa)
  return rsa, salt, c, alg_oid, iv, hmac_alg.md

def pem_pkcs8_decrypt(pem: str, password: bytes, log:bool = False):
  key, salt, c, alg_oid, iv, md = pem_pkcs8_decrypt_raw(pem, password, log)
  return key


@util.type_check
def pem_pkcs8_encrypt(rsa_key,
                      password: bytes,
                      salt: bytes,
                      c: int,
                      alg_oid: oid.Oid,
                      iv: Optional[bytes] = None,
                      hmac_md: str = "SHA-256",
                      log: bool = False) -> str:
  """Generates an encrypted PEM of an RSA key.
  
  Args:
    rsa_key: the RSA key to encrypt
    password: the password used for the encryption
    salt: the salt used for the key derivation
    c: the number of rounds of the key derivation
    alg_oid: the OID of the encryption mode
    iv: the IV of the encryption (used for testing only)
    log: displays information while encrypting
  Returns:
    the encrypted key
 """

  if alg_oid is None:
    alg_oid = id_aes128_ECB
  pem_alg = pem_algorithms.get_algorithm(alg_oid)
  keysize_in_bits = pem_alg.key_size()
  keysize = keysize_in_bits // 8
  iv_size_in_bytes = pem_alg.iv_size()
  hmac_alg = hmac_algorithms.HmacAlgorithm(hmac_md)
  hmac_oid = get_oid(hmac_alg.oid)
  dk = get_key(password, salt, c, keysize, hmac_alg.md)
  cipher = pem_alg.cipher(dk)

  check_rsa_key(rsa_key)
  encoded_key = asn.OctetString(asn.encode(rsa_key))
  rsa_alg = [asn.Oid(rsaEncryption), asn.Null()]
  key = [0, rsa_alg, encoded_key]
  key_der = asn.encode(key)

  if iv_size_in_bytes is None:
    iv = bytes()
    ciphertext = cipher.encrypt(key_der)
  else:
    # Uses the IV passed into this function or generates a random one.
    # Passing an IV as argument is used for debugging and generating specific
    # edge cases.
    if iv is None:
      iv = os.urandom(iv_size_in_bytes)
    ciphertext = cipher.encrypt(iv, key_der)
  if log:
    print(key)
    print('key_der')
    print(key_der.hex())
    print('Ciphertext')
    print(ciphertext.hex())

  alg_struct = [
      asn.Oid(id_PBES2),
      [[
          asn.Oid(id_PBKDF2),
          [asn.OctetString(salt), c, [asn.Oid(hmac_oid),
                                      asn.Null()]]
      ], [asn.Oid(alg_oid), asn.OctetString(iv)]]
  ]
  struct = [alg_struct, asn.OctetString(ciphertext)]
  der = asn.encode(struct)
  b64 = base64.b64encode(der).decode('ascii')
  res = [header]
  for j in range(0, len(b64), 64):
    res.append(b64[j:j+64])
  res.append(footer)
  res.append("")
  return "\n".join(res)
