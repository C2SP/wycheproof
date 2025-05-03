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
import ccm
import gcm
import pem
import aes_modes
import pem_algorithms

# TODO: Needs cleanup, documentation and verification
#   This implementation is taken from code used for a CTF challenge.
#   The code does not attempt to fully implement this code.
# TODO: Stuff to add
#   * other algorithms
#   * better verification
#   * references
#   * identify differences to PKCS #8 based PEMs.

# RFC 1421
#   gives an overview.
#   defines the PEM format (Section 4.3.1):
#      <CR><LF> required,
#      lines not longer than 1000 characters
#      only ASCII characters allowed.
# RFC 1422
#   Defines a grammar for PEM (mail).
# RFC 1423
#   Defines the encryption modes:
#     DES-CBC (Section 1.1)
#     MD2, MD5 (Section 2)
#     DES-ECB (Section 3.1)
#   Since this document has been written before AES and any other usable
#   block ciphers it is of no value for such ciphers.
# RFC 1424

# TODO: RFC 8018 does not define PKCS #5 based PEMs.
#   It defines the password based encryption that is used in both PEM encodings.
#   Hence it is unclear where this definiton is coming from.
#   Likely the files need to be reorganized further:
#     PKCS5: the password based encryption used in both PEM forms
#     PKCS8 PEM variants
#     PKCS5 PEM variants

pkcs5_header = "-----BEGIN RSA PRIVATE KEY-----"
pkcs5_footer = "-----END RSA PRIVATE KEY-----"

def pem_pkcs5_decrypt(pem_key: str,
                      password: bytes,
                      c: int = 2048,
                      log: bool = False):
  md = "SHA-256"
  start = pem_key.find(pkcs5_header)
  if start == -1:
    raise ValueError("Could not find header")
  else:
    start += len(pkcs5_header)
  end = pem_key.find(pkcs5_footer)
  if end == -1:
    raise ValueError("Could not find footer")
  end_intro = pem_key.find('\n\n')
  if end_intro == -1:
    raise ValueError("Could not divide pem")
  intro = pem_key[start:end_intro]
  ct = base64.b64decode(pem_key[end_intro : end])
  # TODO: Where is this defined?
  # Proc-Type: 4,ENCRYPTED
  # DEK-Info: AES-128-CBC,4584A08F24B664D84621B8395C20B7B1
  fields = {}
  for line in intro.split('\n'):
    parts = line.split(':', 1)
    if len(parts) == 2:
      fields[parts[0]] = parts[1]
    elif line:
      print("unknown line:", line)
  if 'Proc-Type' in fields:
    if fields['Proc-Type'].strip() != '4,ENCRYPTED':
      print("unknown proc-Type", fields['Proc-Type'])
  if "DEK-Info" not in fields:
    raise ValueError("No DEK-Info")
  alg, salt_hex = fields["DEK-Info"].split(",")
  alg = alg.strip()
  salt = bytes.fromhex(salt_hex)
  # TODO: add more algorithms
  if alg in pem_algorithms.ALGORITHM_TABLE_PKCS5:
    pem_alg = pem_algorithms.ALGORITHM_TABLE_PKCS5[alg]
    keysize = pem_alg.key_size() // 8
    ivsize = pem_alg.iv_size()
  else:
    raise ValueError("Unsupported algorithm:" + alg)
  dk = pem.get_key(password, salt, c, keysize + ivsize, md)
  if log:
    print(len(ct))
    print(ct.hex())
  key = dk[:keysize]
  iv = dk[keysize:]
  cipher = pem_alg.cipher(key)
  if isinstance(cipher, ccm.Ccm) or isinstance(cipher, gcm.Gcm):
    aad = b""
    raw_ct = ct[:-cipher.tagsize]
    tag = ct[-cipher.tagsize:]
    if isinstance(cipher, gcm.Gcm):
      a, t = cipher.raw_decrypt(iv, aad, ct)
      # assert tag == t
    else:
      a = cipher.decrypt(iv, aad, ct, tag)
  else:
    a = cipher.decrypt(iv, ct)
  if log or 1:
    block = 32
    for i in range(0, len(a), block):
      print(a[i:i + block].hex())

    print("-----------------???-------------------")
