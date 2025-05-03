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

from google.auth import jwt

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature

# token and key generated in https://jwt.io
token = 'eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IkxZeVAyZyJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.OjJokSnHIdMxqTlpT055GJDe72-zoTZBE5NISmrDPx0dletHBTnlbl1wwr0EhWaxgKIesZ7N7eLd4XW-TgX-vA'

public_key = '-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEVs/o5+uQbTjL3chynL4wXgUg2R9\nq9UU8I5mEovUf86QZ7kOBIjJwqnzD1omageEHWwHdBO6B+dFabmdT9POxg==\n-----END PUBLIC KEY-----\n'

# test using google.auth
# This code fails because it is still expecting an RSA key
try:
  jwt.decode(token, certs=public_key)
  print("No error")
except Exception as e:
  print("Error decoding jwt:", e)

def asn_length(length: int) -> bytes:
  if length < 0:
    raise ValueError("negative length")
  if length < 128:
    return bytes([length])
  else:
    b = bytes()
    while length:
      length, rem = divmod(length, 256)
      b = bytes([rem]) + b
    if len(b) > 127:
      raise ValueError("integer too big")
    return bytes([128 + len(b)]) + b

def asn_encode(tag: int, value: bytes) -> bytes:
  return bytes([tag]) + asn_length(len(value)) + value

def asn_encode_int(value: bytes) -> bytes:
  '''Returns the asn encoding of a bigint.

  Args:
     val: the integer to encode in unsigned
          bigendian representation.
  Returns:
     The DER encoding of the integer.
  '''
  # Removes trailing 0's.
  while value and value[0] == 0:
    value = value[1:]
  # Prepends a 0 to avoid that the size is 0
  # or the encoding represents a negative integer.
  if len(value) == 0 or value[0] >= 128:
    value = bytes([0]) + value
  return asn_encode(0x02, value)


def convert_p1363_asn(sig: bytes, elem_size: int = 32) -> bytes:
  '''Converts a P1363 encoded ECDSA signature to an ASN.1 encoded signature.

  Args:
    sig: a P1363 encoded signature.
    elem_size: the size of a field element. (i.e. 32 bytes for NIST-P256 curves)
  Returns:
    the DER encoded signature.
  '''
  if len(sig) != 2*elem_size:
    raise ValueError("Not a valid P1363 encoded signature")
  r, s = sig[:elem_size], sig[elem_size:]
  return asn_encode(0x30, asn_encode_int(r) + asn_encode_int(s))


# obtain the signature and message from the token
header, payload, message, signature = jwt._unverified_decode(token)  # pylint: disable=protected-access

print('header:', header, type(header))
print('payload:', payload, type(payload))
print('message:', message, type(message))
print('signature:', signature.hex(), len(signature))

asn_sig = convert_p1363_asn(signature)

print('asn sig:', asn_sig.hex())

# decodes the public key. This simplifies checking its validity with
# other code.
pk_base64 = (b"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEVs/o5+uQbTjL3chynL4wXgUg2R9"
             b"q9UU8I5mEovUf86QZ7kOBIjJwqnzD1omageEHWwHdBO6B+dFabmdT9POxg==")
pk_der = base64.b64decode(pk_base64)
print('public_key:', pk_der.hex())
# This is the point of the public key.
pk_point = (7850540730117855537377310150564140534713067357541121232721010766305002029006,
            65316312644653463644210322201871599477553959356638327946530363791985981247174)


#test using cryptography
try:
  key = load_pem_public_key(public_key.encode("utf-8"), backend=default_backend())
  key.verify(asn_sig, message, ec.ECDSA(hashes.SHA256()))
  print("Token verified")
except InvalidSignature:
  print("Invalid signature")

