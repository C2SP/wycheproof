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

import hashlib
import hmac
import util
import typing

# More KDFs:
# https://web.archive.org/web/20160322090517/https://www.di-mgt.com.au/cryptoKDFs.html
# RFC 2898
#
# NIST Special Publication 800-56A, Section 5.8.1
# https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Ar3.pdf
#  - gives a lot of choices
#  - parameters are:
#    * shared secret,
#    * size of derived key,
#    * salt
#    * IV
#    * FixedInfo (e.g. parties, public keys, other public and private info)
#
# NIST SP 800-108
# https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-108.pdf
# Why is this legacy?
# 
# Section, 5
# - Counter mode (similar to kdf1, kdf2)
#    K(i) := PRF (KI, [i]2 || Label || 0x00 || Context || [L]2)
#    [i]2 just means integer to binary conversion, no endianess or length is
#    specified. 
#    All the fields have fixed length (defined by the protocol or the
#    key (section 5))
#    PRF is either HMAC or CMAC
#    
# - Feedback mode (somewhat similar to HKDF)
#   K(i) := PRF (KI, K(i-1) {|| [i]2 }|| Label || 0x00 || Context || [L]2) 
#   One main difference is that L is appended to the PRF input.
# 
# - double-pipeline iteration mode (new)
# Inputs:
# - key derivation key,
# - label
# - context
# - IV,
def I2OSP(n: int, m: int):
  '''
  I2OSP(n, m) returns an m byte bigendian representation of an unsigned
  integer as defined in RFC 3447 Section 4.1.
  >>> I2OSP(258, 4).hex()
  '00000102'
  '''
  if n < 0 or n.bit_length() >= 8 * m:
    raise ValueError("n is out of range")
  return n.to_bytes(4, "big")

# Not sure how to define a type for hash functions.
# This is an object that implements update(bytes) and digest() -> bytes
HashCtx = typing.Any
# Basically expecting typing.Callable[[], HashCtx] but that no longer works.
HashFunction = typing.Any

@util.type_check
def kdf(md: HashFunction,
        secret: bytes, 
        label: typing.Optional[bytes], 
        size: int,
        ctr: int) -> bytes:
  res = bytes()
  while len(res) < size:
    h = md()
    h.update(secret)
    h.update(I2OSP(ctr, 4))
    if label:
      h.update(label)
    res += h.digest()
    ctr += 1
  return res[:size]

# https://www.shoup.net/iso/std4.pdf
# Section 6.2.2
# TODO: this implementation has not been checked against
#   a third party implementation or test vectors.
def kdf1sha1(seed: bytes, size: int):
  '''Implements KDF-1 defined in ISO18033-2.
 
     The definition there does not include a label.

  Args:
     seed: the seed of the pseudorandom stream
     size: the requested number of bytes of the pseudorandom stream

  Returns:
     the pseudorandom bytes
  >>> kdf1sha1(bytes(range(16)), 42).hex()
  '719ea750a65a93d80e1e0ba33a2ba0e7acddd98cec12757110b0b95cdf5ba6857f406dc6f497a8508319'
  '''
  return kdf(hashlib.sha1, seed, None, size, ctr=0)

# https://www.shoup.net/iso/std4.pdf
# Section 6.2.3
# TODO: this implementation has not been checked against
#   a third party implementation or test vectors.
def kdf2sha1(seed: bytes, size: int):
  '''Implements KDF-2 defined in ISO18033-2. 
     The definition there does not include a label.

  Args:
     seed: the seed of the pseudorandom stream
     size: the requested number of bytes of the pseudorandom stream

  Returns:
     the pseudorandom bytes

  >>> kdf2sha1(bytes(range(16)), 42).hex()
  'ec12757110b0b95cdf5ba6857f406dc6f497a8508319267b14ea09aa27f2566d31206fc3bf568d303360'
  '''
  return kdf(hashlib.sha1, seed, None, size, ctr=1)

# TODO: this implementation has not been checked against
#   a third party implementation or test vectors.
def kdfX963Sha1(secret: bytes, label: bytes, size: int):
  '''Implements the KDF defined in X9.63 and SEC1.

  Args:
     secret: the seed of the pseudorandom stream
     label: an additional label
     size: the requested number of bytes of the pseudorandom stream

  Returns:
     the pseudorandom bytes

  >>> kdfX963Sha1(bytes(range(16)), bytes(range(16, 32)), 42).hex()
  'd5946768b3474b6c8166c2562a3ebfa5382c34f013d304345d0430a8896c0b7b70750e1de51bb97142ca'
  '''
  return kdf(hashlib.sha1, secret, label, size, ctr=1)
  
if __name__ == "__main__":
    import doctest
    doctest.testmod()

