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
import keccak
import sm3
from util import type_check

@type_check
def hash(hash_name: str, message: bytes) -> bytes:
  """Convenience function for computing a hash.

  Args:
    hash_name: the name of teh hash.
    message: the message to hash

  Returns:
    the hash value
  """
  # SHAKE128 and SHAKE256 have variable length output.
  # When used as a hash function then the output length is typically
  # defined as 32 and 64 bytes respectively.
  # Situations where this is defined explicitely are:
  #   RFC 8702, Section 3.2.2: ECDSA signatures with SHAKE
  #   RFC 8702, Section 3.2.1: RSA-PSS signatures with SHAKE
  #     (the MGF however uses an output size depending on the padding).
  if hash_name == "SHAKE128":
    return shake(hash_name, message, 32)
  elif hash_name == "SHAKE256":
    return shake(hash_name, message, 64)
  elif hash_name == "KECCAK-224":
    return keccak.KECCAK_224(message)
  elif hash_name == "KECCAK-256":
    return keccak.KECCAK_256(message)
  elif hash_name == "KECCAK-384":
    return keccak.KECCAK_384(message)
  elif hash_name == "KECCAK-512":
    return keccak.KECCAK_512(message)
  elif hash_name == "SM3":
    return sm3.Sm3(message)

  if hash_name == "MD5":
    md = hashlib.md5()
  elif hash_name == "SHA-1":
    md = hashlib.sha1()
  elif hash_name == "SHA-224":
    md = hashlib.sha224()
  elif hash_name == "SHA-256":
    md = hashlib.sha256()
  elif hash_name == "SHA-384":
    md = hashlib.sha384()
  elif hash_name == "SHA-512":
    md = hashlib.sha512()
  elif hash_name == "SHA3-224":
    md = hashlib.sha3_224()
  elif hash_name == "SHA3-256":
    md = hashlib.sha3_256()
  elif hash_name == "SHA3-384":
    md = hashlib.sha3_384()
  elif hash_name == "SHA3-512":
    md = hashlib.sha3_512()
  elif hash_name == "SHA-512/224":
    md = hashlib.new("sha512-224")
  elif hash_name == "SHA-512/256":
    md = hashlib.new("sha512-256")
  # When used as a hash SHAK128 has 32 bytes of output
  # and SHAKE256 has 64 bytes of output
  else:
    raise ValueError("Unknown hash:" + hash_name)
  md.update(message)
  return md.digest()

def block_size(hash_name: str) -> int:
  """Returns the block size of a hash function in bytes.
  
  The block size is the number of bytes of the message
  that are compressed in one step.

  Args:
    hash_name: the name of the hash function
  
  Returns:
    the block size of the hash function in bytes.
  """
  if hash_name in ["MD5", "SHA-1", "SHA-224", "SHA-256", "SM3"]:
    return 64
  elif hash_name in ["SHA-384", "SHA-512", "SHA-512/224", "SHA-512/256"]:
    return 128
  elif hash_name == "SHA3-224":
    return 144
  elif hash_name == "SHA3-256":
    return 136
  elif hash_name == "SHA3-384":
    return 104
  elif hash_name == "SHA3-512":
    return 72
  elif hash_name == "KECCAK-224":
    return 144
  elif hash_name == "KECCAK-256":
    return 136
  elif hash_name == "KECCAK-384":
    return 104
  elif hash_name == "KECCAK-512":
    return 72
  else:
    raise ValueError("Unknown hash:" + hash_name)

  
def digest_size(hash_name: str) -> int:
  """Returns the digest size of a hash function in bytes.

  Args:
    hash_name: the name of the hash

  Returns:
    the length of the digest in bytes
  """
  return len(hash(hash_name, b""))


@type_check
def shake(name: str, message: bytes, size: int) -> bytes:
  """Computes the SHAKE hash and returns size bytes.

  Args:
    name: the name of the function
    message: the message to hash
    size: the size of the output in bytes

  Returns:
    the SHAKE hash of message
  """
  if name == "SHAKE128":
    md = hashlib.shake_128()
  elif name == "SHAKE256":
    md = hashlib.shake_256()
  else:
    raise ValueError("Unknown algorithm:" + name)
  md.update(message)
  return md.digest(size)


