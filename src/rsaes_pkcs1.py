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

import asn
import hashlib
import rsa_key
import typing
import util
import prand
import flag
import conversions

def non_zero_bytes(size: int, seed: bytes, label: bytes) -> bytes:
  """Generates size non-zero bytes.

  The result is slightly biased. This doesn't matter here, since the
  result is used for test vectors only.

  Args:
    size: the number of bytes to generate
    seed: the seed for the pseudorandom number generator
    label: an additional argument for the pseudorandom number generator

  Returns:
    size pseudorandom bytes that are all not equal to 0.
  """
  # Generate ps_len non-zero bytes. The result is slightly biased.
  s1 = prand.randbytes(size, seed=seed, label=label)
  s2 = prand.randbytes(size, seed=seed, label=label + b"2")
  return bytes(x or y or 0xff for x, y in zip(s1, s2))

class DecryptionError(ValueError):
  """Thrown during decryption of a ciphertext.

  All cases of DecryptioErrors must not be distinguishable.
  If an attacker learns the cause of a decryption error
  then this information is useful for a padding oracle attack.
  """

class RsaesPkcs1:
  """Implements RSA PKCS#1 encryption.

  Using https://tools.ietf.org/html/rfc8017
  """

  def __init__(self, key, seed=b"1ly34h;jk4hkq"):
    self.key = key
    self.seed = seed  # Used to generate a deterministic padding
    self.mod_bits = key.n.bit_length()
    self.k = (self.mod_bits + 7) // 8


  def privateKeyPkcs8(self):
    """Returns the private key."""
    return self.key.privateKeyPkcs8()

  def max_message_size(self):
    """Returns the maximal size of the message in bytes."""
    return self.k - 11

  def pad(self, msg: bytes) -> bytes:
    """Pads the a message.

    Note the padding is deterministic and depends on the given
    seed. This is done so that test vector generation always generates
    the same values.

    Args:
      msg: the message to pad.

    Returns:
      the padded message.
    """
    m_len = len(msg)
    if m_len > self.max_message_size():
      raise ValueError("message too long")
    ps_len = self.k - m_len - 3
    ps = non_zero_bytes(ps_len, self.seed, msg)
    block_type = 2
    em = bytes(1) + bytes([block_type]) + ps + bytes(1) + msg
    assert len(em) == self.k
    return em

  @util.type_check
  def encrypt(self, msg: bytes) -> bytes:
    """Encrypts a message.

    Note this encryption is uses a determinstic padding so that
    test vector generation always generates the same test vector.

    Args:
      msg: the message to encrypt

    Returns:
      the encrypted message.
    """
    em = self.pad(msg)
    m = conversions.os2ip(em)
    c = pow(m, self.key.e, self.key.n)
    return conversions.i2osp(c, self.k)

  @util.type_check
  def decrypt(self, ct: bytes) -> bytes:
    """Decrypts a message.

    Args:
      ct: the ciphertext

    Returns:
      the decrypted message
    Raises:
      ValueError: if the ciphertext has the wrong format
      DecryptionError: if the padding is wrong. If an implementation throws
        distinct exceptions based on the error in the padding then padding
        oracle attacks are likely possible. Of course, such attacks are
        still possible if the implementation is correct but the caller
        blunders.
    """
    if len(ct) != self.k:
      raise ValueError("c is of incorrect length")
    c = conversions.os2ip(ct)
    if c >= self.key.n:
      raise ValueError("c is not a correct ciphertext")
    m = self.key.private_exp(c)
    em = conversions.i2osp(m, self.k)
    # This implementations does not try to be constant time,
    # since it is meant for test vector generation.
    valid = True
    if em[0] != 0:
      valid = False
    if em[1] != 2:
      valid = False
    first_zero = 0
    for i in range(self.k - 1, 0, -1):
      if em[i] == 0:
        first_zero = i
    if first_zero < 10:
      valid = False
    if valid:
      return em[first_zero + 1:]
    else:
      raise DecryptionError()

  # ===== Generation of modified ciphertexts =====
  @util.type_check
  def modified_encrypt(self, msg: bytes, mod_ct: bool, case) -> bytes:
    """Generate modified ciphertexts.

    Args:
      msg: the message to encrypt
      mod_ct: if True the ciphertext is modified if False only padding is
        modified.
      case: a CaseIter

    Returns:
      a modified ciphertext
    """
    m_len = len(msg)
    # Allow paddings that are too short at this point.
    if m_len > self.k - 3:
      raise ValueError("message too long")
    ps_len = self.k - m_len - 3
    ps = bytearray(non_zero_bytes(ps_len, self.seed, msg))
    if case("The padding string is all 0."):
      ps = bytes(ps_len)
    if case("The padding string is all 1 bits."):
      special_case_ps = flag.Flag(
          label="SpecialCasePadding",
          bug_type=flag.BugType.FUNCTIONALITY,
          description="This is a test vector where ps is not random. "
          "The ciphertext is still valid and decryption should not be "
          "affected.")
      case.add(flags=[special_case_ps])
      ps = bytes([255]) * ps_len
    if case("rsa_sslv23_padding"):
      # SSL3 would use this padding if rolled back to SSL2.
      # I.e. this padding is an error when rolled back, otherwise it is valid.
      # This is defined in the function RSA_padding_add_SSLv23 of openssl.
      rsa_sslv23_padding = flag.Flag(
          label="Sslv23Padding",
          bug_type=flag.BugType.FUNCTIONALITY,
          description="SSL v3 would use this padding if rolled back to version 2."
          "The padding is valid, it is simply a special case that was used to "
          "detect rollback attacks.")
      case.add(flags=[rsa_sslv23_padding])
      ps = ps[:-8] + bytes([3])*8
    # Zeros in ps are not allowed
    for i in (0, 1, 7):
      if case(f"Byte {i} of the padding string is 0. "
              "All bytes should be non-zero."):
        ps[i] = 0
    if ps_len > 2:
      if case("The padding string has been truncated."):
        ps = ps[:-2]
      if case("The padding string has been removed."):
        ps = bytes()
    ps = bytes(ps)
    block_type = 2
    first_byte = 0
    if case("The block type is 0."):
      block_type = 0
    if case("The block type is 1. This block type is used for signatures."):
      block_type = 1
    if case("The block type is 0xff."):
      block_type = 0xff
    if case("The first byte of the encoded message is 1."):
      first_byte = 1
    if case("The first byte of the encoded message is 3."):
      first_byte = 3
    if case("Using signature padding instead of encryption padding."):
      block_type = 1
      ps = bytes([0xff])*ps_len
    em = bytes([first_byte, block_type]) + ps + bytes(1) + msg
    if case("The byte after the padding string is not 0."):
      ps = non_zero_bytes(self.k, self.seed, b"1231")
      em = bytes([first_byte, block_type]) + ps
    if case("Using no padding (rsp. an all-zero padding)"):
      em = msg
    m = conversions.os2ip(em)
    if case("m = 2"):
      m = 2
    if case("m = n-2"):
      m = self.key.n - 2
    c = pow(m, self.key.e, self.key.n)
    ct_size = self.k
    if case("c = 0"):
      c = 0
    if case("c = 1"):
      c = 1
    if case("c = n-1"):
      c = self.key.n - 1
    if case("c = n"):
      ct_too_long = flag.Cve(
          "CVE 2021-3580",
          "Some implementations fail when the ciphertext is too long.")
      case.add(flags=[ct_too_long])
      c = self.key.n
    if case("ciphertext not reduced"):
      t = -c * pow(self.key.n, -1, 256) % 256
      c = c + t * self.key.n
      ct_size += 1
    res = conversions.i2osp(c, ct_size)
    if mod_ct:
      if case("ciphertext is empty"):
        res = bytes()
      if case("Prepended bytes to ciphertext"):
        cve = flag.Cve(
            "CVE 2020-14967",
            "jsrsasign package before 8.0.18 for Node.js. Its RSA PKCS1 v1.5 "
            "decryption implementation does not detect ciphertext modification "
            "by prepending '\0' bytes to ciphertexts.")
        case.add(flags=[cve])
        res = bytes(2) + res
      if case("appended bytes to ciphertext"):
        res = res + bytes(2)
      if case("truncated ciphertext"):
        res = res[1:]
    return res
