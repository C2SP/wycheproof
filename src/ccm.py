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

import cmac

class Ccm:
  block_cipher = None
  def __init__(self,
               key: bytes,
               tagsize: int = 16,
               skip_checks: bool = True):
    """Initializes an AES-CCM cipher with a given key and tag size.

    Args:
      cipher: a block cipher (e.g. aes.AES)
      key: the key
      tagsize: the size of the tag in bytes CCM allows tag sizes
          of 4,6,8,10,12,14,16 bytes
      skip_checks: True means that some parameter checks are skipped.
          This allows to generate test vectors for invalid parameters.

    """
    if self.block_cipher is None:
      raise ValueError("block_cipher is undefined. Use a subclass")
    if tagsize not in (4,6,8,10,12,14,16) and not skip_checks:
      raise ValueError("Incorrect tag size")
    if self.block_cipher.block_size_in_bytes != 16:
      raise ValueError("Not implemented")
    self.E = self.block_cipher(key)
    self.tagsize = tagsize
    self.skip_checks = skip_checks

  def _encode_aad(self, aad: bytes) -> bytes:
    a = len(aad)
    if a == 0:
      return bytes()
    if a < 2**16 - 2**8:
      p = a.to_bytes(2, "big")
    elif a < 2**32:
      p = bytes([0xff, 0xfe]) + a.to_bytes(4, "big")
    else:
      p = bytes([0xff, 0xff]) + a.to_bytes(8, "big")
    p += aad
    p += bytes(-len(p) % 16)
    return p

  def _formatbyte(self, aadsize: int, tagsize: int, noncesize: int) -> int:
    """Returns the format byte of B_0.

    Args:
      aadsize: the size of the additional data in bytes
      tagsize: the size of the tag in bytes
      noncesize: the size of the nonce in bytes
    Returns:
      the format byte of B_0
    """
    b = 0
    if aadsize > 0:
      b += 1 << 6
    b += ((tagsize - 2) // 2) << 3
    b += 14 - noncesize
    return b

  def _B0(self, aadsize: int, tagsize: int, nonce: bytes, msgsize: int) -> bytes:
    """Computes the first block of the CCM.

    Args:
      aadsize: the size of the additional data in bytes
      tagsize: the size of the tag in bytes
      nonce: the nonce
      msgsize: the size of the message in bytes
    Returns:
      B_0
    """
    noncesize = len(nonce)
    q = 15 - noncesize
    b = bytes([self._formatbyte(aadsize, tagsize, noncesize)])
    b += nonce
    if self.skip_checks:
      msgsize %= 256 ** q
    b += msgsize.to_bytes(q, "big")
    return b

  def _xor(self, a: bytes, b: bytes) -> bytes:
    assert len(a) == len(b)
    return bytes(x^y for x,y in zip(a,b))

  def _ctr(self, nonce: bytes, b: bytes) -> bytes:
    noncesize = len(nonce)
    q = 15 - noncesize
    iv = bytearray(bytes([(q - 1) % 256]) + nonce + bytes(q))
    res = bytearray(b)
    for i in range(len(b)):
      if i % 16 == 0:
        stream = self.E.encrypt_block(bytes(iv))
        for k in range(15, -1 ,-1):
          iv[k] = (iv[k] + 1) & 0xff
          if iv[k]: break
      res[i] ^= stream[i % 16]
    return bytes(res)

  def _ccm(self, nonce: bytes, aad: bytes, msg: bytes) -> bytes:
    """Computes the CCM.

    Args:
      nonce: the nonce
      aad: additional data to authenticate
      msg: the plaintext
    Returns:
      the full 16-byte CCM
    """
    b = self._B0(len(aad), self.tagsize, nonce, len(msg))
    b += self._encode_aad(aad)
    b += msg
    b += bytes(-len(b) % 16)
    block = bytes(16)
    for i in range(0, len(b), 16):
      block = self.E.encrypt_block(self._xor(block, b[i:i+16]))
    return block

  def _check_nonce(self, nonce: bytes) -> None:
    """Checks whether a nonce is valid.

    Some invalid nonces are accepted if self.skip_checks is True.
    This happens when it is possible to generate test vectors (although
    these test vectors are of course invalid.)

    Args:
      nonce: the nonce to check
    Raises:
      ValueError: if the nonce is not valid.
    """
    if 7 <= len(nonce) <= 13:
      # this is a valid nonce
      return
    if not self.skip_checks:
      raise ValueError("Invalid nonce size")
    # Nonces larger than 16 bytes make no sense,
    # even if we skip parameter checks.
    if len(nonce) > 15:
      raise ValueError("Undefined nonce size")

  def encrypt(self, nonce: bytes, aad: bytes, msg: bytes) -> tuple[bytes, bytes]:
    """Encrypts a message.

    Args:
      nonce: the nonce
      aad: the additional data to authenticate
      msg: the message to encrypt

    Returns:
      the ciphertext and the tag
    """
    self._check_nonce(nonce)
    assert len(aad) < 2**64
    # assert len(msg) < 16 * 2**(8*self.q - 4)
    tag = self._ccm(nonce, aad, msg)
    ct = self._ctr(nonce, tag + msg)
    return ct[16:], ct[:self.tagsize]

  def decrypt(self, nonce: bytes, aad: bytes, ct: bytes, tag: bytes) -> bytes:
    """Decrypts a ciphertext.

    Args:
      nonce: the nonce
      aad: the additional data
      ct: the ciphertext
      tag: the tag
    Returns:
      the plaintext
    Raises:
      ValueError: if the ciphertext is incorrect
    """
    if len(aad) >= 2**64:
      raise ValueError("AAD is too long")
    # assert len(ct) < 16 * 2**(8*self.q - 4)
    self._check_nonce(nonce)
    if len(tag) != self.tagsize:
      raise ValueError("Tag size is incorrect")
    m = self._ctr(nonce, tag + bytes(-len(tag)%16) + ct)
    tag0 = m[:self.tagsize]
    msg = m[16:]
    tag1 = self._ccm(nonce, aad, msg)
    if tag1[:self.tagsize] != tag0:
      raise ValueError("Invalid tag")
    return msg

if __name__ == "__main__":
  pass
