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
from typing import Union, Optional, Tuple
import util
import prand
import conversions


@util.type_check
def xor(a: bytes,b: bytes) -> bytes:
  assert len(a) == len(b)
  return bytes(x^y for x,y in zip(a, b))

@util.type_check
def mgf1(md: str, seed: bytes, size: int) -> bytes:
  ctr = 0
  res = bytes()
  while len(res) < size:
    res += util.hash(md, seed + conversions.i2osp(ctr, 4))
    ctr += 1
  return res[:size]

class DecryptionError(ValueError):
  """Thrown during decryption of a ciphertext.

     All cases of DecryptioErrors must not be distinguishable.
     If an attacker learns the cause of a decryption error
     then this information is useful for a padding oracle attack.
  """

class RsaesOaep:
  """Using https://tools.ietf.org/html/rfc8017"""

  def __init__(self,
               key,
               md: str,
               mgf: str,
               mgf_md: str,
               seed=b"1ly34h;jk4hkq"):
    key.fill_crt()
    self.key = key
    self.md = md
    assert isinstance(mgf, str)
    mgf = mgf.upper()
    if mgf == "MGF1":
      self.mgf = mgf1
    else:
      raise ValueError("Unknown mgf:" + mgf)
    self.mgf_md = mgf_md
    self.seed = seed  # Used to generate a deterministic padding
    self.mod_bits = key.n.bit_length()
    self.k = (self.mod_bits + 7) // 8
    self.h_len = len(util.hash(md, b""))

  def asn_mask_gen_algorithm(self):
    assert self.mgf == mgf1
    mgf_md_oid = asn.oid_from_hash(self.mgf_md)
    mgf1_oid = asn.Oid("2a864886f70d010108")
    return [mgf1_oid, [mgf_md_oid, asn.Null()]]

  def asn_oaep_params(self):
    """Returns the RSAES-OAEP-Params for this class
       as defined in Section A.2.1 of RFC 8017."""
    md_oid = asn.oid_from_hash(self.md)
    mask_gen_algorithm = self.asn_mask_gen_algorithm()
    return [[md_oid, asn.Null()], mask_gen_algorithm]

  def privateKeyPkcs8(self):
    # TODO: BoringSSL, Conscrypt etc do not accept keys with
    #   OAEP parameters. Not sure what is wrong.
    # id_rsaes_oaep = asn.Oid("2a864886f70d010107")
    # params = self.asn_oaep_params()
    # pkcs1algorithm = [id_rsaes_oaep, params]
    # return self.key.privateKeyPkcs8(pkcs1algorithm)
    return self.key.privateKeyPkcs8()

  @util.type_check
  def encrypt(self,
              msg: bytes,
              label: Optional[bytes] = None) -> bytes:
    if label is None:
      label = b""
    if len(msg) > self.k - 2 * self.h_len - 2:
      raise ValueError("message too long")
    l_hash = util.hash(self.md, label)
    ps = bytes(self.k - len(msg) - 2 * self.h_len - 2)
    db = l_hash + ps + bytes([0x01]) + msg
    seed = prand.randbytes(self.h_len, seed=self.seed, label=msg)
    db_mask = self.mgf(self.mgf_md, seed, self.k - self.h_len - 1)
    masked_db = xor(db, db_mask)
    seed_mask = self.mgf(self.mgf_md, masked_db, self.h_len)
    masked_seed = xor(seed, seed_mask)
    em = bytes(1) + masked_seed + masked_db
    m = conversions.os2ip(em)
    c = pow(m, self.key.e, self.key.n)
    return conversions.i2osp(c, self.k)

  @util.type_check
  def decrypt(self,
              ct: bytes,
              label: Optional[bytes] = None) -> bytes:
    if label is None:
      label = bytes()
    l_hash = util.hash(self.md, label)
    if len(ct) != self.k:
      raise ValueError("c is of incorrect length")
    c = conversions.os2ip(ct)
    if c >= self.key.n:
      raise ValueError("c is not a correct ciphertext")
    m = pow(c, self.key.d, self.key.n)
    em = conversions.i2osp(m, self.k)
    y = em[0]
    masked_seed = em[1:1+self.h_len]
    masked_db = em[1+self.h_len:]
    seed_mask = self.mgf(self.mgf_md, masked_db, self.h_len)
    seed = xor(masked_seed, seed_mask)
    db_mask = self.mgf(self.mgf_md, seed, self.k - self.h_len - 1)
    db = xor(masked_db, db_mask)
    l_hash2 = db[:self.h_len]
    ok = True
    # Because of Mangers attack no information about padding errors
    # should be leaked. In the following code no attempts to remove
    # timing leaks have been made. This code is for test generation only.
    if l_hash != l_hash2:
      ok = False
    if y != 0:
      ok = False
    msg_start = None
    for i in range(self.h_len, len(db)):
      if db[i] == 1:
        msg_start = i + 1
        break
      elif db[i] != 0:
        break
    if msg_start is None:
      ok = False
    if ok:
      return db[msg_start:]
    else:
      raise DecryptionError()

  @util.type_check
  def try_unpad(self, em: bytes) -> Optional[Tuple[bytes, bytes]]:
    """Helper function for test vector generation.
    
    This function tries to return a message and a label such that the padding
    of the message and the label is equal to em.
    
    Args:
      em:
    """
    assert len(em) == self.k
    if em[0] != 0: return
    if self.mgf != mgf1: return
    if self.md != self.mgf_md: return
    if em[1+self.h_len:1+2*self.h_len] == bytes(self.h_len):
      masked_seed = em[1:1+self.h_len]
      masked_db = em[1+self.h_len:]
      seed_mask = self.mgf(self.mgf_md, masked_db, self.h_len)
      seed = xor(masked_seed, seed_mask)
      label = seed + bytes(4)
      db_mask = self.mgf(self.mgf_md, seed, self.k - self.h_len - 1)
      db = xor(masked_db, db_mask)
      l_hash = util.hash(self.md, label)
      l_hash2 = db[:self.h_len]
      assert l_hash == l_hash2
      for i in range(self.h_len, len(db)):
        if db[i] == 1:
          return db[i+1:], label
        if db[i] != 0:
          return

  def max_message_size(self) -> int:
    return self.k - 2 * self.h_len - 2

  # ===== Generation of modified ciphertexts =====
  @util.type_check
  def modified_encrypt(self,
                       msg: bytes,
                       label: Optional[bytes] = None,
                       case=None) -> bytes:
    if label is None:
      label = bytes()
    assert case
    if len(msg) > self.k - 2 * self.h_len - 2:
      raise ValueError("message too long")
    if len(label) > 0:
      if case("non-empty label replaced with empty string"):
        label = b""
    l_hash = bytearray(util.hash(self.md, label))
    if case("first byte of l_hash modified"):
      l_hash[0] ^= 1
    if case("last byte of l_hash modified"):
      l_hash[-1] ^= 1
    if case("l_hash changed to all 0"):
      l_hash = bytearray(self.h_len)
    if case("l_hash changed to all 1"):
      l_hash = bytearray([0xff]*self.h_len)
    l_hash = bytes(l_hash)
    ps = bytearray(self.k - len(msg) - 2 * self.h_len - 2)
    if len(ps) > 0:
      if case("first byte of ps modified"):
        ps[0] ^= 0x80
      if case("last byte of ps modified"):
        ps[0] ^= 0x80
      if case("first byte of ps is 1"):
        ps[0] ^= 0x01
      if case("all bits in ps flipped"):
        ps = bytearray([0xff]) * len(ps)
    ps = bytes(ps)
    delimiter = 0x01
    if case("ps terminated by 0xff"):
      delimiter = 0xff
    db = l_hash + ps + bytes([delimiter]) + msg
    db_len = self.k - self.h_len - 1
    if case("ps is all zero"):
      db = l_hash + bytes(db_len - self.h_len)
    if case("ps replaced by 0xff's"):
      db = l_hash + bytes([0xff] * (db_len - self.h_len))
    seed = prand.randbytes(self.h_len, seed=self.seed, label=msg)
    if case("seed is all 0"):
      seed = bytes(self.h_len)
    if case("seed is all 1"):
      seed = bytes([0xff] * self.h_len)
    db_mask = self.mgf(self.mgf_md, seed, db_len)
    masked_db = xor(db, db_mask)
    seed_mask = self.mgf(self.mgf_md, masked_db, self.h_len)
    masked_seed = xor(seed, seed_mask)
    first_byte = 0
    if case("First byte is 1"):
      first_byte = 1
    em = bytes([first_byte]) + masked_seed + masked_db
    m = conversions.os2ip(em)
    ct_size = self.k
    if case("m is 0"):
      m = 0
    if case("m is 1"):
      m = 1
    if case("m is n-1"):
      m = self.key.n-1
    if case("m is n"):
      m = self.key.n
    c = pow(m, self.key.e, self.key.n)
    if (c + self.key.n).bit_length() <= 8 * self.k:
      if case("added n to c"):
        c = c + self.key.n
    if case("ciphertext not reduced"):
      t = -c * pow(self.key.n, -1, 256) % 256
      c = c + t*self.key.n
      ct_size += 1
    res = conversions.i2osp(c, ct_size)
    if case("ciphertext is empty"):
      res = bytes()
    if case("prepended bytes to ciphertext"):
      res = bytes(2) + res
    if case("appended bytes to ciphertext"):
      res = res + bytes(2)
    if case("truncated ciphertext"):
      res = res[1:]
    return res
