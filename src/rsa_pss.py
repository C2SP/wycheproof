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
import rsa_key
import pem_util
from typing import Optional, Union
import util
import prand
import conversions


def xor(a: bytes, b: bytes) -> bytes:
  assert len(a) == len(b)
  return bytes(x ^ y for x, y in zip(a, b))


def mgf1(md: str, seed: bytes, size: int) -> bytes:
  ctr = 0
  res = bytes()
  while len(res) < size:
    res += util.hash(md, seed + conversions.i2osp(ctr, 4))
    ctr += 1
  return res[:size]


class RsassaPss:
  """Implements RSASSA-PSS.

  The implementation is based on RFC 8017.
  So far it is unclear if SHA-3 can also be used for
  RSASSA-PSS.

  SHAKE:
  RFC 8692 extends RSASSA-PSS to SHAKE128 and SHAKE256.
  Section 4.1.1 defines the use of these two functions:
  - the hash and mgf must use the same function
  - SHAKE128 uses a 32 byte output when used as hash
  - SHAKE256 uses a 64 byte output when used as hash
  - when used as mgf the output is emLen - hLen - 1
  """

  @util.type_check
  def __init__(self,
               key,
               md: Optional[str],
               mgf: str,
               mgf_md: Optional[str],
               s_len: Optional[int],
               specify_params: bool = False,
               seed: bytes = b"kl3nz5h2dy1",
               allow_variable_length_salt: bool = False):
    """Constructs an RSASSA-PSS signer or verifier.

    Args:
      key: an RSA public or private key
      md: the hash function for hashing the message. should be None if SHAKE is
        used for the mgf.
      mgf: the message generation function. Currently MGF1, SHAKE128 and
        SHAKE256 are supported
      mgf_md: the hash function used for the mgf. Should be None if SHAKE is
        used.
      s_len: the seed length
      specify_params: True if the ASN encoding of the keys should include the
        PSS parameters. False is typical for common crypto libraries.
      allow_variable_length_salt: True if signatures with a salt other than
        s_len should be accepted.
    """
    key.fill_crt()
    self.key = key
    self.md = md
    self.mgf_name = mgf.upper()
    self.mgf_md = mgf_md
    self.seed = seed  # This implementation uses deterministic signatures
    self.specify_params = specify_params
    self.mod_bits = key.n.bit_length()
    self.em_bits = self.mod_bits - 1  # section 8.1.1
    self.em_len = (self.em_bits + 7) // 8
    self.allow_variable_length_salt = allow_variable_length_salt
    if self.mgf_name == "MGF1":
      self.s_len = s_len
    elif self.mgf_name in ("SHAKE128", "SHAKE256"):
      self.md = self.mgf_name
      self.mgf_md = self.mgf_name
      if self.mgf_name == "SHAKE128":
        if s_len not in (None, 32):
          raise ValueError("Invalid s_len")
        self.s_len = 32
      elif self.mgf_name == "SHAKE256":
        if s_len not in (None, 64):
          raise ValueError("invalid s_len")
        self.s_len = 64
    else:
      raise ValueError("Unknown mgf:" + mgf)
    # Some parameter validations:
    if self.s_len is None or self.s_len < 0:
      raise ValueError("Invalid s_len")
    if s_len is not None and self.s_len != s_len:
      raise ValueError("Invalid s_len specified")

  def hash_message(self, message: bytes) -> bytes:
    if self.md == "SHAKE128":
      return util.shake(self.md, message, 32)
    elif self.md == "SHAKE256":
      return util.shake(self.md, message, 64)
    else:
      return util.hash(self.md, message)

  def mgf(self, input: bytes, size: int) -> bytes:
    if self.mgf_name == "MGF1":
      return mgf1(self.mgf_md, input, size)
    elif self.mgf_name in ("SHAKE128", "SHAKE256"):
      return util.shake(self.mgf_name, input, size)
    else:
      raise ValueError("Unsupported MGF")

  # RFC 8017 Section A.2
  # PKCS1Algorithms =
  #    ...
  #    { OID id-RSASSA-PSS   PARAMETERS RSASSA-PSS-params }
  # Section A.2.3.  RSASSA-PSS
  # id-RSASSA-PSS    OBJECT IDENTIFIER ::= { pkcs-1 10 }
  #
  #  RSASSA-PSS-params ::= SEQUENCE {
  #     hashAlgorithm      [0] HashAlgorithm      DEFAULT sha1,
  #     maskGenAlgorithm   [1] MaskGenAlgorithm   DEFAULT mgf1SHA1,
  #     saltLength         [2] INTEGER            DEFAULT 20,
  #     trailerField       [3] TrailerField       DEFAULT trailerFieldBC
  # }
  def asn_pss_param_struct(self) -> asn.AsnStructure:
    if self.mgf_name == "MGF1":
      md_oid = asn.oid_from_hash(self.md)
      mgf_md_oid = asn.oid_from_hash(self.mgf_md)
      # TODO: What is the correct OID for mgf1
      mgf1_oid = asn.Oid("2a864886f70d010108")
      trailerField = 1  # trailer bc
      return [asn.Explicit(0, [md_oid, asn.Null()]),
              asn.Explicit(1, [mgf1_oid, [mgf_md_oid, asn.Null()]]),
              asn.Explicit(2, self.s_len),
              asn.Explicit(3, trailerField)]
    elif self.mgf_name in ("SHAKE128", "SHAKE256"):
      raise ValueError("Not implemented")
    else:
      raise ValueError("Unknown MGF")

  def pkcs1algorithm(self) -> asn.AsnStructure:
    if self.mgf_name == "MGF1":
      id_rsassa_pss = asn.Oid([1, 2, 840, 113549, 1, 1, 10])
      return [id_rsassa_pss, self.asn_pss_param_struct()]
    elif self.mgf_name == "SHAKE128":
      id_rsassa_pss_shake128 = asn.Oid([1, 3, 6, 1, 5, 5, 7, 6, 30])
      return id_rsassa_pss_shake128
    elif self.mgf_name == "SHAKE256":
      id_rsassa_pss_shake256 = asn.Oid([1, 3, 6, 1, 5, 5, 7, 6, 31])
      return id_rsassa_pss_shake256
    else:
      raise ValueError("unsupported mgf:" + self.mgf_name)

  def public_key(self):
    return self.key.publicKey()

  def public_key_asn(self) -> asn.AsnStructure:
    if self.specify_params:
      params = self.pkcs1algorithm()
    else:
      params = None
    return self.public_key().publicKeyAsn(params)

  def public_key_pem(self) -> str:
    der = asn.encode(self.public_key_asn())
    return pem_util.public_key_pem(der)

  def emsa_pss_encode(self, message: bytes) -> bytes:
    m_hash = self.hash_message(message)
    h_len = len(m_hash)
    if self.em_bits < 8 * h_len + 8 * self.s_len + 9:
      # Should be equivalent to em_len < h_len + s_len + 2:
      raise ValueError("encoding error")
    salt = prand.randbytes(self.s_len, seed=self.seed, label=message)
    m = bytes(8) + m_hash + salt
    h = self.hash_message(m)
    ps = bytes(self.em_len - self.s_len - h_len - 2)
    db = ps + bytes([1]) + salt
    db_mask = self.mgf(h, self.em_len - h_len - 1)
    masked_db = xor(db, db_mask)
    clear_bits = 8 * self.em_len - self.em_bits
    assert 0 <= clear_bits < 8
    first_byte = masked_db[0] % (2 ** (8 - clear_bits))
    em = bytes([first_byte]) + masked_db[1:] + h + bytes([0xbc])
    # sanity check
    assert len(em) == self.em_len
    return em

  def emsa_pss_verify(self, msg: bytes, em: bytes) -> bool:
    """Returns True if em is consistent with msg.

       Returns False if em is inconsistent with msg.
    """
    m_hash = self.hash_message(msg)
    h_len = len(m_hash)
    # This is property of the key. Why does the RFC not throw an error here.
    if self.em_len < h_len + self.s_len + 2:
      return False
    if em[-1] != 0xbc:
      return False
    mask_len = self.em_len - h_len - 1
    masked_db = em[:mask_len]
    h = em[mask_len:mask_len + h_len]
    clear_bits = 8 * self.em_len - self.em_bits
    assert 0 <= clear_bits < 8
    if masked_db[0] >> (8 - clear_bits):
      return False
    db_mask = self.mgf(h, mask_len)

    db = xor(masked_db, db_mask)
    db = bytearray(db)
    db[0] &= 2 ** (8 - clear_bits) - 1
    db = bytes(db)
    if self.allow_variable_length_salt:
      for i, b in enumerate(db):
        if b != 0:
          ps_len = i
          break
      else:
        # No delimiter found
        return False
    else:
      # ps_len
      #   = self.em_len - h_len - self.s_len - 2
      #   = mask_len - self.s_len - 1
      #   = len(db) - self.s_len - 1
      ps_len = self.em_len - self.s_len - h_len - 2
    ps = db[:ps_len]
    delimiter = db[ps_len]
    salt = db[ps_len + 1:]
    if ps != bytes(ps_len):
      return False
    if delimiter != 1:
      return False
    m2 = bytes(8) + m_hash + salt
    h2 = self.hash_message(m2)
    return h == h2

  @util.type_check
  def sign(self, msg: bytes) -> bytes:
    em = self.emsa_pss_encode(msg)
    m = conversions.os2ip(em)
    sig = pow(m, self.key.d, self.key.n)
    return conversions.i2osp(sig, (self.mod_bits + 7) // 8)

  @util.type_check
  def verify(self, msg: bytes, sig: bytes) -> bool:
    """Verifies a signature.

       Returns true if the signature is valid, false if the signatue is
       invalid. Throws an error if the key or parameters are invalid.
    """
    if len(sig) != (self.mod_bits + 7) // 8:
      return False
    s = conversions.os2ip(sig)
    if not 0 <= s < self.key.n:
      return False
    m = pow(s, self.key.e, self.key.n)
    try:
      em = conversions.i2osp(m, self.em_len)
    except ValueError:
      return False
    return self.emsa_pss_verify(msg, em)

  # ===== Generation of modified signatures =====
  def modified_emsa_pss_encode(self, message: bytes, case):
    m_hash = bytearray(self.hash_message(message))
    # Modifying m_hash: this is not very important, since
    # an implementation is unlikely to fail for such modification.
    if case("first byte of m_hash modified"):
      m_hash[0] ^= 1
    if case("first byte of m_hash modified"):
      m_hash[0] ^= 0x80
    if case("last byte of m_hash modified"):
      m_hash[-1] ^= 1
    if case("last byte of m_hash modified"):
      m_hash[-1] ^= 0x80
    if case("all bits in m_hash flipped"):
      for i in range(len(m_hash)):
        m_hash[i] ^= 0xff;
    m_hash = bytes(m_hash)
    h_len = len(m_hash)
    s_len = self.s_len
    max_s_len = self.em_len - h_len - 2
    for s in sorted({0, 1, 20, 32, s_len - 1, s_len + 1, max_s_len}):
      if self.s_len != s and 0 <= s <= max_s_len:
        if case("s_len changed to %d" % s):
          s_len = s
    if self.em_bits < 8 * h_len + 8 * s_len + 9:
      # Should be equivalent to em_len < h_len + s_len + 2:
      raise ValueError("encoding error")
    salt = prand.randbytes(s_len, seed=self.seed, label=message)
    if s_len > 0:
      if case("salt is all 0"):
        salt = bytes(s_len)
      if case("salt is all 1"):
        salt = bytes([0xff] * s_len)
    zero_pad = bytearray(8)
    # Modifications of padding1
    if case("byte 0 in zero padding modified"):
      zero_pad[0] = 1
    if case("byte 7 in zero padding modified"):
      zero_pad[7] = 0x80
    if case("all bytes in zero padding modified"):
      zero_pad = bytes([0x01] * 8)
    zero_pad = bytes(zero_pad)
    m = zero_pad + m_hash + salt
    h = bytearray(self.hash_message(bytes(m)))
    if case("first byte of hash h modified"):
      h[0] ^= 1
    if case("first byte of hash h modified"):
      h[0] ^= 0x80
    if case("last byte of hash h modified"):
      h[-1] ^= 1
    if case("last byte of hash h modified"):
      h[-1] ^= 0x80
    if case("all bytes of h replaced by 0"):
      h = bytearray(h_len)
    if case("all bits of h replaced by 1s"):
      h = bytearray([0xff] * h_len)
    if case("all bits in hash h flipped"):
      for i in range(len(h)):
        h[i] ^= 0xff;
    if case("hash of salt missing"):
      h = m_hash
      h_len = len(h)
    h = bytes(h)
    ps_len = self.em_len - s_len - h_len - 2
    ps = bytearray(ps_len)
    # Modifications of padding2
    # TODO: This is the most important case.
    #   Failing to check this padding might allow signature forgeries.
    #   Maybe there need to be more tests.
    if case("first byte of ps modified"):
      ps[0] = 1
    if case("last byte of ps modified"):
      ps[-1] = 1
    if case("all bytes of ps changed to 0xff"):
      ps = bytearray([0xff] * ps_len)
    if case("all bytes of ps changed to 0x80"):
      ps = bytearray([0x80] * ps_len)
    ps = bytes(ps)
    b = 1
    if case("ps followed by 0"):
      b = 0
    if case("ps followed by 0xff"):
      b = 0xff
    db = ps + bytes([b]) + salt
    if ps_len >= 8:
      # Someone might parse db to find the start of the salt.
      # In the worst case this could allow to include random bytes
      # and be exploitable.
      if case("shifted salt"):
        db = db[8:] + db[:8]
      if case("including garbage"):
        db = db[8:] + bytes(range(8))
    db_mask = self.mgf(bytes(h), self.em_len - h_len - 1)
    masked_db = bytearray(xor(db, db_mask))
    clear_bits = 8 * self.em_len - self.em_bits
    assert 0 <= clear_bits < 8
    mask = 2 ** (8 - clear_bits) - 1
    old = masked_db[0]
    masked_db[0] &= mask
    for bit in range(8 - clear_bits, 8):
      if old & (2 ** bit):
        if case("bit %d of masked_db not cleared" % bit):
          masked_db[0] |= 2 ** bit
    if masked_db[0] != 0:
      if case("first byte of masked_db changed to 0"):
        masked_db[0] = 0
    last_byte = 0xbc
    for b in [0, 0x3c, 0xff]:
      if case("last byte in em modified"):
        last_byte = b
    em = masked_db + h + bytes([last_byte])
    # sanity check
    assert len(em) == self.em_len
    return bytes(em)

  def modified_sign(self, msg: bytes, case) -> bytes:
    em = self.modified_emsa_pss_encode(msg, case)
    m = conversions.os2ip(em)
    sig = pow(m, self.key.d, self.key.n)
    if case("signature is 0"):
      sig = 0
    if case("signature is 1"):
      sig = 1
    if case("signature is n-1"):
      sig = self.key.n - 1
    if case("signature is n"):
      sig = self.key.n
    sig_size = (self.mod_bits + 7) // 8
    if case("signature is not reduced"):
      t = -sig * pow(self.key.n, -1, 256) % 256
      sig += t * self.key.n
      sig_size += 1
    res = conversions.i2osp(sig, sig_size)
    if case("prepending 0's to signature"):
      res = bytes(2) + res
    if case("appending 0's to signature"):
      res = res + bytes(2)
    if case("truncated signature"):
      res = res[:-2]
    if case("empty signature"):
      res = b""
    return bytes(res)
