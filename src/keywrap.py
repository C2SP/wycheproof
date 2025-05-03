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

import aes
import camellia
import seed
import aria
import modify
import prand
import util
import typing
import enum

# References:
# RFC 3394
# RFC 5649
# NIST SP 800-38F
# https://nvlpubs.nist.gov/nistpubs/specialpublications/nist.sp.800-38f.pdf
#
# NIST uses
# - W for the strong pseudorandom permuation
# - KW the construction also in RFC 3394
# - KWP the construction also in RFC 5649
# - TW, TKW the same constructions using TDES.
# Some properties we might check:
#   Wrapping key should be at least as strong as the key it protects (A.2)
#
# Potential test vectors:
# RFC3394:
#    Check that padding is checked during unwrap [done]
#    Can't wrap or unwrap empty string. [done]
#    Unwrapping just the IV is valid if not checked. [done]
#    Wrap and unwrap odd lengths. [done]
#    Unwrap short ct [done]
#    The number of rounds overflows 256 if the length
#    of the input is longer than 336 bytes. Not sure if this is defined. If
#    allowed then this should always be the same. [done]
#    include RFC5649 encrypted stuff [done]
#    Check whether 8 byte keys are allowed?
#       The function W requries n >= 3 (i.e. 8 bytes IV and 16 byte key data)
#
# RFC5649:
#    Timing attacks and oracles for the padding would not useful if the
#    raw wrapping and unwrapping were a strong pseudorandom permutation.
#    Unfortunately, because of the special treatment of pt <= 8 bytes this
#    is not the case. So we have to check.
#    Other stuff:
#    - check empty strings
#    - test vectors for different lengths: < 8, multiple of 8, multiple of 16
#    - input longer than 336 bytes [done]
#    - first 4 bytes of IV wrong [done]
#    - length wrong (padding ok):
#      -- length > 2**31 [done],
#      -- length > len(R) [done],
#      -- length = len(R)-8 [done],
#      -- length = 0
#    - padding too long [done]
#    - padding not 0 [done]:
#    - encrypted string contains 0's at the end
#    - RFC3394 encrypted stuff [done]
# RFC 3657 generalizes RFC 3394 to Camellia.
#    - no test vectors are given
#    - IV is the same.
#    - no generalization to KWP
# RFC 4010 generalizes RFC 3394 to SEED.
# RFC 5794 generalizes KW and KWP to ARIA.
#    - OIDs:
#       id-aria128-kw
#       id-aria128-kwp etc.
#
# There may be generalizations to SM4:
# Test vectors may be here GB/T 36624-2018 Appendix C.2
#
# Algorithm names:
# AESWrapAes: IAIK
# TODO:
#   - select names for the keywrap algorithms
#   - generalize kwp
class Mode(enum.Enum):
  """Defines the behaviour of KeyWrap for

     small sizes up to 64 bits
  """
  NIST = 1  # Nist SP 800 38f does not define small sizes
  RFC = 2  # RFC 3394 says to use the padding then encrypt with AES once.
  UNCHECKED = 3 # Uses W incorrectly.

class KeyWrap:
  default_iv = bytes([0xa6])*8
  block_cipher = None

  def __init__(self, key: bytes):
    if self.block_cipher is None:
      raise ValueError("Block cipher is not specified. Call subclass")
    self.block = self.block_cipher(key)

  def round(self, a:bytes, r:bytes, t:int):
    c = self.block.encrypt_block(a + r)
    k = 7
    c = bytearray(c)
    while t and k >= 0:
      c[k] ^= t  & 0xff
      t >>= 8
      k -= 1
    return bytes(c[:8]), bytes(c[8:])

  def inv_round(self, a:bytes, r:bytes, t:int):
    c = bytearray(a + r)
    k = 7
    while t and k >= 0:
      c[k] ^= t  & 0xff
      t >>= 8
      k -= 1
    p = self.block.decrypt_block(c)
    return p[:8], p[8:]

  @util.type_check
  def wrap(self,
           pt: bytes,
           iv: typing.Optional[bytes] = None,
           mode: Mode = Mode.RFC)-> bytes:
    assert len(pt) % 8 == 0
    if iv is None:
      iv = self.default_iv
    if len(pt) == 0:
      if mode == Mode.UNCHECKED:
        pass
      else:
        raise ValueError("empty pt")
    if len(pt) == 8:
      if mode == Mode.UNCHECKED:
        pass
      elif mode == Mode.RFC:
        return self.block.encrypt_block(iv + pt)
      else:
        raise ValueError("undefined")
    n = len(pt) // 8
    A = iv
    R = [pt[8*i: 8*(i+1)] for i in range(n)]
    for i in range(6):
      for t in range(n):
        A, R[t] = self.round(A, R[t], i*n+t+1)
    return A + b"".join(R)

  @util.type_check
  def unwrap_raw(self,
                 ct:bytes,
                 mode: Mode = Mode.RFC)->typing.Tuple[bytes, bytes]:
    assert isinstance(ct, bytes)
    if len(ct) % 8 != 0:
      raise ValueError("Expecting a multiple of 8 bytes")
    elif len(ct) < 16:
      if mode != Mode.UNCHECKED:
        raise ValueError("Ciphertext too short to unwrap")
    elif len(ct) == 16:
      if mode == Mode.NIST:
        raise ValueError("Cannot unwrap ciphertext")
      elif mode == Mode.RFC:
        pt = self.block.decrypt(ct)
        return pt[:8], pt[8:]
      else:
        pass
    n = len(ct) // 8 - 1
    A = ct[:8]
    R = [ct[8*i:8*(i+1)] for i in range(1, n+1)]
    for i in range(5, -1, -1):
      for t in range(n - 1, -1, -1):
        A, R[t] = self.inv_round(A, R[t], i*n+t+1)
    return A, b"".join(R)

  @util.type_check
  def unwrap(self,
             ct:bytes,
             iv:typing.Optional[bytes] = None,
             mode: Mode = Mode.RFC)-> bytes:
    tag, R = self.unwrap_raw(ct, mode)
    if iv is None:
      iv = self.default_iv
    if iv != tag:
      raise ValueError("Invalid IV")
    return R

class AesWrap(KeyWrap):
  name = "AES-WRAP"
  block_cipher = aes.AES
  # OIDs for key size in bits
  oids = {
    128: "2.16.840.1.101.3.4.1.5",
    192: "2.16.840.1.101.3.4.1.25",
    256: "2.16.840.1.101.3.4.1.45"}
  # TODO:
  #   SEC 1 v.2 uses
  #   "1.3.132.1.25.1" for aes192-key-wrap and
  #   "1.3.132.1.25.2" for aes256-key-wrap.
  #   Is there a difference?

class CamelliaWrap(KeyWrap):
  """Defined in RFC 3657"""
  name = "CAMELLIA-WRAP"
  block_cipher = camellia.Camellia
  oids = {
    128: "1.2.392.200011.61.1.1.3.2",
    192: "1.2.392.200011.61.1.1.3.3",
    256: "1.2.392.200011.61.1.1.3.4"}

class SeedWrap(KeyWrap):
  """Defined in RFC 4010"""
  name = "SEED-WRAP"
  block_cipher = seed.Seed

class AriaWrap(KeyWrap):
  """Defined in RFC 5794"""
  name = "ARIA-WRAP"
  block_cipher = aria.Aria


class Kwp:
  # The underlying keywrap algorithm without padding
  keywrap = None
  def __init__(self, key: bytes):
    if self.keywrap is None:
      raise ValueError("keywrap is undefined. Use a subclass")
    self.kw = self.keywrap(key)

  @util.type_check
  def wrap(self, pt:bytes)->bytes:
    iv = bytes.fromhex("A65959A6") + len(pt).to_bytes(4, "big")
    padlen = -len(pt) % 8
    inp = pt + bytes(padlen)
    if len(inp) == 8:
      return self.kw.block.encrypt_block(iv + inp)
    else:
      return self.kw.wrap(inp, iv=iv, mode=Mode.RFC)

  def modified_wrap(self, pt, case):
    if case("empty wrapping"):
      return bytes()
    pt_len = len(pt)
    padlen = -len(pt) % 8
    if case("length = 0"):
      pt_len = 0
    if case("length is longer than padded message"):
      pt_len = len(pt) + padlen + 1
    if case("length is one block longer than padded message"):
      pt_len = len(pt) + padlen + 8
    if case("length = 2**31-1"):
      pt_len = 2**32 - 1
    if case("length = 2**32-1"):
      pt_len = 2**32 - 1
    if case("length = 2**31 + %d" % len(pt)):
      pt_len = 2**31 + len(pt)
    prefix = bytes.fromhex("A65959A6")
    if case("first byte of prefix modified"):
      prefix = bytes.fromhex("a75959a6")
    if case("last byte of prefix modified"):
      prefix = bytes.fromhex("a65959b6")
    if case("incorrect prefix in iv"):
      prefix = bytes.fromhex("a6a6a6a6")
    if case("prefix in iv is all 0"):
      prefix = bytes.fromhex("00000000")
    if case("prefix in iv is all 1"):
      prefix = bytes.fromhex("ffffffff")
    iv = prefix + pt_len.to_bytes(4, "big")
    if case("RFC 3349 padding"):
      iv = bytes.fromhex("a6a6a6a6a6a6a6a6")
    if case("padding is 8 bytes too long"):
      padlen += 8
    if case("padding is 16 bytes too long"):
      padlen += 16
    padding = bytes(padlen)
    if padlen > 0:
      if case("padding is all 1"):
        padding = bytearray([255] * padlen)
      if case("first byte of padding modified"):
        padding[0] = 1
      if case("last byte of padding modified"):
        padding[-1] = 0x80
    inp = pt + padding
    if len(inp) == 8:
      if case("invalid encryption"):
        return self.kw.wrap(inp, iv=iv, mode=Mode.UNCHECKED)
      return self.kw.block.encrypt_block(iv + inp)
    else:
      return self.kw.wrap(inp, iv=iv, mode=Mode.RFC)

  @util.type_check
  def unwrap(self, ct:bytes) -> bytes:
    if len(ct) == 16:
      p = self.kw.block.decrypt_block(ct)
      iv, R = p[:8], p[8:]
    else:
      iv, R = self.kw.unwrap_raw(ct, mode=Mode.RFC)
    mli = iv[:4]
    assert mli == bytes.fromhex("A65959A6")
    n = 0
    for x in iv[4:]:
      n = 256*n + x
    assert n <= len(R) < n + 8
    for x in R[n:]:
      assert x == 0
    return R[:n]

class AesKwp(Kwp):
  """Defined in RFC 5649"""
  name = "AES-KWP"
  keywrap = AesWrap
  # OIDs for key size in bytes
  oids = {
    128: "2.16.840.1.101.3.4.1.8",
    192: "2.16.840.1.101.3.4.1.28",
    256: "2.16.840.1.101.3.4.1.28"}

class AriaKwp(Kwp):
  """Define in RFC 5794"""
  name = "ARIA-KWP"
  keywrap = AriaWrap

# Deprecated
keywrap_rfc5649 = AesKwp

class HmacWithAesWrap:
  """Defined in RFC 3537"""
  keywrap = AesWrap

  def __init__(self, key:bytes, seed: bytes=b"l1k2xoi3"):
    self.kw = self.keywrap(key)
    self.seed = seed

  def wrap(self, hmackey: bytes) -> bytes:
    if len(hmackey) >= 256:
      raise ValueError("hmackey too long")
    lkey = bytes(len(hmackey))
    padlen = -len(lkey) % 8
    pad = prand.randbytes(padlen, lkey, seed)
    # TODO: What happens when lkey + padlen has length 8?
    return self.kw.wrap(lkey + padlen)

  def modified_wrap(self, hmackey: bytes, case):
    if len(hmackey) >= 256:
      raise ValueError("hmackey too long")
    if case("empty wrapping"):
      return bytes()
    if case("wrapping of size 8"):
      return self.keywrap.default_iv
    if case("wrapping of size 16"):
      return self.keywrap.default_iv + bytes([7])*8
    if case("hmackey has size 255"):
      hmackey = bytes(range(255))
    key_length = len(hmackey)
    if key_length < 240:
      if case("key length larger than wrapping"):
        key_length += 16
    lkey = bytes([key_length]) + hmackey
    padlen = -len(lkey) % 8
    if case("padding too long"):
      padlen += 8
    pad = prand.randbytes(padlen, lkey, seed)
    # TODO: Modified keywraps must be analyzed
    return self.kw.wrap(lkey + padlen)

  def unwrap(self, wrapped: bytes) -> bytes:
    padded = self.kw.unwrap(wrapped)
    key_length = padded[0]
    pad_length = len(padded) - key_length - 1
    if pad_length < 0 or pad_length >= 8:
      raise ValueError("Invalid padding")
    return padded[1 : 1 + key_length]

# Format: [key, bytes to wrap, wrapped result]
test_vectors_rfc3394 = [
  ["000102030405060708090A0B0C0D0E0F",
   "00112233445566778899AABBCCDDEEFF",
   "1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5"],
  ["000102030405060708090A0B0C0D0E0F1011121314151617",
   "00112233445566778899AABBCCDDEEFF",
   "96778B25AE6CA435F92B5B97C050AED2468AB8A17AD84E5D"],
  ["000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
   "00112233445566778899AABBCCDDEEFF",
   "64E8C3F9CE0F5BA263E9777905818A2A93C8191E7D6E8AE7"],
  ["000102030405060708090A0B0C0D0E0F1011121314151617",
   "00112233445566778899AABBCCDDEEFF0001020304050607",
   "031D33264E15D33268F24EC260743EDCE1C6C7DDEE725A936BA814915C6762D2"],
  ["000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
   "00112233445566778899AABBCCDDEEFF0001020304050607",
   "A8F9BC1612C68B3FF6E6F4FBE30E71E4769C8B80A32CB8958CD5D17D6B254DA1"],
  ["000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
   "00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F",
   "28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43B"
   "FB988B9B7A02DD21"],
]

test_vectors_rfc5649 = [
  ["5840df6e29b02af1ab493b705bf16ea1ae8338f4dcc176a8",
   "c37b7e6492584340bed12207808941155068f738",
   "138bdeaa9b8fa7fc61f97742e72248ee5ae6ae5360d1ae6a5f54f373fa543b6a"],
  ["5840df6e29b02af1ab493b705bf16ea1ae8338f4dcc176a8",
   "466f7250617369",
   "afbeb0f07dfbf5419200f2ccb50bb24f"]
]

test_vectors_rfc3537 = [
  ["5840df6e 29b02af1 ab493b70 5bf16ea1 ae8338f4 dcc176a8",
   "c37b7e64 92584340 bed12207 80894115 5068f738",
   "9fa0c146 5291ea6d b55360c6 cb95123c d47b38cc e84dd804 fbcec5e3 75c3cb13"],
]

def testAesWrap():
  for k,d,res in test_vectors_rfc3394:
    w = AesWrap(bytes.fromhex(k))
    wrapped = w.wrap(bytes.fromhex(d))
    assert bytes.fromhex(res) == wrapped
    unwrapped = w.unwrap(wrapped)
    assert bytes.fromhex(d) == unwrapped

def testAesKwp():
  for k,d,res in test_vectors_rfc5649:
    w = AesKwp(bytes.fromhex(k))
    wrapped = w.wrap(bytes.fromhex(d))
    assert bytes.fromhex(res) == wrapped
    unwrapped = w.unwrap(wrapped)
    assert bytes.fromhex(d) == unwrapped

def testHmacWithAesWrap():
  for k,d,res in test_vectors_rfc3537:
    w = HmacWithAesWrap(bytes.fromhex(k))
    unwrapped = w.unwrap(bytes.fromhex(res))
    assert bytes.fromhex(d) == unwrapped

if __name__ == "__main__":
  testAesWrap()
  testAesKwp()
  testHmacWithAesWrap()
