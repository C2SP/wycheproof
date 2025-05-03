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

import chacha
import chacha_poly1305
import gen_chacha_common
import poly1305
import producer
import aead_test_vector
import test_vector
from typing import Optional
import util
import flag

# Reference: https://tools.ietf.org/html/rfc7539

# CVEs:
# CVE-2020-12403   out of bounds when using streaming.
# CVE-2019-1543  allowing 16 byte nonces

class ChachaTestGenerator(gen_chacha_common.ChachaCommonTestGenerator):
  def __init__(self, args):
    super().__init__("CHACHA20-POLY1305", args)

  aead = chacha_poly1305.Chacha20Poly1305
  key_size_in_bytes = 32
  iv_size_in_bytes = 12

  @util.type_check
  def crypt_raw(self, key: bytes, nonce: bytes, data: bytes) -> bytes:
    """Encrypts or decrypts some data."""
    return chacha.chacha20_encrypt(key, 1, nonce, data)

  @util.type_check
  def encrypt(self, key: bytes, iv: bytes, aad: bytes,
              msg: bytes) -> tuple[bytes, bytes]:
    """Convenience method for encrypting with Chach20Poly1305"""
    return chacha_poly1305.Chacha20Poly1305(key).encrypt(iv, aad, msg)

  @util.type_check
  def find_aad(self, key: bytes, nonce: bytes, ct: bytes, tag: bytes) -> bytes:
    """Finds additional data, such that decrypting decrypting

     a given ciphertext and tag with a given key is valid.
     This can be used to generate test vectors with edge case
     values for ciphertext and tag.
    """
    dummy_aad = bytes([255]) * 32
    poly_key = chacha.chacha20_block(key, nonce, 0)[:32]
    poly_inp = dummy_aad
    poly_inp += ct + bytes(-len(ct) % 16)
    poly_inp += poly1305.int_to_bytes(len(dummy_aad), 8)
    poly_inp += poly1305.int_to_bytes(len(ct), 8)
    m = poly1305.modify_blocks(poly_key, poly_inp, 0, 1,
                               poly1305.le_bytes_to_int(tag))
    return m[:32]


  def generate_known_tests(self):
    """Adds test vectors from the chacha20 draft."""
    flag_ktv = flag.Flag(
        label="Ktv",
        bug_type=flag.BugType.BASIC,
        description="Known test vector.",
        links=["RFC 7539"])

    self.gen_test(
        key=bytes(range(128, 160)),
        nonce=bytes.fromhex("070000004041424344454647"),
        pt=b"Ladies and Gentlemen of the clas"
        b"s of '99: If I could offer you o"
        b"nly one tip for the future, suns"
        b"creen would be it.",
        aad=bytes.fromhex("50515253c0c1c2c3c4c5c6c7"),
        comment="RFC 7539",
        flags=[flag_ktv])

  def generate_edge_case_poly1305_keys(self):
    """Generates test vectors where the 32-bit limbs of r are edgecases
       (i.e., minimal or maximal). The nonces below are precomputed
       using chacha_search.py, since finding such nonces takes some time."""

    edge_case_poly_key = flag.Flag(
        label="EdgeCasePolyKey",
        bug_type=flag.BugType.EDGE_CASE,
        description="The test vector contains values where the key for "
        "Poly1305 has edge case values. E.g. the nonces have been constructed "
        "such that the Poly1305 key contains limbs with values such as 0. "
        "The goal of the test vector is to detect incorrect integer arithmetic "
        "in the Poly1305 computation.")
    # New test cases that include 0 limbs.
    key = bytes(range(32))
    cipher = self.aead(key)
    prefix = bytes(range(8))
    for n in [
        "10abb165", "051e9373", "048c3c5f", "03e76f6f", "2dd4cd40", "26c6961b",
        "013da060", "07db33de", "02a11942", "3c0df637"
    ]:
      nonce = prefix + bytes.fromhex(n)
      self.gen_test(
          key=key,
          nonce=nonce,
          aad=bytes([255]) * 64,
          ct=bytes([255]) * 128,
          comment="edge case for poly1305 key:" + cipher.poly_key(nonce).hex(),
          flags=[edge_case_poly_key])
    # Derived from the Xchacha test cases.
    # TODO: Needs more time
    key = bytes.fromhex(
        "9de836aa579585081f330a7c4036e20e38ef15eff3945184d231867f505fffdf")
    prefix = bytes.fromhex("0000000010111213")
    cipher = self.aead(key)
    for n in [
        "0bc672c3", "03e9b9a4", "0700b982", "019836bb", "1d59f288", "0552a411",
        "0c807a72", "0397a143", "08cb0f3f", "0d8fcf4e"
    ]:
      nonce = prefix + bytes.fromhex(n)
      self.gen_test(
          key=key,
          nonce=nonce,
          aad=bytes([255]) * 64,
          ct=bytes([255]) * 127,
          comment="edge case for poly1305 key:" + cipher.poly_key(nonce).hex(),
          flags=[edge_case_poly_key])

  def generate_intermediate_edge_cases(self):
    """Generates test vectors, where the indermediate values in the 
       computation of poly1305 are edge cases."""
    edge_case_poly1305 = flag.Flag(
        label="EdgeCasePoly1305",
        bug_type=flag.BugType.EDGE_CASE,
        description="The test vector contains an edge case for the "
        "integer arithmetic used to compute Poly1305. I.e., the goal "
        "of the test vector is to catch integer overflows.")
    key = bytes(range(32))
    aad = bytes.fromhex("ffffffff")
    for nonce_hex in [
        "000102030405060710abb165",
        "00010203040506072dd4cd40",
        "000102030405060703e76f6f",
    ]:
      nonce = bytes.fromhex(nonce_hex)
      poly_key = chacha.chacha20_block(key, nonce, 0)[:32]
      r,s = poly1305.get_rs(poly_key)
      poly_inp = aad + bytes(-len(aad)%16)
      start_ct = len(poly_inp)
      for val in [0, 1, 5, 10, 19, 20,
                  2**32 - 1, 2**32,
                  2**51 - 1, 2**52 - 1,
                  2**64 - 1,
                  2**64,
                  2**96 - 2**32,
                  2**96 - 2**64 + 2**32,
                  2**102 - 2**51,
                  2**104 - 2**52,
                  r,
                  poly1305.p - r,
                  2**128 - 2**64,
                  2**128 - 2**96 + 2**64 - 2**32,
                  2**128 - 1,
                  2**128,
                  2**128 + 1,
                  poly1305.p - 5,
                  poly1305.p - 1,
                  poly1305.p // 19,
                  poly1305.p // 19 + 1,
                  -2**128 % poly1305.p]:
        poly_inp = bytes([127])*16
        for i in range(3):
          poly_inp = poly1305.append_blocks(poly_key, poly_inp, val)
        ct = poly_inp[start_ct:]
        self.gen_test(
            key,
            nonce,
            aad,
            ct=ct,
            comment=f"Intermediate sum of poly1305 after processing"
            f"{len(poly_inp)} bytes is {hex(val)}.",
            flags=[edge_case_poly1305])


  def generate_all(self):
    """Generate the test vectors."""
    self.generate_known_tests()
    self.generate_pseudorandom_vectors()
    self.generate_invalid_nonces()
    self.generate_modified_tag()
    self.generate_special_case_ct()
    self.generate_edge_case_poly1305_keys()
    self.generate_edge_case_tags()
    self.generate_intermediate_edge_cases()
    # Possible additional tests:
    # - invalid key size


class ChachaPoly1305Producer(producer.Producer):

  def parser(self):
    return self.default_parser()

  def generate_test_vectors(self, namespace):
    tv = ChachaTestGenerator(namespace)
    tv.generate_all()
    return tv.test


# DEPRECATED: Use Producer.produce() instead
def main(namespace):
  ChachaPoly1305Producer().produce(namespace)


if __name__ == "__main__":
  ChachaPoly1305Producer().produce_with_args()
