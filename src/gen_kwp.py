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

import util
import flag
import keywrap
import keywrap_test_vector
import producer
import prand


from typing import Optional, List

ALGORITHMS = ["AES-KWP", "ARIA-KWP"]

FLAG_MODIFIED_PADDING = flag.Flag(
    label="ModifiedPadding",
    bug_type=flag.BugType.MISSING_STEP,
    description="The test vector contains a ciphertext that was obtained "
    "with a modified padding. Unwrapping should verify the padding and "
    "hence reject this test vector. ")


class KwpTestVectorGenerator(keywrap_test_vector.KeywrapTestVectorGenerator):
  """Genreates test vector for the algorithm KWP from NIST SP 800-38F

     https://nvlpubs.nist.gov/nistpubs/specialpublications/nist.sp.800-38f.pdf
     This algorithm is also defined in RFC 5649.

     ANS X9.102-2008,
     Symmetric Key Cryptography For the Financial Services Industry --
     Wrapping of Keys and Associated Data,
     defines an analogue of KWP, which according to NIST is not compatible
     with this implementation.
  """
  def __init__(self,
               algorithm: str,
               keysizes_in_bits: Optional[List[int]]):
    super().__init__(algorithm)
    if algorithm == "AES-KWP":
      self.kwp = keywrap.AesKwp
      self.kw = keywrap.AesWrap
      self.test_vectors = keywrap.test_vectors_rfc5649
      self.test_vector_ref = "RFC 5649"
    elif algorithm == "ARIA-KWP":
      self.kwp = keywrap.AriaKwp
      self.kw = keywrap.AriaWrap
      self.test_vectors = []
    else:
      raise ValueError("Unknown algorithm")

    if keysizes_in_bits:
      self.key_sizes = [s // 8 for s in keysizes_in_bits]
    else:
      self.key_sizes = self.kw.block_cipher.key_sizes_in_bytes

  def wrap(self, key, data):
    return self.kwp(key).wrap(data)

  def gen_small_data_size(self):
    """Generates test vectors where the wrapped key is smaller
       than 128-bits."""
    smallkey = flag.Flag(
        label="SmallKey",
        bug_type=flag.BugType.FUNCTIONALITY,
        description="This test vector wraps a key smaller than 128-bits. "
        "Rejecting such keys may be reasonable to detect weak keys. "
        "Rejecting the keys also simplifies the implementation. ")
    for key_size in self.key_sizes:
      key = prand.randbytes(key_size, b"jkgoyufkfggk")
      for i in range(1, 16):
        seed = b"dafafdawrw" + key + b"%d" % i
        data = prand.randbytes(i, seed)
        self.add_keywrap(key, data, None, "wrapping small key", "valid",
                         flags=[smallkey])

  def gen_invalid_wrapped_size(self):
    """Generates test vectors where the wrapping has an incorrect size."""
    wrong_wrapping_size = flag.Flag(
        label="WrongWrappingSize",
        bug_type=flag.BugType.MISSING_STEP,
        description="The size of the wrapped key should be at least 16 bytes "
        "and a multiple of 8. Unwrapping should check the sizes.")
    for key_size in self.key_sizes:
      key = prand.randbytes(key_size, b"k12j3kl12j31kl")
      for wrapped_size in (0, 1, 4, 8, 15, 17, 20):
        wrapped = prand.randbytes(data_size,
                                  b"k12j3kl12j31kl" + b"%d" % wrapped_size)
        self.add_keywrap(
            key,
            "",
            wrapped,
            "invalid size of wrapped key",
            flags=[wrong_wrapping_size])
      data = bytes(range(16))
      w = self.wrap(key, data)
      self.add_keywrap(key, data, w + bytes([0]),
                       "bytes appended to wrapped key", "invalid",
                       [wrong_wrapping_size])

  def gen_pseudorandom(self):
    """Generate pseudorandom test vectors for the typical cases."""
    for key_size in self.key_sizes:
      for data_size in self.key_sizes:
        self.generate_pseudorandom(
            3, [key_size], [data_size],
            f"key size={key_size} data size={data_size}",
            "valid",
            flags=[flag.NORMAL])

  def gen_long_wrapping(self):
    """Generates test vectors where the counter overflows 256"""
    overflow = flag.Flag(
        label="CounterOverflow",
        bug_type=flag.BugType.FUNCTIONALITY,
        description="The test vector contains a value that is long enough "
        "so that the round counter overflows at 256.")
    for key_size in self.key_sizes:
      key = prand.randbytes(key_size, b"aklsdjfa;kljewr")
      data = bytes([0] * 384)
      self.add_keywrap(
          key,
          data,
          None,
          "Round counter overflows 256",
          "valid",
          flags=[overflow])


#  def wrap(self, pt):
#    iv = bytes.fromhex("A65959A6") + len(pt).to_bytes(4, "big")
#    padlen = -len(pt) % 8
#    inp = pt + bytes(padlen)
#    if len(inp) == 8:
#      return self.kw.block.encrypt_block(iv + inp)
#    else:
#      return self.kw.wrap(inp, iv=iv)

  def gen_modified_padding(self):
    """Generates test vectors where bits in the plaintext padding
       are flipped."""
    for key_size in self.key_sizes:
      for data_size in (9, 15, 16, 24, 31):
        if key_size >= data_size:
          key = prand.randbytes(key_size, b"1;2k3h1jh3")
          data = prand.randbytes(data_size, b"k12h31jk4h")
          kw = self.kw(key)
          pad_length = -len(data)%8
          correct_pad = bytes(pad_length)
          iv = bytes.fromhex("A65959A6") + len(data).to_bytes(4, "big")
          for i in range(len(iv)):
            modified = bytearray(iv)
            modified[i] ^= 0x1
            wrapped = kw.wrap(data + correct_pad, iv=bytes(modified))
            self.add_keywrap(
                key,
                data,
                wrapped,
                "Modified IV",
                "invalid",
                flags=[FLAG_MODIFIED_PADDING])
          if pad_length:
            paddings = {
                bytes([1] + [0]*(pad_length - 1)),
                bytes([0]*(pad_length - 1) + [1]),
                bytes([0]*(pad_length - 1) + [pad_length]),
                bytes([0xff]*pad_length),
                bytes([0x80]*pad_length),
                bytes([pad_length] * pad_length)
            }
            for invalid_pad in sorted(paddings):
              wrapped = kw.wrap(data + invalid_pad, iv=iv)
              self.add_keywrap(
                  key,
                  data,
                  wrapped,
                  "Modified Padding",
                  "invalid",
                  flags=[FLAG_MODIFIED_PADDING])

  def gen_wrong_padding(self):
    """Generates test vectors where the plaintext padding is modified.

       The modifications attempt to detect missing steps in the unwrap
       function.
    """
    # TODO: might be replace by keywrap5469.modified_wrap()
    # List of (iv, padded data, comment) using W
    L1 = (
      ("a6a6a6a6a6a6a6a6", "000102030405060708090a0b0c0d0e0f",
       "RFC 3349 padding"),
      ("a65959a600000010", "00" * 24, "padding too long"),
      ("a65959a600000011", "00" * 32, "padding too long"),
      ("a65959a600000018", "00" * 16, "incorrectly encoded length"),
      ("a65959a6ffffffff", "00" * 16, "length = 2**32-1"),
      ("a65959a67fffffff", "00" * 16, "length = 2**31-1"),
      ("a65959a680000010", "00" * 16, "length = 2**31 + 16"),
      ("a65959a680000017", "ff" * 24, "data is incorrectly padded"),
      ("a65959a600000000", "00" * 16, "length = 0"),
    )
    L2 = (
      ("a6a6a6a6a6a6a6a6", "0001020304050607",
       "RFC 3349 padding with incorrect size"),
      ("a65959a600000007", "0001020304050607", "data is incorrectly padded"),
      ("a65959a600000009", "00" * 8, "length = 9"),
      ("a65959a600000010", "00" * 8, "length = 16"),
      ("a65959a6ffffffff", "00" * 8, "length = 2**32-1"),
      ("a65959a680000008", "00" * 8, "length = 2**31 + 8"),
    )
    L3 = (
      ("a65959a600000000", "", "invalid wrapping of empty key"),
      ("a65959a600000008", "0001020304050607", "invalid wrapping of 8 byte key"),
    )
    for key_size in self.key_sizes:
      key = prand.randbytes(key_size, b"aklsdfja;lk3rjw")
      kw = self.kw(key)
      for hex_iv, hex_data, comment in L1:
        iv = bytes.fromhex(hex_iv)
        data = bytes.fromhex(hex_data)
        wrapped = kw.wrap(data, iv=iv)
        self.add_keywrap(
            key,
            data,
            wrapped,
            comment,
            "invalid",
            flags=[FLAG_MODIFIED_PADDING])
      for hex_iv, hex_data, comment in L2:
        iv = bytes.fromhex(hex_iv)
        data = bytes.fromhex(hex_data)
        wrapped = kw.block.encrypt_block(iv + data)
        self.add_keywrap(
            key,
            data,
            wrapped,
            comment,
            "invalid",
            flags=[FLAG_MODIFIED_PADDING])
      for hex_iv, hex_data, comment in L3:
        iv = bytes.fromhex(hex_iv)
        data = bytes.fromhex(hex_data)
        wrapped = kw.wrap(data, iv = iv, mode=keywrap.Mode.UNCHECKED)
        self.add_keywrap(
            key,
            data,
            wrapped,
            comment,
            "invalid",
            flags=[FLAG_MODIFIED_PADDING])


  def gen_third_party_vectors(self):
    """Adds known test vectors from RFCs."""
    if not self.test_vectors:
      return
    ref = self.test_vector_ref
    for k,d,w in self.test_vectors:
      key = bytes.fromhex(k)
      data = bytes.fromhex(d)
      wrapped = bytes.fromhex(w)
      self.add_keywrap(key, data, wrapped, ref, "valid", flags=[flag.NORMAL])

  def generate_all(self):
    self.gen_pseudorandom()
    self.gen_long_wrapping()
    self.gen_small_data_size()
    self.gen_modified_padding()
    self.gen_wrong_padding()
    self.gen_third_party_vectors()

class KwpProducer(producer.Producer):
  def parser(self):
    res = self.default_parser()
    res.add_argument(
        "--key_sizes",
        type=int,
        nargs="+",
        choices=[128, 192, 256],
        help="a list of key sizes for the wrapping key in bits")
    res.add_argument(
        "--algorithm",
        type=str,
        choices=ALGORITHMS,
        default="AES-KWP",
        help="the algorithm for the key wrapping")
    return res

  def generate_test_vectors(self, namespace):
    algorithm = getattr(namespace, "algorithm", "AES-KWP")
    key_sizes = getattr(namespace, "key_sizes", None)
    tv = KwpTestVectorGenerator(algorithm, key_sizes)
    tv.generate_all()
    return tv.test

# DEPRECATED: Use Producer.produce() instead
def main(namespace):
  KwpProducer().produce(namespace)

if __name__ == "__main__":
  KwpProducer().produce_with_args()
