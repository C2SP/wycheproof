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

import keywrap
import keywrap_test_vector
import producer
import prand
import util
import flag

ALGORITHMS = ["AES-WRAP", "ARIA-WRAP", "CAMELLIA-WRAP", "SEED-WRAP"]


class KwTestVectorGenerator(keywrap_test_vector.KeywrapTestVectorGenerator):
  """Genreates test vector for the algorithm KW from

     NIST SP 800-38F
     https://nvlpubs.nist.gov/nistpubs/specialpublications/nist.sp.800-38f.pdf
     This algorithm is also defined in RFC 3394.
  """
  def __init__(self, namespace, algorithm, key_sizes):
    # TODO: add namespace to KeywrapTestVectorGenerator
    super().__init__(algorithm)
    self.test_vectors = []
    if algorithm == "AES-WRAP":
      self.kw = keywrap.AesWrap
      self.test_vectors = keywrap.test_vectors_rfc3394
      self.test_vectors_ref = "RFC 3394"
    elif algorithm == "SEED-WRAP":
      self.kw = keywrap.SeedWrap
    elif algorithm == "CAMELLIA-WRAP":
      self.kw = keywrap.CamelliaWrap
    elif algorithm == "ARIA-WRAP":
      self.kw = keywrap.AriaWrap
    else:
      raise ValueError("Unknown algorithm:" + algorithm)

    if key_sizes:
      self.key_sizes = [s // 8 for s in key_sizes]
    else:
      self.key_sizes = self.kw.block_cipher.key_sizes_in_bytes

  def wrap(self, key, data):
    return self.kw(key).wrap(data)

  def gen_invalid_data_size(self):
    for key_size in self.key_sizes:
      key = prand.randbytes(key_size, b";klasdjf;a")
      empty_key = flag.Flag(
          label="EmptyKey",
          bug_type=flag.BugType.AUTH_BYPASS,
          description="An empty key cannot be wrapped. "
          "Incorrectly wrapping an empty key may result in key independent "
          "result. Incorrectly unwrapping an empty key may allow to circumvent "
          "authentication.")
      self.add_keywrap(
          key,
          b"",
          self.kw.default_iv,
          "empty keys cannot be wrapped",
          "invalid",
          flags=[empty_key])
      short_key = flag.Flag(
          label="ShortKey",
          bug_type=flag.BugType.MISSING_STEP,
          description="NIST SP 800-38F does not define the wrapping of 8 byte "
          "keys. RFC 3394 Section 2 on the other hand specifies that 8 byte "
          "keys are wrapped by directly encrypting one block with AES.")
      self.add_keywrap(key, bytes(range(8)), None,
          "wrapping an 8 byte key", "acceptable", flags=[short_key])
      data = bytes(range(8))
      wrong_wrapping = self.kw(key).wrap(
          data, mode=keywrap.Mode.UNCHECKED)
      self.add_keywrap(
          key,
          data,
          wrong_wrapping,
          "incorrect wrapping of 8 bytes",
          "invalid",
          flags=[short_key])
      wrong_data_size = flag.Flag(
          label="WrongDataSize",
          bug_type=flag.BugType.MISSING_STEP,
          description="KW cannot be used to wrap a key that is not a multiple "
          "of 8 bytes. Inputs of such sizes should be rejected.")
      for i in range(1, 8):
        self.add_keywrap(
            key,
            bytes(range(i)),
            b"",
            "wrapped key size must be divisible by 8",
            "invalid",
            flags=[wrong_data_size])
      self.add_keywrap(
          key,
          bytes(range(20)),
          b"",
          "wrapped key size must be divisible by 8",
          "invalid",
          flags=[wrong_data_size])

  def gen_invalid_wrapped_size(self):
    invalid_size = flag.Flag(
        label="InvalidWrappingSize",
        bug_type=flag.BugType.MODIFIED_PARAMETER,
        description="The size of the wrapped key is invalid")
    for key_size in self.key_sizes:
      key = prand.randbytes(key_size, b"k12j3kl12j31kl")
      for data_size in (0, 1, 4, 8, 15, 17, 20):
        wrapped = prand.randbytes(data_size, b"k12j3kl12j31kl%d" % data_size)
        self.add_keywrap(
            key,
            b"",
            wrapped,
            "invalid size of wrapped key",
            "invalid",
            flags=[invalid_size])
      data = bytes(range(16))
      w = self.wrap(key, data)
      self.add_keywrap(
          key,
          data,
          w + bytes([0]),
          "bytes appended to wrapped key",
          "invalid",
          flags=[invalid_size])

  def gen_pseudorandom(self):
    for key_size in self.key_sizes:
      for data_size in self.key_sizes:
        if data_size <= key_size:
          self.generate_pseudorandom(
              3, [key_size], [data_size], "", "valid", flags=[flag.NORMAL])
        else:
          self.generate_pseudorandom(
              3, [key_size], [data_size],
              "wrapped key is longer than wrapping key",
              "valid",
              flags=[flag.NORMAL])

  def gen_long_wrapping(self):
    """Generates test vectors where the counter overflows 256"""
    overflow = flag.Flag(
        label="CounterOverflow",
        bug_type=flag.BugType.FUNCTIONALITY,
        description="The test vector contains a value that is long enough "
        "so that the round counter becames larger than 256.")
    for key_size in self.key_sizes:
      key = prand.randbytes(key_size, b";kljq34hwklerjw")
      data = bytes(384)
      self.add_keywrap(
          key,
          data,
          None,
          "Round counter larger than 256",
          "valid",
          flags=[overflow])

  def gen_wrong_padding(self):
    modified_iv = flag.Flag(
        label="ModifiedIv",
        bug_type=flag.BugType.MISSING_STEP,
        description="The test vector contains a ciphertext that was obtained "
        "with an incorrect IV. Unwrapping should verify that the IV is valid "
        "and hence reject this test vector.")
    for key_size in self.key_sizes:
      for data_size in self.key_sizes:
        if key_size >= data_size:
          key = prand.randbytes(key_size, b"1;2k3h1jh3")
          data = prand.randbytes(data_size, b"k12h31jk4h")
          kw = self.kw(key)
          iv = kw.default_iv
          for i in range(len(iv)):
            modified = bytearray(iv)
            modified[i] ^= 0x1
            wrapped = kw.wrap(data, iv=bytes(modified))
            self.add_keywrap(
                key,
                data,
                wrapped,
                f"byte {i} in IV changed",
                "invalid",
                flags=[modified_iv])
          for iv_hex, wrong_iv in (("0000000000000000", "0000000000000000"),
                                   ("A65959A600000000", "RFC 5649 padding"),
                                   ("5959595959595959", "5959595959595959"),
                                   ("ffffffffffffffff", "ffffffffffffffff")):
            wrapped = kw.wrap(data, iv=bytes.fromhex(iv_hex))
            self.add_keywrap(key, data, wrapped, f"IV changed to {wrong_iv}",
                             "invalid", [modified_iv])

  def gen_third_party_vectors(self, test_vectors, ref:str):
    for k,d,w in test_vectors:
      key = bytes.fromhex(k)
      data = bytes.fromhex(d)
      wrapped = bytes.fromhex(w)
      self.add_keywrap(key, data, wrapped, ref, "valid", flags=[flag.NORMAL])

  def generate_all(self):
    self.gen_pseudorandom()
    self.gen_long_wrapping()
    self.gen_invalid_data_size()
    self.gen_invalid_wrapped_size()
    self.gen_wrong_padding()
    if self.test_vectors:
      self.gen_third_party_vectors(self.test_vectors, self.test_vectors_ref)


class KwProducer(producer.Producer):

  def parser(self):
    res = self.default_parser()
    res.add_argument(
        "--key_sizes",
        type=int,
        choices=[128, 192, 256],
        nargs="+",
        help="a list of key sizes in bits for the wrapping key")
    res.add_argument(
        "--algorithm",
        type=str,
        choices=ALGORITHMS,
        default="AES-WRAP",
        help="the wrapping algorithm")
    return res

  def generate_test_vectors(self, namespace):
    key_sizes = getattr(namespace, "key_sizes", None)
    algorithm = getattr(namespace, "algorithm", "AES-WRAP")
    tv = KwTestVectorGenerator(namespace, algorithm, key_sizes)
    tv.generate_all()
    return tv.test


# DEPRECATED: Use Producer.produce() instead
def main(namespace):
  KwProducer().produce(namespace)


if __name__ == "__main__":
  KwProducer().produce_with_args()
