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

import AST
import ff1
import ff1_special
import producer
import test_generation
import test_vector
from typing import Optional, Any
import util
import prand
import flag


# TODO: encodings for test vectors.
#   - one potential encoding is to use character sets
#     such as "0123456789" for radix 10 and represent
#     plaintext and ciphertext as ASCII strings.
#     This encoding does not allow large radix,
#     e.g. any radix larger than about 120
#     [used in third-party implementations, hence this will
#      be supported as one option. Alphabets are things like
#      hex, base62, base85.]
#   - another possibility is to use UTF-8.
#     This is the default of JSON, though it might
#     lead to confusion. [everything else in wycheproof is ASCII].
#   - list of integers
#        [used in tink, so this will be supported]
#   - multiple representations.
#        [probably just an unneccessary mess]
#   - hex encoded utf-8 [too complex]
#   - hex encoded utf-16 [too complex]
#   - using some standard encodings:
#     radix:  name:   alphabet:
#     11-36   base36  0-9a-z
#     64      base64  A-Za-z0-9
#     85      ascii85 0-9A-Za-z!#...
#     [alphabets are part of the test group]
# Potential bugs to test:
#   - integer overflows for large input sizes. [done]
#   - invalid plaintexts, invalid ciphertexts.
#   - silly things, like negative integers.
#   - what are common values for radix?
#        2 (binary), 10(decimal)[done], 16(hex)[done],
#        36(alpha num)[done], 64 (base64)[done], 256(bytes)[done],
#        anything larger than 256?
#   - what are the longest input sizes?
#   - are there common long input sizes? (e.g. 512 bytes)
#     [I'm using one radix per file. Maybe radix 256 should include
#      longer inputs than the other cases]
#   - floating point errors:
#     github/capitalone/fpe uses math.Log
#     Possible test cases: (radix: length)
#        8: (7, 9, 11) (too large)
#       10: (3, 6, 9) (too small)
#       26: (13) (too small)
#       36: (3, 6, 11, 12) (too large)
#       62: (15)
#       64: (7,9,11,13, 14) (too large)
#       [floating point errors should only affect min_len and max_len
#        and hence not result in faulty encryptions.]
#   - interesting cases:
#      3 53 0x10088fda671e0b00a70633 85 slightly bigger than power of two
#     11 37 0xffd1390a0adc2fb8dabbb8174d95c99b 128 slightly smaller than power of two
#      39 7 0x1ff39afbd7 37 slightly smaller than power of two
#     46 23 0x83c63727bebaa2858fd9f63573800000 128 close to 2**127
#     53 11 0x80a23b117c8feb6d 64 close to 2**63
#      78 7 0xff9cd7deb80 44 slightly smaller than power of two
#     78 14 0xff39d62580081ad3a44000 88 slightly smaller than power of two
#      83 8 0x80072a66d5121 52 slightly bigger than power of two
#      97 5 0x1ffd869e1 33 slightly smaller than power of two
#     105 7 0x7ff99c15e819 47 slightly smaller than power of two
#     [doesn't matter much]
#   - overflows for integer arithmetic:
#       num_a, num_b = num_b, (num_a + y) % self.radix ** m
#       y is in range  0 .. 256 ** d where d = 4 * ((b + 3) // 4) + 4
#     [done for d <= 16 (block_size)]
#   - ctr overflow with messages longer than 256 blocks (Schmieg).
# Special cases:
#   - radix 2**16 (the only case where conversion requires 3 bytes)[done]
#   - small integers as intermediate results[done]
#     (some implementations use bigInt)
# Implementations:
#   BouncyCastle release 1.69, June 2021
#
#
#

# --- Type hints ---
# Inputs and outputs for format preserving encryption use two
# distinct formats:
#   (1) an encoded format using a predefined alphabet
#   (2) a list of integers in range(0, radix).
# E.g., if the predefined alphabet is "abcdefg" then
# the string "bbdg" is equivalent to [1, 1, 3, 7].
# Typically, the plan is to use a subset of the base85 alphabet.
# Test vectors with a radix larger than 185 will use a list of
# integers.

EncodedString = str
Digits = list[int]

ALGORITHMS = [ff1.AesFf1]
ALGORITHM_NAMES = [alg.name for alg in ALGORITHMS]
FPE_FORMATS = ["str", "digits"]

class CompactList(list):
  """A list that the JSON formatter tries to represent in a compact format."""
  compact_json = True


class FpeStrTest(test_vector.TestType):
  """Test vectors of type FpeStrTest are intended for format preserving encryption.

  There are two major representations for plaintexts and ciphertexts:
  (1) strings using a limited alphabet e.g. ("0123456789") or (2) lists of
  integers with where each each element is in a range 0..radix-1.

  FpeStrTest uses the first representation. Note that this representation is
  limited. Since Wycheproof test vectors use ASCII, it is not possible to
  represent test vectors for format preserving encryption with a large radix.
  """

class FpeStrTestVector(test_vector.TestVector):
  """A test vector for format preserving encryption."""
  schema = {
      "key": {
          "type": AST.HexBytes,
          "desc": "the key",
      },
      "tweak": {
          "type": AST.HexBytes,
          "desc": "the tweak",
      },
      "msg": {
          "type": EncodedString,
          "desc": "the plaintext",
      },
      "ct": {
          "type": EncodedString,
          "desc": "the ciphertext",
      },
  }

  test_attributes = ["key", "tweak", "msg", "ct"]
  group_attributes = ["radix", "alphabet", "msgSize"]

  def index(self):
    assert isinstance(self.key, bytes)
    return len(self.key), self.alphabet, len(self.msg)

class FpeStrTestGroup(test_vector.TestGroup):
  vectortype = FpeStrTestVector
  testtype = FpeStrTest
  schema = {
      "radix": {
          "type": int,
          "desc": "the expected size of the tag in bits",
      },
      "alphabet": {
          "type": str,
          "desc": "the alphabet for plaintext and ciphertext",
      },
      "keySize": {
          "type": int,
          "desc": "the keySize in bits",
      },
      "msgSize": {
          "type": int,
          "desc": "the length of plaintext and ciphertext",
      }
  }

  def __init__(self, idx: tuple[int, int, int]):
    """Constructs a test group for FPE.

    Args:
       idx: a tuple (keySize, alphabet, msgSize)
    """
    keySize, alphabet, msgSize = idx
    super().__init__()
    self.keySize = keySize
    self.alphabet = alphabet
    self.radix = len(alphabet)
    self.msgSize = msgSize

  def as_struct(self, sort_by=None):
    if sort_by is None:
      sort_by = "comment"
    group = {}
    group["type"] = self.testtype
    group["keySize"] = 8 * self.keySize
    group["radix"] = self.radix
    group["alphabet"] = self.alphabet
    group["msgSize"] = self.msgSize
    group["tests"] = self.get_all_vectors(sort_by=sort_by)
    return group

class FpeListTest(test_vector.TestType):
  """Test vectors of type FpeListTest are intended for format preserving encryption.
  
  There are two major representations for plaintexts and ciphertexts:
  (1) strings using a limited alphabet e.g. ("0123456789") or (2) lists of
  integers with where each each element is in a range 0..radix-1.

  FpeListTest uses the second representation. This representation is more
  flexible than FpeStrTest. It allows to represent test vectors for fromat
  preserving encryption with an radix 0 <= 2 <= 65536.
  """

class FpeListTestVector(test_vector.TestVector):
  """A test vector for format preserving encryption."""
  schema = {
      "key": {
          "type": AST.HexBytes,
          "desc": "the key",
      },
      "tweak": {
          "type": AST.HexBytes,
          "desc": "the tweak",
      },
      "msg": {
          "type": Digits,
          "desc": "the plaintext",
      },
      "ct": {
          "type": Digits,
          "desc": "the ciphertext",
      },
  }

  test_attributes = ["key", "tweak", "msg", "ct"]
  group_attributes = ["radix", "msgSize"]

  def index(self):
    assert isinstance(self.key, bytes)
    return len(self.key), self.radix, len(self.msg)

class FpeListTestGroup(test_vector.TestGroup):
  vectortype = FpeListTestVector
  testtype = FpeListTest
  schema = {
      "radix": {
          "type": int,
          "desc": "the expected size of the tag in bits",
      },
      "keySize": {
          "type": int,
          "desc": "the key size in bits",
      },
      "msgSize": {
          "type": int,
          "desc": "the size of plaintexts and ciphertexts",
      }
  }

  def __init__(self, idx: tuple[int, int]):
    """idx = (keySize, radix)"""
    keySize, radix, msgSize = idx
    super().__init__()
    self.keySize = keySize
    self.radix = radix
    self.msgSize = msgSize

  def as_struct(self, sort_by: Optional[str] = None) -> dict[str, Any]:
    if sort_by is None:
      sort_by = "comment"
    group = {}
    group["type"] = self.testtype
    group["keySize"] = 8 * self.keySize
    group["msgSize"] = self.msgSize
    group["radix"] = self.radix
    group["tests"] = self.get_all_vectors(sort_by=sort_by)
    return group

class FpeTestVectorGenerator(test_vector.TestGenerator):

  def __init__(self, algorithm, args):
    self.algorithm = algorithm
    self.test = test_vector.Test(algorithm, args)
    self.format = args.format
    if self.format not in FPE_FORMATS:
      raise ValueError("Unknown format:" + self.format)
    for alg in ALGORITHMS:
      if alg.name == algorithm:
        self.fpe = alg
        break
    else:
      raise ValueError("Unknown algorithm:" + algorithm)
    self.alphabet = getattr(args, "alphabet", None)
    if self.alphabet is None:
      self.alphabet = ("0123456789"
                       "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                       "abcdefghijklmnopqrtstuvxyz"
                       "!#$%&()*+_;<=>?@^_`{|}~")

  def new_testgroup(self, idx):
    if self.format == "str":
      return FpeStrTestGroup(idx)
    elif self.format == "digits":
      return FpeListTestGroup(idx)

  @util.type_check
  def permute(self, radix: int, key: bytes, tweak: bytes, msg: Digits,
              check_inputs: bool) -> Digits:
    ff = self.fpe(key, radix, check_inputs=check_inputs)
    return ff.encrypt(tweak, msg)

  @util.type_check
  def invert(self, radix: int, key: bytes, tweak: bytes, ct: Digits) -> Digits:
    ff = self.fpe(key, radix)
    return ff.decrypt(tweak, ct)

  def get_alphabet(self, radix):
    max_radix = len(self.alphabet)
    if radix > max_radix:
      raise ValueError(f"Radix to long for alphabet of size {max_radix}")
    return self.alphabet[:radix]

  def encode(self, digits: Digits, alphabet: str) -> str:
    chars = []
    for d in digits:
      if 0 <= d < len(alphabet):
        chars.append(alphabet[d])
        continue
      if d == len(alphabet):
        # Try character following alphabet
        c = chr(ord(alphabet[-1]) + 1)
        if c not in alphabet:
          chars.append(c)
          continue
      # use one of the remaining printable characters pseudorandomly
      invalid = [chr(c) for c in range(35, 127) if chr(c) not in alphabet]
      if invalid:
        val = prand.randrange(
            0, len(invalid), seed=b"kj12h341", label=str(digits))
        chars.append(invalid[val])
        continue
      raise ValueError("could not encode digits")
    return "".join(chars)

  @util.type_check
  def add_fpe(self,
              radix: int,
              key: bytes,
              tweak: bytes,
              msg: Digits,
              *,
              ct: Optional[Digits] = None,
              comment: str = "",
              valid: str = "valid",
              flags: Optional[list[flag.Flag]] = None,
              check_inputs: bool = True):
    if flags is None:
      flags = []
    else:
      flags = self.add_flags(flags)
    if ct is None:
      try:
        ct = self.permute(radix, key, tweak, msg, check_inputs)
      except Exception as ex:
        ct = []
        valid = "invalid"
        comment = str(ex)
    if self.format == "str":
      alphabet = self.get_alphabet(radix)
      test = FpeStrTestVector()
      test.alphabet = alphabet
      test.msg = self.encode(msg, alphabet)
      test.ct = self.encode(ct, alphabet)
    elif self.format == "digits":
      test = FpeListTestVector()
      test.msg = CompactList(msg)
      test.ct = CompactList(ct)
    test.radix = radix
    test.key = key
    test.tweak = tweak
    test.result = valid
    test.comment = comment
    test.flags = flags
    self.add_test(test)

  def add_edge_case(self, edge_case):
    # class EdgeCase:
    #   radix: int
    #   key: bytes
    #   tweak: bytes
    #   pt: list[int]
    #   comment: str
    self.add_fpe(
        edge_case.radix,
        edge_case.key,
        edge_case.tweak,
        edge_case.pt,
        comment=edge_case.comment,
        flags=edge_case.flags)

  def generate_pseudorandom(self,
                            cnt: int,
                            key_sizes: list[int],
                            tweak_sizes: list[int],
                            msg_sizes: list[int],
                            radix: int,
                            comment: str = "",
                            valid: str = "valid",
                            flags: Optional[list[flag.Flag]] = None):
    """Genrate pseudorandom test vectors for various sizes.

    Args:
      cnt: the number of test vectors per case
      key_sizes: the key sizes in bytes.
      tweak_sizes: the sizes of the tweaks.
      msg_sizes: the number of digits in the message.
      radix: the radix
      comment: a description of the test cases.
      valid: one of valid, invalid or acceptable.
      flags: a list of flags
    """
    for key_size in key_sizes:
      for tweak_size in tweak_sizes:
        for msg_size in msg_sizes:
          for i in range(cnt):
            ident = b"%d %d %d %d" % (key_size, tweak_size, msg_size, i)
            key = prand.randbytes(key_size, b"key:" + ident)
            tweak = prand.randbytes(tweak_size, b"tweak:" + ident)
            msg = []
            for j in range(msg_size):
              digit = prand.randrange(
                  0, radix, seed=ident, label=j.to_bytes(4, "big"))
              msg.append(digit)
            self.add_fpe(radix, key, tweak, msg,
                         comment=comment, valid=valid, flags=flags)

  def generate_invalid(self, key_sizes: list[int], tweak_sizes: list[int],
                       msg_sizes: list[int], radix: int):
    """Genrates test vectors with invalid inputs.

    Args:
      key_sizes: the key sizes in bytes.
      tweak_sizes: the sizes of the tweaks.
      msg_sizes: the number of digits in the message.
      radix: the radix
    """
    # TODO: Maybe reduce the number of test vectors generated
    #   here.
    invalid_pt_flag = flag.Flag(
        label="InvalidPlaintext",
        bug_type=flag.BugType.MODIFIED_PARAMETER,
        description="FF1 expects inputs from a fixed range of digits. "
        "This test vector contains a plaintext containing invalid digits.")
    for key_size in key_sizes:
      for tweak_size in tweak_sizes:
        for msg_size in msg_sizes:
          for invalid_digit in [-1, radix]:
            ident = b"sjkfh%d %d %d %d" % (key_size, tweak_size, msg_size,
                                           invalid_digit)
            key = prand.randbytes(key_size, b"key:" + ident)
            tweak = prand.randbytes(tweak_size, b"tweak:" + ident)
            msg = []
            for i in range(msg_size):
              digit = prand.randrange(
                  0, radix, seed=ident, label=i.to_bytes(4, "big"))
              msg.append(digit)
            for pos in sorted({0, msg_size - 1, msg_size // 3}):
              invalid_pt = msg[:]
              invalid_pt[pos] = invalid_digit
              self.add_fpe(
                  radix,
                  key,
                  tweak,
                  invalid_pt,
                  comment="plaintext contains invalid values",
                  valid="invalid",
                  flags=[invalid_pt_flag],
                  check_inputs=False)

  def generate_special(self,
                       key_sizes: list[int],
                       tweak_sizes: list[int],
                       msg_sizes: list[int],
                       radix: int = None):
    for key_size in key_sizes:
      for tweak_size in tweak_sizes:
        for msg_size in msg_sizes:
          ident = b"qkjwheqk2 %d %d %d" % (key_size, tweak_size, msg_size)
          key = prand.randbytes(key_size, b"key:" + ident)
          tweak = prand.randbytes(tweak_size, b"tweak:" + ident)
          for edge_case in ff1_special.generate_state(self.fpe, radix, key,
                                                      tweak, msg_size):
            self.add_edge_case(edge_case)
    for key_size in key_sizes:
      for msg_size in msg_sizes:
        ident = b"adfadf %d %d %d" % (key_size, tweak_size, msg_size)
        key = prand.randbytes(key_size, b"key:" + ident)
        for edge_case in ff1_special.generate_extreme_y(self.fpe, radix, key,
                                               msg_size):
          self.add_edge_case(edge_case)


  def generate_all(self,
                   key_sizes: Optional[list[int]] = None,
                   tweak_sizes: Optional[list[int]] = None,
                   radix: int = None):
    """Generate test vectors for all test cases for the given algorithm.

    Args:
      key_sizes: generates test vectors for these key sizes in bytes. Default is
        the set of all valid key sizes of the underlying block cipher.
      tag_sizes: generates test vectors for these tag sizes in bytes. Default is
        the size of the block of the underlying block cipher.
    """
    valid_key_sizes = self.fpe.block_cipher.key_sizes_in_bytes
    if key_sizes is None:
      key_sizes = valid_key_sizes
    if tweak_sizes is None:
      tweak_sizes = [8]
    if radix is None:
      radix = 10
    # Determine the message sizes.
    # This includes:
    # * all sizes up to 33
    # * 40 and 64
    # * minimal and maximal message sizes for a given d
    max_d = {}
    min_d = {}
    invalid_msg_sizes = []
    small_msg_sizes = []
    normal_msg_sizes = []
    large_msg_sizes = []
    for i in range(260):
      u, v, b, d = self.fpe.sizes_for_radix(radix, i)
      if d <= 36:
        max_d[d] = i
        if d not in min_d:
          min_d[d] = i
    all_sizes = list(range(34)) + [40, 64, 80, 128, 260]
    for d, i in max_d.items():
      all_sizes.append(i)
    for d, i in min_d.items():
      all_sizes.append(i)
    for i in sorted(set(all_sizes)):
      # NIST SP 800-38G
      # Section 5.1 radix in 2 .. 2**16
      # radix**minlen >= 1'000'000
      # 2<=minlen<=maxlen < 2**32
      # Appendix A: 100 original specification.
      m = radix ** i
      if i < 2 or m < 100:
        invalid_msg_sizes.append(i)
      elif m < 1000000:
        small_msg_sizes.append(i)
      elif m <= 2 ** 128:
        normal_msg_sizes.append(i)
      else:
        large_msg_sizes.append(i)

    invalid_msg_size = flag.Flag(
        label="InvalidMessageSize",
        bug_type=flag.BugType.MISSING_STEP,
        description="FF1 imposes a minimal size of the inputs. "
        "The original specification of FF1 required radix**minlen >= 100, "
        "NIST SP 800-38G rev 1, requires radix**minlen >= 1'000'000. "
        "This test vector contains a short message such that both limits "
        "are violated and hence should be rejected.")
    small_msg_size = flag.Flag(
        label="SmallMessageSize",
        bug_type=flag.BugType.LEGACY,
        description="FF1 imposes a minimal size of the inputs. "
        "The original specification of FF1 required radix**msglen >= 100, "
        "NIST SP 800-38G rev 1 changes this and requires radix**msglen >= "
        "1'000'000. This test vector contains a message of size msglen, "
        "such that radix**msglen lies between these two limits.")
    normal_msg_size = flag.Flag(
        label="NormalMessageSize",
        bug_type=flag.BugType.BASIC,
        description="The specification of FF1 uses integer arithmetic of "
        "arbitrary size for long messages. Some implementations may choose "
        "to restrict the message length to simplify the implementation of FF1. "
        "This test vector contains a message of size msglen such that "
        "1'000'000 <= radix**msglen <= 2**128.")
    large_msg_size = flag.Flag(
        label="LargeMessageSize",
        bug_type=flag.BugType.FUNCTIONALITY,
        description="The specification of FF1 uses integer arithmetic of "
        "arbitrary size for long messages. Some implementations may choose "
        "to restrict the message length to simplify the implementation of FF1. "
        "This test vector contains a message of size msglen such that "
        "radix**msglen > 2**128.")
    invalid_key_size = flag.Flag(
        label="InvalidKeySize",
        bug_type=flag.BugType.MODIFIED_PARAMETER,
        description="The key size is invalid.")
    # cnt, keysizes, tweak_sizes, msg_sizes, radix
    self.generate_pseudorandom(
        1,
        key_sizes,
        tweak_sizes,
        invalid_msg_sizes,
        radix,
        "message size too small",
        flags=[invalid_msg_size])
    self.generate_pseudorandom(
        1,
        key_sizes,
        tweak_sizes,
        small_msg_sizes,
        radix,
        "small message size",
        flags=[small_msg_size])
    self.generate_pseudorandom(
        1,
        key_sizes,
        tweak_sizes,
        normal_msg_sizes,
        radix,
        "normal message size",
        flags=[normal_msg_size])
    self.generate_pseudorandom(
        1,
        key_sizes,
        tweak_sizes,
        large_msg_sizes,
        radix,
        "large message size",
        flags=[large_msg_size])
    other_key_sizes = [0, 1, 8, 20, 40]
    invalid_key_sizes = [x for x in other_key_sizes if x not in valid_key_sizes]
    self.generate_pseudorandom(
        1,
        invalid_key_sizes,
        tweak_sizes,
        normal_msg_sizes[:1],
        radix,
        "invalid key size",
        flags=[invalid_key_size])
    self.generate_special(key_sizes, tweak_sizes[:1], normal_msg_sizes, radix)
    self.generate_invalid(key_sizes, tweak_sizes[:1], normal_msg_sizes, radix)

class FpeProducer(producer.Producer):
  def parser(self):
    res = self.default_parser()
    res.add_argument(
        "--algorithm",
        type=str,
        choices=ALGORITHM_NAMES,
        default="AES-FF1",
        help="the algorithm")
    res.add_argument(
        "--key_sizes",
        type=int,
        choices=[128, 192, 256],
        nargs="+",
        help="a list of key sizes in bits")
    res.add_argument(
        "--tweak_sizes",
        type=int,
        nargs="+",
        help="a list of tweak sizes in bits")
    res.add_argument("--radix", type=int, default=10, help="the radix")
    res.add_argument(
        "--alphabet",
        type=str,
        help="The alphabet to use for encoding messages."
        " Default is the base85 alphabet or a substring of it.")
    res.add_argument(
        "--format",
        type=str,
        choices=FPE_FORMATS,
        default="digits",
        help="the format of plaintext and ciphertexts")
    return res

  def generate_test_vectors(self, namespace):
    algorithm = namespace.algorithm
    tv = FpeTestVectorGenerator(algorithm, namespace)
    key_sizes_in_bits = getattr(namespace, "key_sizes", None)
    if key_sizes_in_bits:
      key_sizes = [x // 8 for x in key_sizes_in_bits]
    else:
      key_sizes = None
    tweak_sizes_in_bits = getattr(namespace, "tweak_sizes", None)
    if tweak_sizes_in_bits:
      tweak_sizes = [x // 8 for x in tweak_sizes_in_bits]
    else:
      tweak_sizes = None
    radix = getattr(namespace, "radix", None)
    tv.generate_all(key_sizes, tweak_sizes, radix)
    return tv.test


# DEPRECATED: Use Producer.produce() instead
def main(namespace):
  FpeProducer().produce(namespace)


if __name__ == "__main__":
  FpeProducer().produce_with_args()
