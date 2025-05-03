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

# Things to check:
# - large sizes
# - length too large
# - undefined tags
# - missing indefinite delimiters
# - indefinite structures with missing delimiters
# - all structures can use indefinite encoding.
# - simple elements with larger values
# - mixed indefs
# - dicts with structured keys
# - dicts with dicts as keys.
# - dicts with nan's as keys
# - dicts with lists as keys

import modify
import cbor
from cbor import CborStruct, MajorType, Indefinite, Simple, Tag, Float, BigFloat, BigDecimal

class CborFuzzer:

  def __init__(self):
    pass

  def encode_item(self, mt: MajorType, n: int, val: bytes = b''):
    if n < 0:
      raise ValueError("n is negative")
    case = self.case
    tval = mt.value << 5
    if case("Replacing type"):
      tval = (tval + 32) % 256
    if n <= 23:
      tag = n
      size = 0
    elif n < 256:
      tag = 24
      size = 1
    elif n < 2**16:
      tag = 25
      size = 2
    elif n < 2**32:
      tag = 26
      size = 4
    elif n < 2**64:
      tag = 27
      size = 8
    else:
      raise cbor.CborEncodingError('Not implemented')
    if size == 0:
      if case("Using non-optimal encoding"):
        size = 1
        tag = 24
    elif size >= 1 and size < 8:
      if case("Using non-optimal encoding"):
        size = 2 * size
        tag += 1
    if case("Undefined tag"):
      size = 16
      tag = 28
    header = bytes([tval + tag])
    if size:
      header += int.to_bytes(n, size, 'big')
    return header + val

  def encode_indef_item(self, mt: MajorType, val: bytes):
    case = self.case
    delim = bytes([0xff])
    if case("missing delimiter in indef encoding"):
      delim = bytes(0)
    if case("doubled delimiter in indef encoding"):
      delim = bytes([0xff] * 2)
    return bytes([(mt.value << 5) + 31]) + val + delim

  def encode_simple(self, val: int) -> bytes:
    assert 0 <= val < 256
    case = self.case
    for val2 in (20, 21, 22):
      if val != val2 and case("Replacing simple value"):
        return self.encode_simple(val2)
    return self.encode_item(MajorType.PRIMITIVE, val)

  def encode_int(self, val: int) -> bytes:
    case = self.case
    if val != 0 and case("encoding negative"):
      val = -val
    if case("encoding complement"):
      val = ~val
    if val != 0 and case("replacing integer by 0"):
      val = 0
    if val >= 0:
      mt = MajorType.POSITIVE_INT
      tag = 2
    else:
      val = ~val
      mt = MajorType.NEGATIVE_INT
      tag = 3
    if val.bit_length() <= 64:
      return self.encode_item(mt, val)
    else:
      size = (val.bit_length() + 7) // 8
      bytes = val.to_bytes(size, 'big')
      enc = self.encode(bytes)
      return self.encode_item(MajorType.SEMANTIC_TAG, tag, enc)

  def encode_bytes(self, b: bytes) -> bytes:
    case = self.case
    len_b = len(b)
    for modified_len, description in [
        # Java sometimes throws OutOfMemory errors for this case
        (2 ** 31 - 1, "length == 2**31 - 1"),
        (2 ** 32 + len_b, "32-bit overflow of length"),
        # Not implemented
        # (2 ** 64 + len_b, "64-bit overflow of length")
        ]:
      if len_b != modified_len:
        if case(description):
          len_b = modified_len
    return self.encode_item(MajorType.BYTES, len_b, b)

  def encode_str(self, s: str) -> bytes:
    case = self.case
    if s and case("Replacing string by empty string"):
      s = ''
    if case("Appending 0-characters"):
      s += '\0\0'
    utf8 = s.encode('utf-8')
    if case("encoding string as byte array"):
      return self.encode(utf8)
    return self.encode_item(MajorType.TEXT, len(utf8), utf8)

  def encode_list(self, s: list) -> bytes:
    case = self.case
    if case("appending null to list"):
      s = s + [None]
    if case("appending empty list to list"):
      s = s + [[]]
    if len(s) and case("replacing list by empty list"):
      s = []
    if len(s) >= 2 and case("dropping last element from list"):
      s = s[:-1]
    if len(s) >= 2 and case("dropping first element from list"):
      s = s[1:]
    if len(s) and case("duplicating last element in list"):
      s = s + [s[-1]]
    t = b''.join(self.encode(v) for v in s)
    return self.encode_item(MajorType.ARRAY, len(s), t)

  def encode_map(self, m: dict) -> bytes:
    t = b''.join(self.encode(k) + self.encode(v) for k, v in m.items())
    return self.encode_item(MajorType.MAP, len(m), t)

  def encode_float(self, v: float, size: int = 64) -> bytes:
    if size == 16:
      fmt = ">e"
      val = 25
    elif size == 32:
      fmt = ">f"
      val = 26
    elif size == 64:
      fmt = ">d"
      val = 27
    else:
      raise ValueError("invalid float size")
    encoding = struct.pack(fmt, v)
    tag = (MajorType.PRIMITIVE.value << 5) + val
    return bytes([tag]) + encoding

  def encode_tag(self, s: Tag) -> bytes:
    ba = self.encode(s.val)
    return self.encode_item(MajorType.SEMANTIC_TAG, s.tag, ba)

  def encode_indef(self, s: CborStruct) -> bytes:
    if isinstance(s, list):
      t = b''.join(self.encode(v) for v in s)
      return self.encode_indef_item(MajorType.ARRAY, t)
    elif isinstance(s, dict):
      t = b''.join(self.encode(k) + self.encode(v) for k, v in s.items())
      return self.encode_indef_item(MajorType.MAP, t)
    elif isinstance(s, tuple):
      if all(isinstance(v, str) for v in s):
        t = b''.join(self.encode(v) for v in s)
        return self.encode_indef_item(MajorType.TEXT, t)
      elif all(isinstance(v, bytes) for v in s):
        t = b''.join(self.encode(v) for v in s)
        return self.encode_indef_item(MajorType.BYTES, t)
    raise cbor.CborEncodingError('not implemented')

  def encode_bigdecimal(self, s: BigDecimal):
    t = self.encode([s.exponent, s.mantissa])
    return self.encode_item(MajorType.SEMANTIC_TAG, 4, t)

  def encode_bigfloat(self, s: BigFloat):
    t = self.encode([s.exponent, s.mantissa])
    return self.encode_item(MajorType.SEMANTIC_TAG, 5, t)

  def encode(self, s: CborStruct) -> bytes:
    """Encodes a structure."""
    case = self.case
    if case("Dropping value"):
      return b''
    if s is False:
      return self.encode_simple(20)
    elif s is True:
      return self.encode_simple(21)
    elif s is None:
      return self.encode_simple(22)
    elif isinstance(s, int):
      return self.encode_int(s)
    elif isinstance(s, float):
      return self.encode_float(s)
    elif isinstance(s, Float):
      return self.encode_float(s.val, s.size)
    elif isinstance(s, bytes):
      return self.encode_bytes(s)
    elif isinstance(s, str):
      return self.encode_str(s)
    elif isinstance(s, list):
      return self.encode_list(s)
    elif isinstance(s, dict):
      return self.encode_map(s)
    elif isinstance(s, Tag):
      return self.encode_tag(s)
    elif isinstance(s, Indefinite):
      return self.encode_indef(s.value)
    elif isinstance(s, Simple):
      return self.encode_simple(s.value)
    elif isinstance(s, BigFloat):
      return self.encode_bigfloat(s)
    elif isinstance(s, BigDecimal):
      return self.encode_bigdecimal(s)
    else:
      raise cbor.CborEncodingError('not implemented')

  def fuzz(self, s: CborStruct):
    """Usage:

    for enc, comment in f.fuzz(struct):
      ...
    """
    def wrapper(case):
      self.case = case
      return self.encode(s)

    yield from modify.CaseIter(wrapper)

def test():
  f = CborFuzzer()
  for b, c in f.fuzz([1, 0x1123456789abcdeff, "2", False]):
    print(b.hex(), c)

if __name__ == "__main__":
  test()
