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

from dataclasses import dataclass
import enum
import math
import struct
from typing import Tuple, List, Dict, Any, Union, Optional

# Defined in RFC 8949 (obsoletes RFC 7049).
#
# The RFC defines a number of terms to describe the degree of correctness.
# Well-formed:  A data item that follows the syntactic structure of CBOR.
#     Appendix C adds some pseudocode to decide if a data item is well-formed.
# Valid:  A data item that is well-formed and also follows the semantic
#     restrictions that apply to CBOR data items. The rules here are not
#     specified in the RFC. Presumably this includes for example correct
#     formats for data/time strings.
# Canonical: Section 3.9 defines a canonical representation. This format
#     selects a particular format among multiple equivalent representations.
#     The canonical representation in this section is only an example.
#     Protocols may define their own canonical representation.
# Strict decoding: The decoder must check for potentially ambiguous data. E.g.,
#  *  a map that has more than one entry with the same key
#  *  a tag that is used on a data item of the incorrect type
#  *  a data item that is incorrectly formatted for the type given to
#     it, such as invalid UTF-8 or data that cannot be interpreted with
#     the specific tag that it has been tagged with.
#
# TODO:
# Missing implementations:
#   * add a flag that enforces a canonical representation (Section 3.9)
#   * Encoded Text (section 2.4.4.3, so far only Tag(tag, txt) can be
#     used.
#
# Unclear points:
#   * Appendix C defines well-formed encodings.
#     This allows non-compact encodings. Should such encodings
#     be allowed?
#   * Appendix A gives examples for the encoding.
#     The encoding appears to indicate that the shortest
#     encoding of floats that is exact should be used.
#     i.e. 1.5 is encoded as half float, since the half float
#     representation is exact.

class MajorType(enum.Enum):
  POSITIVE_INT = 0
  NEGATIVE_INT = 1
  BYTES = 2
  TEXT = 3
  ARRAY = 4
  MAP = 5
  SEMANTIC_TAG = 6
  PRIMITIVE = 7

@dataclass
class Indefinite:
  """Wrapper to indicate that indefinite encoding should be used for an object.
  """
  value: Union[list, dict, Tuple[str, ...], Tuple[bytes, ...]]

@dataclass
class Simple:
  """Wrapper for simple values."""
  value: int

@dataclass
class Tag:
  tag: int
  val: 'CborStruct'

@dataclass
class Float:
  val: float
  size: int  # size in bits

@dataclass
class BigFloat:
  """Represents the value mantissa * 2**(exponent)
  """
  exponent: int
  mantissa: int

@dataclass
class BigDecimal:
  """Represents the value mantissa * 10**(exponent)
  """
  exponent: int
  mantissa: int

@dataclass
class DateTimeString:
  """A date/time string as defined in RFC 3339 (and RFC 4287).

  Examples:
    1985-04-12T23:20:50.52Z
    1996-12-19T16:39:57-08:00
    1990-12-31T23:59:60Z
    1990-12-31T15:59:60-08:00
    1937-01-01T12:00:27.87+00:20
    2003-12-13T18:30:02Z
    2003-12-13T18:30:02.25Z
    2003-12-13T18:30:02+01:00
    2003-12-13T18:30:02.25+01:00
  """
  datetime: str

@dataclass
class DateTimeNumeric:
  """Numerical representation of seconds relative to 1970-01-01T00:00Z.

  The tagged item can be a positive or negative integer (major types 0 and 1),
  or a floating-point number (major type 7 with additional information
  25, 26, or 27). Negative values are used for a time before 1970-01-01T00:00Z.
  Floating-point numbers are used to denote fractions of a second.
  """
  datetime: Union[int, float, 'Float']

# Type hint for objects that can be encoded with CBOR.
# I.e. these are int, bytes, str, float, arrays, dicts
CborStruct = Union[
    int,
    str,
    bytes,
    float,
    Float,
    BigFloat,
    BigDecimal,
    Tag,
    Indefinite,
    Simple,
    List['CborStruct'],
    Dict['CborStruct', 'CborStruct']
]

class CborEncodingError(Exception):
  """Used for errors during encoding."""


class CborDecodingError(Exception):
  """Used for errors during decoding."""

# Some constants (with no python equivalent)
Undefined = Simple(23)

class Encoder:

  def __init__(self, canonical: bool = False):
    """Initializes an encoder.

    Args:
      canonical: enforces the canonical encoding described in Section 3.9.
        This means that dictionaries are sorted. There is no indefinite
        encoding. Floats use the smallest precise encoding. 
    """
    self.canonical = canonical

  def encode_item(self, mt: MajorType, n: int, val: bytes = b''):
    tval = mt.value << 5
    if n <= 23:
      header = bytes([tval + n])
    elif n < 256:
      header = bytes([tval + 24]) + int.to_bytes(n, 1, 'big')
    elif n < 2**16:
      header = bytes([tval + 25]) + int.to_bytes(n, 2, 'big')
    elif n < 2**32:
      header = bytes([tval + 26]) + int.to_bytes(n, 4, 'big')
    elif n < 2**64:
      header = bytes([tval + 27]) + int.to_bytes(n, 8, 'big')
    else:
      raise CborEncodingError('Not implemented')
    return header + val

  def encode_indef_item(self, mt: MajorType, val: bytes):
    return bytes([(mt.value << 5) + 31]) + val + bytes([0xff])

  def encode_simple(self, val: int) -> bytes:
    if val < 0 or 24 <= val <= 31 or val >= 256:
      raise CborEncodingError("Invalid simple value")
    return self.encode_item(MajorType.PRIMITIVE, val)

  def encode_int(self, val: int) -> bytes:
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
    return self.encode_item(MajorType.BYTES, len(b), b)

  def encode_str(self, s: str) -> bytes:
    utf8 = s.encode('utf-8')
    return self.encode_item(MajorType.TEXT, len(utf8), utf8)

  def encode_list(self, s: list) -> bytes:
    t = b''.join(self.encode(v) for v in s)
    return self.encode_item(MajorType.ARRAY, len(s), t)

  def encode_map(self, m: dict) -> bytes:
    elems = [self.encode(k) + self.encode(v) for k, v in m.items()]
    if self.canonical:
      # TODO: Check what happens if the equal keys are allowed.
      #   There is some discussion of sorting in the errata.
      elems = sorted(elems)
    t = b''.join(elems)
    return self.encode_item(MajorType.MAP, len(m), t)

  def encode_float(self, v: float, size: int = 64) -> bytes:
    encoding = None
    for (sz, fmt, n) in (
        (16, ">e", 25),
        (32, ">f", 26),
        (64, ">d", 27)):
      if self.canonical or sz == size:
        try:
          encoding = struct.pack(fmt, v)
          val = n
          if math.isnan(v):
            break
          if self.canonical:
            v2 = struct.unpack(fmt, encoding)[0]
            if v == v2:
              break
        except Exception:
          pass
    if encoding is None:
      raise ValueError("Could not encode float")
    tag = (MajorType.PRIMITIVE.value << 5) + val
    return bytes([tag]) + encoding

  def encode_tag(self, s: Tag) -> bytes:
    ba = self.encode(s.val)
    return self.encode_item(MajorType.SEMANTIC_TAG, s.tag, ba)

  def encode_joined(self, s: CborStruct) -> bytes:
    if isinstance(s, tuple):
      if all(isinstance(v, str) for v in s):
        s = ''.join(v for v in s)
      elif all(isinstance(v, bytes) for v in s):
        s = b''.join(v for v in s)
      else:
        raise CborEncodingError('not implemented')
    return self.encode(s)

  def encode_indef(self, s: CborStruct) -> bytes:
    if self.canonical:
      return self.encode_joined(s)
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
    raise CborEncodingError('not implemented')

  def encode_bigdecimal(self, s: BigDecimal):
    exponent, mantissa = s.exponent, s.mantissa
    if self.canonical:
      # TODO: Does the canonical encoding expect
      #   decimal to int, decimal to float conversion when exact?
      if mantissa == 0:
        exponent = 0
      else:
        while mantissa % 10 == 0:
          mantissa //= 10
          exponent += 1
    t = self.encode([exponent, mantissa])
    return self.encode_item(MajorType.SEMANTIC_TAG, 4, t)

  def encode_bigfloat(self, s: BigFloat):
    exponent, mantissa = s.exponent, s.mantissa
    if self.canonical:
      # TODO: Does the canonical encoding expect
      #   bigfloat to float conversion when possible?
      if mantissa == 0:
        exponent = 0
      else:
        while mantissa % 2 == 0:
          mantissa //= 2
          exponent += 1
    t = self.encode([exponent, mantissa])
    return self.encode_item(MajorType.SEMANTIC_TAG, 5, t)

  def encode(self, s: CborStruct) -> bytes:
    """Encodes a structure."""
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
    elif isinstance(s, DateTimeString):
      return self.encode(Tag(0, s.datetime))
    elif isinstance(s, DateTimeNumeric):
      return self.encode(Tag(1, s.datetime))

    else:
      raise CborEncodingError('not implemented')


class Decoder:
  def __init__(self, strict: bool = False, keep_encoding: bool = False):
    """Constructs a decoder.

    At the moment it is unclear to me how strict decoders are expected
    to be. E.g., Section 2.4 "optional tagging and items" of RFC 7049:

      Decoders do not need to understand tags, and thus tags may be of
      little value in applications where the implementation creating a
      particular CBOR data item and the implementation decoding that stream
      know the semantic meaning of each item in the data flow. ...

    Section 3, defines some error conditions.

    Args:
      strict: use strict checking during decoding.
      keep_encoding: adds wrapper to structures to keep encoding information.
          For example, structures like Float(0.5, 32) are returned when True,
          but a simple float 0.5 is returned when False.
    """
    self.strict = strict
    self.keep_encoding = keep_encoding

  def get(self, s, pos):
    if pos < len(s):
      return s[pos]
    else:
      raise CborDecodingError("input too short")

  def get_bytes(self, s, start, stop):
    if stop <= len(s):
      return s[start:stop]
    else:
      raise CborDecodingError("input too short")

  def get_item(self,
               s: bytes,
               pos: int,
               strict: Optional[bool] = False) -> Tuple[MajorType, int, int]:
    """ Gets the major type and value of the next item.

    Args:
      s: the byte array from which the item is read
      pos: the position in s
      strict: enforce strict decoding
    Returns:
      a tuple containing the major type, the value, and the new position
      in s.
    """
    b = self.get(s, pos)
    mt = MajorType(b >> 5)
    tag = b % 32
    if 0 <= tag <= 23:
      return mt, tag, pos + 1
    elif 24 <= tag <= 27:
      sz = 1 << (tag - 24)
      val = self.get_bytes(s, pos + 1, pos + 1 + sz)
      n = int.from_bytes(val, 'big')
      if strict and n < 24:
        raise CborDecodingError("not compact form")
      return mt, int.from_bytes(val, 'big'), pos + 1 + sz
    else:
      raise CborDecodingError("unknown tag")

  def decode_int(self, s, pos: int):
    mt, val, pos = self.get_item(s, pos)
    if mt == MajorType.NEGATIVE_INT:
      val = ~val
    return val, pos

  def decode_str(self, s, pos: int):
    mt, val, pos = self.get_item(s, pos)
    b = self.get_bytes(s, pos, pos + val)
    return b.decode('utf-8'), pos + val

  def decode_bytes(self, s, pos: int):
    mt, val, pos = self.get_item(s, pos)
    b = self.get_bytes(s, pos, pos + val)
    return b, pos + val

  def decode_list(self, s, pos: int):
    mt, val, pos = self.get_item(s, pos)
    res = []
    for _ in range(val):
      val, pos = self.decode_first(s, pos)
      res.append(val)
    return res, pos

  def decode_dict(self, s, pos: int):
    mt, val, pos = self.get_item(s, pos)
    res = {}
    for _ in range(val):
      key, pos = self.decode_first(s, pos)
      val, pos = self.decode_first(s, pos)
      res[key] = val
    return res, pos

  def decode_float(self, s, pos: int):
    b = self.get(s, pos)
    tag = b % 32
    if tag == 25:
      sz = 2
      fmt = '>e'
    elif tag == 26:
      sz = 4
      fmt = '>f'
    elif tag == 27:
      sz = 8
      fmt = '>d'
    ba = self.get_bytes(s, pos + 1, pos + 1 + sz)
    val = struct.unpack(fmt, ba)[0]
    if self.keep_encoding:
      val = Float(val, 8 * sz)
    return val, pos + 1 + sz

  def decode_simple(self, s: bytes, pos: int):
    mt, val, pos = self.get_item(s, pos, strict=True)
    if val == 20:
      res = False
    elif val == 21:
      res = True
    elif val == 22:
      res = None
    elif val == 23:
      res = Undefined
    elif 0 <= val <= 23 or 32 <= val <= 255:
      res = Simple(val)
    else:
      raise CborDecodingError("Invalid value for simple %d" % val)
    return res, pos

  def decode_bigint(self, s: bytes, pos: int, tag: int):
    assert tag in (2, 3)
    val, pos = self.decode_first(s, pos)
    if isinstance(val, bytes):
      n = int.from_bytes(val, 'big')
      if tag == 3:
        n = ~n
      return n, pos
    else:
      raise CborDecodingError("expected bytes")

  def decode_tag(self, s, pos):
    mt, tag, pos = self.get_item(s, pos)
    if tag == 0:
      val, pos = self.decode_first(s, pos)
      if isinstance(val, str):
        return DataTimeString(val)
      else:
        raise CborDecodingError("Wrong type for DateTimeString")
    elif tag == 1:
      val, pos = self.decode_first(s, pos)
      if isinstance(val, int) or isinstance(val, float) or isinstance(val, Float):
        return DataTimeNumeric(val)
      else:
        raise CborDecodingError("Wrong type for DateTimeNumeric")
    elif tag == 2 or tag == 3:
      return self.decode_bigint(s, pos, tag)
    elif tag == 4:
      return self.decode_bigdecimal(s, pos)
    elif tag == 5:
      return self.decode_bigfloat(s, pos)
    elif tag <= 255:
      val, pos = self.decode_first(s, pos)
      return Tag(tag, val), pos
    raise CborDecodingError("invalid tag")

  def decode_bigdecimal(self, s, pos):
    val, pos = self.decode_first(s, pos)
    if isinstance(val, list) and len(val) == 2:
      exp, mantissa = val
      if isinstance(exp, int) and isinstance(mantissa, int):
        return BigDecimal(exp, mantissa), pos
    raise CborDecodingError("invalid bigdecimal")

  def decode_bigfloat(self, s, pos):
    val, pos = self.decode_first(s, pos)
    if isinstance(val, list) and len(val) == 2:
      exp, mantissa = val
      if isinstance(exp, int) and isinstance(mantissa, int):
        return BigFloat(exp, mantissa), pos
    raise CborDecodingError("invalid bigfloat")

  def decode_indef_first(self, s: bytes, pos: int):
    h = self.get(s, pos)
    mt = MajorType(h >> 5)
    tag = h & 0x1f
    pos += 1
    assert tag == 31
    parts = []
    if mt in (MajorType.TEXT, MajorType.BYTES):
      allow_composition = False
    else:
      allow_composition = True
    while True:
      h = self.get(s, pos)
      if h == 0xff:
        pos += 1
        break
      val, pos = self.decode_first(s, pos, allow_composition)
      parts.append(val)
    if mt == MajorType.ARRAY:
      if self.keep_encoding:
        parts = Indefinite(parts)
      return parts, pos
    elif mt == MajorType.MAP:
      if len(parts) % 2 == 1:
        raise CborDecodingError("Odd number of entries in map")
      res = {parts[i]: parts[i+1] for i in range(0, len(parts), 2)}
      if self.keep_encoding:
        return Indefinite(res), pos
      else:
        return res, pos
    elif mt == MajorType.TEXT:
      if all(isinstance(x, str) for x in parts):
        if self.keep_encoding:
          return Indefinite(tuple(parts)), pos
        else:
          return "".join(parts), pos
    elif mt == MajorType.BYTES:
      if all(isinstance(x, bytes) for x in parts):
        if self.keep_encoding:
          return Indefinite(tuple(parts)), pos
        else:
          return b"".join(parts), pos
    raise CborDecodingError("Invalid indefinite encoding")

  def decode_first(self, s: bytes, pos: int, allow_composition: bool = True):
    h = self.get(s, pos)
    mt = MajorType(h >> 5)
    tag = h & 0x1f
    if tag == 31:
      if allow_composition:
        return self.decode_indef_first(s, pos)
      else:
        raise CborDecodingError("Invalid composition")
    elif (mt == MajorType.POSITIVE_INT or
       mt == MajorType.NEGATIVE_INT):
      return self.decode_int(s, pos)
    elif mt == MajorType.MAP:
      return self.decode_dict(s, pos)
    elif mt == MajorType.ARRAY:
      return self.decode_list(s, pos)
    elif mt == MajorType.TEXT:
      return self.decode_str(s, pos)
    elif mt == MajorType.BYTES:
      return self.decode_bytes(s, pos)
    elif mt == MajorType.PRIMITIVE:
      if tag <= 24:
        return self.decode_simple(s, pos)
      if 25 <= tag <= 27:
        return self.decode_float(s, pos)
    elif mt == MajorType.SEMANTIC_TAG:
      return self.decode_tag(s, pos)
    raise CborDecodingError("Not implemented")

  def decode(self, s: bytes):
    res, pos = self.decode_first(s, 0)
    if pos != len(s):
      raise CborDecodingError("%d bytes remaining" % (len(s) - pos))
    return res

def check_well_formed(input: bytes):

  """Implements the pseudocode that checks if a data item is well formed.

  The definition has changed between RFC 7049 and 8949.
  In particular:
    * Simple values must now use the short form if possible.

  Args:
    input: the bytes to check
  Raises:
    CborDecodingError: if the input is not well-formed.
  """

  ptr = 0

  def take(n: int):
    nonlocal ptr
    if ptr + n <= len(input):
      res = input[ptr : ptr + n]
      ptr += n
      return res
    else:
      raise CborDecodingError("input too short")

  def uint(b: bytes):
    return int.from_bytes(b, 'big')

  # Some magic constants used in RFC 8949
  INDEFINITE = 99
  BREAK = -1

  def well_formed(breakable: bool = False) -> int:
    """Parses a data item.

    Args:
      breakable: True if an indefinite break is allowed
    Returns:
      The major type of the data item parsed if this item
      was definite-length, INDEFINITE_ITEM if the item was
      indefinite-length and BREAK if a break stop code was
      encountered.
    Raises:
      CborDecodingException if the data item was not well formed.
    """
    ib = uint(take(1))
    mt = ib >> 5
    ai = ib & 0x1f
    if ai == 24:
      val = uint(take(1))
    elif ai == 25:
      val = uint(take(2))
    elif ai == 26:
      val = uint(take(4))
    elif ai == 27:
      val = uint(take(8))
    elif ai in (28, 29, 30):
      raise CborDecodingError("Invalid ai %d" % ai)
    elif ai == 31:
       return well_formed_indefinite(mt, breakable)
    else:
      val = ai
    # process content
    if mt in (2, 3):
      take(val)
    elif mt == 4:
      for _ in range(val):
        well_formed()
    elif mt == 5:
      for _ in range(2 * val):
        well_formed()
    elif mt == 6:
      well_formed()  # 1 embedded data item
    elif mt == 7:
      if ai == 24 and val < 32:
        raise CborDecodingError("bad simple")
    else:
      # case 0, 1, 7 do not have content; just use val
      assert mt in (0, 1)
    return mt  # finite data item

  def well_formed_indefinite(mt: int, breakable: bool):
    if mt in (2, 3):
      while (it := well_formed(True)) != BREAK:
        if it != mt:
          raise CborDecodingError(f"Invalid element: expected {mt} got {it}")
    elif mt == 4:
      while well_formed(True) != BREAK:
        pass
    elif mt == 5:
      while well_formed(True) != BREAK:
        well_formed()
    elif mt == 7:
      if breakable:
        return BREAK
      else:
        raise CborDecodingError("No enclosing indefinite")
    else:
      raise CborDecodingError(f"Invalid value mt={mt}")
    return INDEFINITE  # No break out

  well_formed()
  if ptr != len(input):
    raise CborDecodingError("Not all bytes read")
