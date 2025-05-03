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
from typing import Optional, Tuple

def BerError(
    message: str,
    ref: Optional[str] = None ,
    sect: Optional[str] = None):
  """Returns an exception for invalid BER encodings.

  This function also takes a reference and section of the violated BER rule.
  So far these additional arguments are just documentation. They may be used
  later.

  Args:
    message: the error message
    ref:  a reference describing the violated BER.
    sect: the section where the rule was described.
  """
  return asn.AsnError(message)

# References
# ==========
K93 = "Kaliski, A layman's guide to a subset of ASN.1, DER, and BER, 1993"
# Also defines CER, which is an ASN encoding that uses indefinite encoding
# rules.
X690 = "ITU-T, X 690"

# TODO: Enforce the following rules:
# Section 8.2:
#   BOOLEAN is primitive (done)
#   BOOLEAN always uses 1 byte content (done)
#   BOOLEAN any nonzero value = True (done)
# Section 8.3:
#   INTEGER is primitive (done)
#   INTEGER uses one or more bytes content (done)
#   content length is minimal (done)
# Section 8.4: enumerated values
#   enumerated values are primitive:
#   ...
# Section 8.6:
#   BitStrings are either primitive or constructed. (done)
#   Unused bits is an integer in the range 0..7. (done)
#   Constructed encodings can be nested
#   BER encodings can have trailing 1's. (done)
#   In constructed BitStrings only the last segment can have unused bits,
#     all other segments should be a multiple of 8. (done)
#   The tags of all the segments are always 3. (done)
# Section 8.7:
#   OctetStrings are either primitive or constructed. (done)
#   All tags in constructed OctetStrings are 4. (done)
#   Constructed OctetStrings can be nested.
# Section 8.8:
#   Null is primitive (done)
#   Null has no content. (done)
# Section 8.9:
#   Sequence is constructed
# Section 8.10:
#   Set is constructed
#   Order does not matter (but there is a definition for DER encoding)
# Section 8.19:
#   OIDs are primitive (done)
#   ... check rules for OID representation
# Section 8.20:
#   relative OID, don't know about this
#

class AsnParser:
  """Implements a parser for ASN.1

  The goal of the parser is to generate test vectors for project Wycheproof.
  This is a goal different from implementing a parser for production:
  - the parser allows lax decoding, which means it may skip a number of
    invalid encodings and try to return a possible interpretation.
  - a main focus is determining the exact cause of an error
  """

  def __init__(self, strict: bool = True):
    self.strict = strict

  def parse_bool(self, content: bytes) -> bool:
    if len(content) != 1 and self.strict:
      raise BerError("The content of a boolean consists of one octet",
                     ref = X690, sect = "8.2.1")
    if content == bytes(1):
      return False
    else:
      # The value True can be encoded with any non-zero value.
      # The DER encoding uses the byte 1.
      return True

  def parse_integer(self, content: bytes) -> int:
    """Parses the contents of an integer.

    This is described in Seciton 8.3 of X.690.
    """
    if len(content) == 0:
      if self.strict:
        raise BerError("An integer cannot have an empty content",
                       ref = X690, sect = "8.3.2")
      else:
        return 0
    if len(content) < 2:
      minimal_encoding = True
    elif content[0] == 0 and content[1] < 128:
      minimal_encoding = False
    elif content[0] == 0xff and content[1] >= 128:
      minimal_encoding = False
    else:
      minimal_encoding = True
    if not minimal_encoding and self.strict:
      raise BerError("The content of an integer should have minimal length",
                     ref = X690, sect = "8.3.2")
    return int.from_bytes(content, "big", signed=True)

  def construct_element(self, tag: int, content: bytes):
    return asn.AsnElement(tag, content)

  def construct(self, tag_struct: asn.Tag, parts):
    tag = tag_struct.identifier
    # TODO: X690 section 8.21.5.4 constructs a visible string
    #   from OCTET_STRINGS. Is this valid? Is there a rule describing this?
    acceptable_part_tags = [tag, asn.OCTET_STRING]
    if self.strict:
      if not asn.is_constructed(tag):
        raise BerError(f"Element {asn.describe_tag(tag)} cannot be constructed")
    if tag == asn.SEQUENCE:
      return parts
    elif tag == asn.SET:
      return asn.Set(parts)

    for part in parts:
      if not isinstance(part, asn.Element):
        raise BerError(f"Cannot use type {type(part)} to construct "
                       f"{asn.describe_tag(tag)}")
      part_tag = part.get_tag()
      if isinstance(part_tag, asn.Tag) and part_tag.tag_class == asn.UNIVERSAL:
        part_tag = part_tag.identifier
      if part_tag not in acceptable_part_tags:
        raise BerError(f"Cannot use element {asn.describe_tag(part_tag)} "
                       f"to construct {asn.describe_tag(tag)}")
    if tag in [
        asn.OCTET_STRING,
        asn.UTF8_STRING,
        asn.PRINTABLE_STRING,
        asn.T61_STRING,
        asn.VIDEOTEX_STRING,
        asn.IA5_STRING,
        asn.GRAPHIC_STRING,
        asn.VISIBLE_STRING,
        asn.GENERAL_STRING,
        asn.UNIVERSAL_STRING,
        asn.CHARACTER_STRING,
        asn.BMP_STRING]:
      content = b''.join(p.value() for p in parts)
      return self.construct_element(tag, content)
    elif tag == asn.BIT_STRING:
      unused = 0
      content = b''
      for part in parts:
        if unused:
          raise BerError("Only the last part in a constructed BitString may "
                         "contain unused bits")
        val = part.value()
        if not val:
          raise BerError("Invalid bit string")
        unused = val[0]
        content += val[1:]
      return asn.BitString(content, unused)
    else:
      raise ValueError(f"Construction of tag {asn.describe_tag(tag)} is not"
                       f" implemented.")


  def parse_indefinite(self, tag: asn.Tag, b: bytes
      ) -> Tuple[asn.AsnStructure, bytes]:
    if not tag.constructed:
      raise BerError("Invalid tag for indefinite encoding")
    L = []
    while True:
      if len(b) < 2:
        raise BerError("missing delimiter of indefinite encoding")
      if b[0] == b[1] == 0:
        remainder = b[2:]
        break
      v,b = self.parse_first(b)
      L.append(v)
    return self.construct(tag, L), remainder

  def parse_tag(self, b: bytes) -> Tuple[asn.Tag, bytes]:
    if not b:
      raise BerError("empty element")
    tag_class = b[0] & 0xc0
    constructed = b[0] &0x20 != 0
    if b[0] % 32 != 31:
      tag_number = b[0] % 32
      remainder = b[1:]
    else:
      tag_number = 0
      for i in range(1, len(b)):
        tag_number = tag_number * 128 + b[i] % 128
        if b[i] < 128:
          remainder = b[i+1:]
          break
      else:
        raise BerError("Invalid tag", ref = X690, sect="8.1.2.4")
    return asn.Tag(tag_number, tag_class, constructed), remainder

  def parse_length(self, b: bytes) -> Tuple[Optional[int], bytes]:
    if not b:
      raise BerError("missing length of element")
    if b[0] == 128:
      # Indefinite length encoding
      return None, b[1:]
    elif b[0] < 128:
      # short form length encoding
      return b[0], b[1:]
    else:
      # long form length encoding
      lengthsize = b[0] - 128
      if lengthsize == 127:
        raise BerError("Length of an element cannot use 127 bytes",
                       ref = X690, sect = "8.1.3.5")
      if lengthsize + 1 > len(b):
        raise BerError("Not enough bytes for the length")
      length = int.from_bytes(b[1: 1 + lengthsize], 'big')
      return length, b[1 + lengthsize:]

  def parse_first(self, b: bytes) -> Tuple[asn.AsnStructure, bytes]:
    tag, b = self.parse_tag(b)
    length, b = self.parse_length(b)
    if length is None:
      return self.parse_indefinite(tag, b)
    if length > len(b):
      raise BerError("length of element longer than sequence")
    content = b[:length]
    remainder = b[length:]
    if tag.tag_class == asn.UNIVERSAL:
      if tag.constructed:
        parts = self.parse_parts(content)
        return self.construct(tag, parts), remainder
      else:
        return self.parse_primitive(tag, content), remainder
    else:
      return self.parse_not_universal(tag, content), remainder


  def parse_primitive(self, tag_struct, content: bytes):
    tag = tag_struct.identifier
    assert not tag_struct.constructed
    assert tag_struct.tag_class == asn.UNIVERSAL

    if tag == asn.BOOLEAN:
      return self.parse_bool(content)
    elif tag == asn.INTEGER:
      return self.parse_integer(content)
    elif tag == asn.BIT_STRING:
      if len(content) < 1:
        raise BerError("unused bits in BitString missing")
      unused_bits = content[0]
      if unused_bits >= 8:
        raise BerError("The number of unused bits must be in the range 0..7",
                       ref=X690, sect = "8.6")
      if unused_bits > 0 and len(content) < 2:
        raise BerError("An empty BitString has no content and 0 unused bits",
                       ref=X690, sect="8.6.2.3")
      if unused_bits > 0:
        content = content[:-1] + bytes([content[-1] & (0xff << unused_bits)])
      return asn.BitString(content[1:], unused_bits)
    elif tag == asn.OCTET_STRING:
      return asn.OctetString(content)
    elif tag == asn.NULL:
      if len(content) != 0:
        raise BerError("NULL must not have any content",
                       ref = X690, sect = "8.8")
      return asn.Null()
    elif tag == asn.OBJECT_IDENTIFIER:
      try:
        return asn.Oid(content)
      except ValueError as ex:
        raise BerError(str(ex))
    elif tag == asn.UTF8_STRING:
      return asn.Utf8String(str(content, 'utf8'))
    elif tag == 0x0a:
      return asn.Enumerated(content)
    elif tag == asn.SEQUENCE:
      raise BerError(f"wrong tag {tag}. Sequences are always constructed",
                     ref = X690, sect = "8.9")
    elif tag == asn.SET:
      raise BerError(f"wrong tag {tag}. Sets are always constructed",
                     ref = X690, sect = "8.10")
    else:
      return asn.AsnElement(tag_struct, content,
                            description=asn.describe_tag(tag))


  def parse_not_universal(self, tag_struct, content):
    cls = tag_struct.tag_class
    num = tag_struct.identifier
    constructed = tag_struct.constructed
    assert cls in [asn.APPLICATION, asn.CONTEXT_SPECIFIC, asn.PRIVATE]
    try:
      val = self.parse(content)
      res = asn.Explicit(num, val, cls, constructed)
    except Exception:
      res = asn.AsnElement(tag_struct, content)
    return res

  def parse_parts(self, s: bytes) -> list:
    L = []
    while len(s):
      res, s = self.parse_first(s)
      L.append(res)
    return L

  def parse_list(self, s: bytes) -> list:
    return parse_parts(s)

  def parse_set(self, s: bytes) -> list:
    L = parse_parts(s)
    return asn.Set(L)

  def parse(self, s: bytes) -> asn.AsnStructure:
    res, rem = self.parse_first(s)
    if rem and self.strict:
      raise BerError("Unused bytes at the end of element")
    return res

  def parse_fromhex(self, s: str) -> asn.AsnStructure:
    return self.parse(bytes.fromhex(s))

# convenience functions
def parse(b: bytes, *, strict: bool = True):
  return AsnParser(strict=strict).parse(b)


