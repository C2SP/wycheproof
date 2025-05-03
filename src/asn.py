# python3

# Copyright 2016 Google Inc. All Rights Reserved.
# Author: bleichen@google.com (Daniel Bleichenbacher)
#
# ASN encoding for generating test vectors.
#
# This module requires python version 3.6 or higher.
# Earlier versions of python do not keep the order of kwargs.
# Hence the arguments in Sequence may be reordered.

# This module must only be used for testing. It is incomplete
# and untested.


# TODO:
#   - remove **args
#   - fuzzing is incomplete: e.g. Utf8Strings are not covered
#   - extended tags are not well supported
#   - Element could be extended to have tag and content.
#   - AsnElement should be simplified.

import util
import base64
import oid
import math
from typing import Optional, List, Union, Any

# Encoding types
EOC = 0
BOOLEAN = 1
INTEGER = 2
BIT_STRING = 3
OCTET_STRING = 4
NULL = 5
OBJECT_IDENTIFIER = 6
OBJECT_DESCRIPTOR = 7
EXTERNAL = 8
REAL = 9
ENUMERATED = 10
EMBEDDED_PDV = 11
UTF8_STRING = 12
RELATIVE_OID = 13
SEQUENCE = 16
SET = 17
NUMERIC_STRING = 18
PRINTABLE_STRING = 19
T61_STRING = 20
VIDEOTEX_STRING = 21
IA5_STRING = 22
UTC_TIME = 23
GENERALIZED_TIME = 24
GRAPHIC_STRING = 25
VISIBLE_STRING = 26
GENERAL_STRING = 27
UNIVERSAL_STRING = 28
CHARACTER_STRING = 29
BMP_STRING = 30

CONSTRUCTED = 0x20
CONSTRUCTED_SEQUENCE = CONSTRUCTED + SEQUENCE
CONSTRUCTED_SET = CONSTRUCTED + SET

UNIVERSAL = 0
APPLICATION = 64
CONTEXT_SPECIFIC = 128
PRIVATE = 192

# References
X690 = "ITU-T X.690"

# tag info:
#   name: a description used for this tag
#   primitive: True if this type can be encoded in BER as primitive type.
#      False if this is not allowed. None if I haven't found documentation yet.
#   constructed: True if this type can be endoded in BER as constructed type.
#      False if this is not allowed. None if I don't know yet.
#   ref: a reference in the format (document, section)
#   encoding: used for strings.
TAG_INFO = {
    BOOLEAN: {
        "name": "boolean",
        "primitive": True,
        "constructed": False,
        "ref": (X690, "8.2")
    },
    INTEGER: {
        "name": "integer",
        "primitive": True,
        "constructed": False,
        "ref": (X690, "8.3")
    },
    BIT_STRING: {
        "name": "bit string",
        "primitive": True,
        "constructed": True,
        "ref": (X690, "8.6.1")
    },
    OCTET_STRING: {
        "name": "octet string",
        "primitive": True,
        "constructed": True,
        "ref": (X690, "8.7.1")
    },
    NULL: {
        "name": "null",
        "primitive": True,
        "constructed": False,
        "ref": (X690, "8.8.1")
    },
    OBJECT_IDENTIFIER: {
        "name": "oid",
        "primitive": True,
        "constructed": False,
        "ref": (X690, "8.19")
    },
    OBJECT_DESCRIPTOR: {
        "name": "object descriptor",
        "primitive": True,
        "constructed": None
    },
    EXTERNAL: {
        "name": "external",
        "primitive": None,
        "constructed": None,
        "ref": (X690, "8.18")
    },
    REAL: {
        "name": "real",
        "primitive": True,
        "constructed": False,
        "ref": (X690, "8.5.1")
    },
    ENUMERATED: {
        "name": "enumerated",
        "primitive": True,
        "constructed": False,
        "ref": (X690, "8.4")
    },
    EMBEDDED_PDV: {
        "name": "embedded pdv",
        "primitive": None,
        "constructed": None,
        "ref": (X690, "8.17")
    },
    UTF8_STRING: {
        "name": "utf8 string",
        "primitive": True,
        "constructed": True,
        "encoding": "utf-8"
    },
    RELATIVE_OID: {
        "name": "relative oid",
        "primitive": True,
        "constructed": False,
        "ref": (X690, "8.20")
    },
    SEQUENCE: {
        "name": "sequence",
        "primitive": False,
        "constructed": True,
        "ref": (X690, "8.9")
    },
    SET: {
        "name": "set",
        "primitive": False,
        "constructed": True,
        "ref": (X690, "8.11")
    },
    NUMERIC_STRING: {
        "name": "numeric string",
        "primitive": True,
        "constructed": True
    },
    # character set a..z, A..Z, 0..9, space, (),-./:=? [K93] section 5.11
    PRINTABLE_STRING: {
        "name": "printable string",
        "primitive": True,
        "constructed": True
    },
    # an 8-bit extension of ASCII. Seems deprecated in favor of unicode.
    T61_STRING: {
        "name": "T61 string",
        "primitive": True,
        "constructed": True
    },
    VIDEOTEX_STRING: {
        "name": "videotex string",
        "primitive": True,
        "constructed": True
    },
    IA5_STRING: {
        "name": "ia5 string",
        "primitive": True,
        "constructed": True,
        "encoding": "ascii"
    },
    UTC_TIME: {
        "name": "utc time",
        "primitive": True,
        "constructed": False
    },
    GENERALIZED_TIME: {
        "name": "generalized time",
        "primitive": True,
        "constructed": False
    },
    GRAPHIC_STRING: {
        "name": "graphic string",
        "primitive": True,
        "constructed": True
    },
    VISIBLE_STRING: {
        "name": "visible string",
        "primitive": True,
        "constructed": True,
        "ref": (X690, "8.23")
    },
    GENERAL_STRING: {
        "name": "general string",
        "primitive": True,
        "constructed": True
    },
    UNIVERSAL_STRING: {
        "name": "universal string",
        "primitive": True,
        "constructed": True
    },
    CHARACTER_STRING: {
        "name": "character string",
        "primitive": True,
        "constructed": True
    },
    BMP_STRING: {
        "name": "bmp string",
        "primitive": True,
        "constructed": True
    },
}


# ASN structures are any of the following:
#   integers
#   float
#   List[AsnStructure]
#   bytearray, bytes
#   sets
#   Element
#   anything else that implements .asn()
#   None -> empty
#   Named
# Not allowed are strings. Strings should be wrapped into one of the
# string types.
# Since type hints currently do not include duck typing I don't know
# how to specify this type any better than the following:
AsnStructure = Any

# Describes an ASN structure.
# Currently this is either
#   None
#   str   the name of the fields
#   List[AsnDescriptor]  a sequence of fields
AsnDescriptor = Any


class Named:
  """Used to give an ASN structure a name.
  
  This is not part of ASN.1. It is simply used, so that the ASN fuzzer
  can generate more informative comments.
  E.g., bit_string is equivalent to Named("signature", bit_string) for
  most purposes.
  """

  def __init__(self, name: str, val: AsnStructure):
    self.name = name
    self.val = val

  def __eq__(self, other) -> bool:
    return other == self.val


class Raw:
  """Raw bytes."""

  def __init__(self, name: str, val: bytes):
    self.name = name
    self.val = val

class AsnError(ValueError):
  """Used for incorrect ASN"""


# TODO: Maybe add a function that explains differences between
#   an encoding and a structure.

def is_constructed(tag: int) -> bool:
  """Determines if a tag is constructed.

  Args:
    tag: the tag

  Returns:
    True if the tag is constructed
  """
  if tag in TAG_INFO:
    return TAG_INFO[tag]["constructed"]
  else:
    return False


def is_primitive(tag: int) -> bool:
  """Determine whether the tag is primitive

  Args:
    tag: the tag

  Returns:
    True if the tag is primitive
  """
  if tag in TAG_INFO:
    return TAG_INFO[tag]["primitive"]
  else:
    return False


class Tag:
  def __init__(self,
               identifier: int,
               tag_class: int = UNIVERSAL,
               constructed: bool = False):
    assert tag_class in [UNIVERSAL, APPLICATION, CONTEXT_SPECIFIC, PRIVATE]
    self.identifier = identifier
    self.tag_class = tag_class
    self.constructed = constructed

  def __repr__(self) -> str:
    return f"Tag({self.identifier}, {self.tag_class}, {self.constructed})"

  def __eq__(self, other: Any) -> bool:
    if isinstance(other, Tag):
      return (self.identifier == other.identifier and
              self.tag_class == other.tag_class and
              self.constructed == other.constructed)
    elif isinstance(other, int):
      # Assumes short form
      return self.encode() == bytes([other])
    else:
      return NotImplemented

  # http://luca.ntop.org/Teaching/Appunti/asn1.html
  # Section 3.1
  def encode(self) -> bytes:
    """Encodes a tag.

    Returns:
      the ASN.1 encoding of the tag
    """
    num = self.identifier
    if num < 31:
      # low tag number form
      tagid = num + self.tag_class
      if self.constructed:
        tagid += CONSTRUCTED
      return bytes([tagid])
    else:
      # high tag number form
      val = bytes()
      while num:
        num, rem  = divmod(num, 128)
        if num:
          rem += 128
        val = bytes([rem]) + val
      tagid = 31 + self.tag_class
      if self.constructed:
        tagid += CONSTRUCTED
      return bytes([tagid]) + val


def describe_tag(tag: Union[Tag, int]) -> str:
  """Returns a readable representation of a tag.

  Args:
    tag: the tag to describe

  Returns:
    a description of the tag
  """
  if isinstance(tag, Tag):
    if tag.tag_class == UNIVERSAL:
      tag = tag.identifier
    else:
      return str(tag)
  if tag in TAG_INFO:
    name = TAG_INFO[tag]["name"]
    if name:
      return name
  if tag & 0x20 and (tag - 0x20) in TAG_INFO:
    name = TAG_INFO[tag - 0x20]["name"]
    if name:
      return name
  return "tag " + hex(tag)


class Element:
  """Abstract class for ASN elements.

  Subclasses must either define the tag. Either as
    tag = <ASN_TAG>
  or by overriding get_tag().

  Subclasses must override value() -> bytes.

  Args:
    desc: A description of the element. Default is a description derived from
      the tag.
  """

  def __init__(self, *, desc: Optional[str] = None):
    self.desc = desc

  def wrap(self, b: bytes) -> bytes:
    return encode_elem(self.get_tag(), b)

  def asn(self) -> bytes:
    return self.wrap(self.value())

  @util.type_check
  def get_tag(self) -> Tag:
    """Returns the tag of the Element.
    
    Returns:
      the tag
    """
    if hasattr(self, "tag"):
      return self.tag
    raise Exception(f"missing tag in {type(self)}")

  def value(self) -> bytes:
    """Returns the encoded value of this element."""
    raise Exception(f"value() not implemented in {type(self)}")

  def __eq__(self, other) -> bool:
    return isinstance(other, Element) and self.asn() == other.asn()

  def description(self) -> str:
    return self.desc or describe_tag(get_tag())


def is_element_type(val: Any, element_type: int) -> bool:
  """Determine if val is of a given element_type."""
  if not isinstance(val, Element):
    return False
  tag = val.get_tag()
  if isinstance(tag, int):
    return tag == element_type
  else:
    return tag.identifier == element_type


class AsnElement(Element):
  @util.type_check
  def __init__(self,
               tag: Union[int, Tag],
               val: bytes,
               func = None,
               description: Optional[str] = None,
               rep: Optional[str] = None):
    """Constructs an AsnElement."""
    if isinstance(tag, int):
      assert 0 <= tag < 31
      tag = Tag(tag, UNIVERSAL, constructed=False)
    self.val = val
    self.tag = tag
    self.func = func
    self.description = description
    self.rep = rep

  def asn(self) -> bytes:
    """Returns the encoding of this element."""
    return encode_elem(self.tag, self.val)

  def value(self) -> bytes:
    return self.val

  def __repr__(self) -> str:
    if self.rep is not None:
      return self.rep
    opt_vals = ""
    if self.description:
      opt_vals += ", description=%s" % repr(self.description)
    if self.func:
      return "%s(%s%s)" % (self.func, repr(self.val), opt_vals)
    else:
      return "AsnElement(%s, %s%s)" % (repr(self.tag), repr(self.val), opt_vals)

  __str__ = __repr__


class BitStringElem(Element):
  tag = BIT_STRING

  @util.type_check
  def __init__(self, val: bytes, unused: int):
    self.val = val
    self.unused = unused

  def value(self):
    return self.val

  def wrap(self, b: bytes) -> bytes:
    return encode_elem(self.tag, bytes([self.unused]) + b)

class WrappedOctets(Element):
  tag = OCTET_STRING

  def __init__(self, elem: AsnStructure):
    self.elem = elem
    self.val = encode(elem)

  def value(self) -> bytes:
    return self.val

  def __repr__(self) -> str:
    return f"WrappedOctets({repr(self.elem)}, {repr(self.elem)})"


class WrappedBitString(Element):
  tag = BIT_STRING

  def __init__(self, elem: AsnStructure, *, unused: int = 0):
    self.elem = elem
    self.unused = unused
    self.val = encode(elem)

  def value(self) -> bytes:
    return self.val

  def wrap(self, b: bytes) -> bytes:
    return encode_elem(self.tag, bytes([self.unused]) + b)

  def __repr__(self) -> str:
    return f"WrappedBitstring({repr(self.elem)}, {repr(self.elem)})"


# TODO: deprecate
class AsnComposition(Element):
  def __init__(self,
               tag: int,
               prefix: str,
               elem: AsnStructure,
               desc: AsnDescriptor = None):
    """Generates an ASN composition.

       args:
         tag: The tag of the element
         prefix: used to generate BitStrings
         elem: The element in the composition
    """
    if isinstance(tag, int):
      assert 0 <= tag < 31
      tag = Tag(tag)
    if isinstance(prefix, str):
      prefix = bytes.fromhex(prefix)
    assert isinstance(prefix, bytes)

    self.tag = tag
    self.prefix = prefix
    self.elem = elem
    self.desc = desc

  def value(self) -> bytes:
    return self.prefix + encode(self.elem)

  def __repr__(self):
    prefix = repr(self.prefix)
    if self.desc is None:
      return "AsnComposition(%s, %s, %s)" % (
          repr(self.tag), prefix, repr(self.elem))
    else:
      return "AsnComposition(%s, %s, %s, %s)" % (
          repr(self.tag), prefix, repr(self.elem), repr(self.desc))

class Utf8String(Element):
  tag = Tag(UTF8_STRING)

  def __init__(self, val: str):
    self.val = val

  def value(self) -> bytes:
    return self.val.encode("utf8")

  def __repr__(self):
    return "Utf8String({self.val!r})"


class Sequence(Element):
  tag = Tag(SEQUENCE, constructed=True)
  def __init__(self, **kwargs):
    self.kwargs = kwargs

  def items(self):
    return self.kwargs.items()

  def value(self):
    elems = [encode(x) for k,x in self.items()]
    return b"".join(elems)

  def __repr__(self):
    args = ", ".join("%s=%s" % (k, repr(v)) for k,v in self.items())
    return "Sequence(%s)" % args

class Set(Element):
  tag = Tag(SET, constructed=True)

  def __init__(self, elements):
    self.elements = elements

  def value(self) -> bytes:
    elems = [encode(x) for x in self.elements]
    return b"".join(elems)

  def __repr__(self):
    return f"Set({self.elements!r})"

class Boolean(Element):
  tag = Tag(BOOLEAN)

  def __init__(self, val: bool):
    self.val = val

  def value(self):
    return bytes([int(self.val)])

  def __repr__(self):
    return f"Boolean({self.val!r})"

class Null(Element):
  tag = Tag(NULL)

  def __init__(self):
    pass

  def value(self):
    return bytes()

  def __repr__(self):
    return("Null()")


# TODO: Not sure if the name Explicit is a good name for the class.
# Examples:
#   [1] INTEGER
#   is an integer with tag_class CONTEXT_SPECIFIC, identifier 1 and
#   explicit encoding (http://luca.ntop.org/Teaching/Appunti/asn1.html Section 2.3)
# Explicit tags are always constructed. [cite?]
class Explicit(Element):
  def __init__(self,
               ident: int,
               val,
               tag_class: int = CONTEXT_SPECIFIC,
               constructed: bool = True):
    if not (0 <= ident < 31):
      raise AsnError(f"Invalid ident:{ident}")
    assert tag_class in [APPLICATION, CONTEXT_SPECIFIC, PRIVATE]
    self.ident = ident
    self.tag_class = tag_class
    self.constructed = constructed
    self.val = val
    self.tag = Tag(ident, tag_class, constructed)

  def value(self) -> bytes:
    return encode(self.val)

  def __repr__(self) -> str:
    class_rep = {
      APPLICATION : "APPLICATION",
      CONTEXT_SPECIFIC : "CONTEXT_SPECIFIC",
      PRIVATE : "PRIVATE"} [self.tag_class]
    return "Explicit(%s, %s, %s, %s)" % (
        repr(self.ident), repr(self.val), class_rep, self.constructed)

class Implicit(Element):
  def __init__(self,
               ident: int,
               val,
               tag_class: int = CONTEXT_SPECIFIC,
               constructed: bool = True):
    # TODO: implement for larger identifiers
    if not (0 <= ident < 31):
      raise AsnError(f"Invalid ident:{ident}")
    assert tag_class in [APPLICATION, CONTEXT_SPECIFIC, PRIVATE]
    self.ident = ident
    self.tag_class = tag_class
    self.constructed = constructed
    self.val = val
    self.tag = Tag(ident, tag_class, constructed)

  def asn(self):
    encoded = encode(self.val)
    if encoded[0] & 31 != 31:
      tag_size = 1
    else:
      raise ValueError("long form tags are not implemented")
    return self.tag.encode() + encoded[tag_size:]

  def __repr__(self):
    class_rep = {
      APPLICATION : "APPLICATION",
      CONTEXT_SPECIFIC : "CONTEXT_SPECIFIC",
      PRIVATE : "PRIVATE"} [self.tag_class]
    return "Implicit(%s, %s, %s, %s)" % (
        repr(self.ident), repr(self.val), class_rep, self.constructed)


# TODO: BitString(bytes) is ambiguous.
#   This needs to have a constructor where val are raw bytes
#   and a constructor where val is an AsnStructure.
#   The same is true for other constructors below.
def BitString(val, unused_bits:int = 0) -> AsnElement:
  """val can be one of the following:
     * bytearray or bytes
     * a structure: in this case the structure is ASN encoded
       an the ASN encoded result is represeted as a BitString"""
  if isinstance(val, str):
    raise ValueError("hexadecimal strings have been deprecated")
  if isinstance(val, bytearray):
    val = bytes(val)
  if isinstance(val, bytes):
    # TODO: Use BitStringElem
    val = bytes([unused_bits]) + val
    return AsnElement(BIT_STRING, val, func="BitString")
  else:
    # TODO: deprecate AsnComposition
    prefix = bytes([unused_bits])
    return AsnComposition(BIT_STRING, prefix, val)


@util.type_check
def OctetString(val: bytes, description: str = None) -> AsnElement:
  # return Named(description, OctetString(val))
  return AsnElement(OCTET_STRING, val, func="OctetString",
                    description=description)

# TODO: deprecate str for Oids.
@util.type_check
def Oid(val: Union[str, bytes, list, oid.Oid]) -> AsnElement:
  if isinstance(val, str):
    val = bytes.fromhex(val)
  elif isinstance(val, list):
    val = oid.Oid(val)

  if isinstance(val, oid.Oid):
    nodes = val.nodes
    val = val.bytes()
  elif isinstance(val, bytes):
    nodes = oid.bytes2nodes(val)
  else:
    raise ValueError("Invalid type:", type(val))
  rep = f"Oid({repr(nodes)})"
  return AsnElement(OBJECT_IDENTIFIER, val, func="Oid", rep=rep)


def Enumerated(val, **args):
  """Uses: Enumerated(int), Enumerated(bytearray), Enumerated(hex)"""
  if isinstance(val, int):
    val = bytes([val])
  return AsnElement(ENUMERATED, val, func="Enumerated", **args)

def OctetStringFromInt(n: int, size: int) -> AsnElement:
  return OctetString(n.to_bytes(size, "big"))


def OctetStringFromStruct(struct) -> AsnElement:
  return AsnComposition(OCTET_STRING, b"", struct)

def to_asn(val) -> Optional[AsnStructure]:
  if isinstance(val, oid.Oid):
    return Oid(val)
  return None

@util.type_check
def encode(val: AsnStructure) -> bytes:
  if val is None:
    # Generated b"" in previous versions
    raise ValueError("Ambiguous, use asn.Raw(b\"\") instead")
  if isinstance(val, type):
    # Sanity check for things like encode(Null).
    raise ValueError(f"Can't encode a type {type}")
  if isinstance(val, bytearray) or isinstance(val, bytes) or isinstance(
      val, str):
    # This is an ambiguous left-over from the python2 version.
    # I.e. it is unclear how strings should be encoded.
    # bytearrays could be either encoded as OctetStrings or are
    # already encoded.
    raise ValueError("Ambiguous, use Utf8String, OctetString, Raw, etc.")
  if isinstance(val, Raw):
    return val.val
  if isinstance(val, Named):
    return encode(val.val)
  if isinstance(val, bool):
    return encode(Boolean(val))
  if isinstance(val, int):
    return encode_bigint(val)
  if isinstance(val, float):
    return encode_float_approx(val)
  if isinstance(val, list):
    elem = b"".join(encode(x) for x in val)
    return encode_elem(CONSTRUCTED_SEQUENCE, elem)
  if isinstance(val, set):
    elems = [encode(x) for x in val]
    # Make the order deterministic
    elems = sorted(elems)
    return encode_elem(CONSTRUCTED_SET, b"".join(elems))
  if isinstance(val, Element):
    return val.asn()
  if hasattr(val, "asn"):
    return val.asn()
  converted = to_asn(val)
  if converted is not None:
    return encode(converted)
  raise TypeError("not implemented:", type(val), val)

# DEPRECATED: this was used for doc test.
def encode_hex(val: AsnStructure) -> str:
  return encode(val).hex()

def encode_b64(val: AsnStructure) -> str:
  der = encode(val)
  b64 = base64.b64encode(der)
  return b64.decode("ascii")


def bigendian(n: int, signed: bool = False) -> bytes:
  """Converts an integer into bytes using bigendian encoding.

  Args:
    n: the integer to convert
    signed: if True then twos complement representation is used.

  Returns:
    the encoded integer
  """
  if not signed and n < 0:
    raise ValueError("n is negative")
  res = bytearray()
  m = n
  while True:
    m, rem = divmod(m, 256)
    res.append(rem)
    if m in (0, -1):
      break
  if signed:
    isneg = res[-1] >= 128
    if isneg and n >= 0:
      res.append(0)
    elif not isneg and n < 0:
      res.append(255)
  return bytes(res[::-1])

def encode_bigint(n: int) -> bytes:
  return encode_elem(INTEGER, bigendian(n, signed=True))

def encode_bigint_fixedlength(n: int, size: int) -> bytes:
  """Encodes non-negative integer in bigendian format using a fixed size"""
  b = bytearray(size)
  for i in range(size):
    n, rem = divmod(n, 256)
    b[i] = rem
  assert n==0
  return bytes(b[::-1])

def encode_float_approx(val: float, rel_error=2**-48):
  # https://github.com/Asn1Net/Asn1Net.Reader/blob/master/src/Asn1Net.Reader/Tests/BerReaderTests/BasicReaderTests.cs
  if math.isnan(val):
    return bytes([0x09, 0x01, 0x42])
  if math.isinf(val):
    if val > 0:
      return bytes([0x09, 0x01, 0x40])
    else:
      return bytes([0x09, 0x01, 0x41])
  m, e = math.frexp(val)
  while abs(round(m)-m) > rel_error:
    rel_error *= 2
    m *= 2
    e -= 1
  return encode_float(int(round(m)), e, 2)

def encode_float(mantissa: int, exp: int, base: int = 2) -> bytes:
  """Encoding of real integers.
     Only base 2 encodings are supported.
     Only encodings with a 1 byte exponent are supported.
     0.0 is not supported"""
  assert isinstance(mantissa, int)
  assert mantissa != 0
  assert base == 2
  m = bigendian(mantissa, signed=True)
  e = bigendian(exp, signed=True)
  assert len(e) in (1, 2, 3)
  info = 0x80 + len(e) - 1
  return encode_elem(REAL, bytes([info]) + e + m)

def encode_length(n: int) -> bytes:
  """ Returns a hex string that encodes the length of a tag."""
  if (n < 128):
    # short encoding
    return bytes([n])
  # long encoding
  s = bigendian(n, signed=False)
  l = len(s)
  if l > 127:
    # integer is too long
    raise ValueError
  return bigendian(128 + l, signed=False) + s

@util.type_check
def encode_elem(tag: Union[int, Tag], value: bytes) -> bytes:
  if isinstance(tag, int):
    tagval = bytes([tag])
  else:
    tagval = tag.encode()
  return tagval + encode_length(len(value)) + value

def encode_indefinite(tag: int, L: List[bytes]) -> bytes:
  """Composition with indefinite length"""
  res = bytearray()
  res.append(tag)
  res.append(0x80)
  for x in L:
    res += x
  res.append(0)
  res.append(0)
  return bytes(res)

def encode_sequence(L: List[bytes]) -> bytes:
  return encode_elem(CONSTRUCTED_SEQUENCE, b"".join(L))

def encode_octet_string(val: bytes) -> bytes:
  return encode_elem(OCTET_STRING, val);

# ----- Hashing -----
def oid_from_hash(md: str) -> Oid:
  return Oid(oid.oid_for_hash(md))
