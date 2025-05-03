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
import oid
from collections.abc import Iterator
from typing import Optional, Any
import util

# TODO: Convert the ASN fuzzer into a class.
#   - add namespace arguments, so that the fuzzer can be modified.
#   - allow longer fields (e.g. 4200 bytes) to check for overflows like
#

# Describes the result of the ASN fuzzer:
# I.e. the fuzzer returns a generator that yields pairs (bug, value)
# where bug is None if no modification was made and a string describing
# the modification otherwise.
# the value is a byte array of the modified encoding.
# TODO: Add an enum indicating the modification. E.g.,
#   - value modified
#   - BER encoding
#   - Invalid encoding
FuzzResult = Iterator[tuple[Optional[str], bytes]]


def _encode_unsigned(v: int) -> bytes:
  """Encodes an unsigned integer.

  Args:
    v: the value to encode

  Returns:
    a bigendian encoding of v using the smallest number of bytes
  """
  size = (v.bit_length() + 7) // 8
  return v.to_bytes(size, "big")


def _flipbit(b: bytes, m: int) -> bytes:
  """Flips a bit in a bytes object.

  Args:
    b: the original bytes object
    m: the bit to flip

  Returns:
    the modified bytes object
  """
  b = bytearray(b)
  byte, bit = divmod(m, 8)
  # wrap around if m is too large
  byte %= len(b)
  b[byte] ^= 1 << bit
  return bytes(b)


@util.type_check
def generate_length(n: int, desc: str) -> FuzzResult:
  """Iterator that returns hex strings that encodes the length of a tag.

  Args:
    n: the length to encode
    desc: a description of the element whose length is encoded

  Yields:
    pairs of comments and modified encodings
  """
  yield None, asn.encode_length(n)
  descr = "length of " + desc
  s = _encode_unsigned(n)
  l = len(s)
  if l > 127:
    # integer is too long
    raise ValueError("integer is too long")
  if n < 128:
    yield f"{descr} uses long form encoding", _encode_unsigned(128 + l) + s
  yield (f"{descr} contains a leading 0",
         _encode_unsigned(128 + l + 1) + bytes([0]) + s)
  yield f"{descr} uses {n+1} instead of {n}", _encode_unsigned(n + 1)
  if n > 0:
    yield f"{descr} uses {n-1} instead of {n}", _encode_unsigned(n - 1)
  # CVE-2012-2110: uses a length of 2**31 as example:
  # CVE-2016-5547
  # CVE-2016-6890: matrixssl no details given
  # CVE-2019-16748: one byte over-read
  # CVE-2021-30737: maybe (needs more details)
  # CVE-2019-17359: bouncy castle (7.5)
  # CVE-2022-34476: accepts malformed ASN, indefinite inside indefinite.
  #                 (moderate), so this is probably just accepting malformed
  #                 ASN.
  # NIST typically gives a score of about 7.5 for OutOfMemoryErrors:
  #   E.g. CVE-2022-24839 (which is unrelated to ASN)
  yield f"uint32 overflow in {descr}", asn.encode_length(2**32 + n)
  yield f"uint64 overflow in {descr}", asn.encode_length(2**64 + n)
  yield f"{descr} = 2**31 - 1", asn.encode_length(2**31 - 1)
  yield f"{descr} = 2**31", asn.encode_length(2**31)  # CVE 2012-2110
  yield f"{descr} = 2**32 - 1", asn.encode_length(2**32 - 1)
  yield f"{descr} = 2**40 - 1", asn.encode_length(2**40 - 1)
  yield f"{descr} = 2**64 - 1", asn.encode_length(2**64 - 1)
  yield f"incorrect {descr}", bytes([255])
  yield (f"replaced {desc} by an indefinite length tag without termination",
         bytes([0x80]))


E = asn.encode_elem
# Large value size to check for overflows:
LARGE_SIZE = 4097
def generate_tag(tag: int, val, desc: Optional[str] = None) -> FuzzResult:
  if isinstance(tag, asn.Tag):
    encoding = tag.encode()
    if len(encoding) == 1:
      tag = encoding[0]
    else:
      # TODO: Not yet implemented
      return
  val_type = asn.describe_tag(tag)
  if desc is None:
    desc = val_type
  l = len(val)
  tagb = bytes([tag])
  # Get the tag value for constructed encodings
  comp_tag = 32 + tag if tag < 32 else tag
  for comment, v in generate_length(l, desc):
    yield comment, tagb + v + val
  yield f"removing {desc}", bytes()
  yield f"lonely {val_type} tag", bytes([tag])
  yield f"appending 0's to {desc}", E(tag, val + bytes(2))
  yield f"prepending 0's to {desc}", E(tag, bytes(2) + val)
  yield f"appending unused 0's to {desc}", E(tag, val) + bytes(2)
  yield f"appending null value to {desc}", E(tag, val + bytes.fromhex("0500"))
  yield f"prepending garbage to {desc}", E(
      comp_tag,
      bytes.fromhex("498177") + E(tag, val))
  yield f"prepending garbage to {desc}", E(comp_tag,
                                           bytes.fromhex("2500") + E(tag, val))
  yield f"appending garbage to {desc}", E(comp_tag, E(
      tag, val)) + bytes.fromhex("0004deadbeef")
  yield ("including undefined tags",
         E(comp_tag,
           bytes.fromhex("aa00bb00cd00") + E(tag, val)))
  yield f"truncated length of {desc}", bytes([tag]) + bytes.fromhex("81")
  yield f"including undefined tags to {desc}", E(
      comp_tag,
      bytes.fromhex("aa02aabb") + E(tag, val))
  yield (f"using composition with indefinite length for {desc}",
         asn.encode_indefinite(comp_tag, [E(tag, val)]))
  yield (f"using composition with wrong tag for {desc}",
         asn.encode_indefinite(comp_tag, [E(tag ^ 1, val)]))

  if tag != asn.NULL:
    yield f"Replacing {desc} with NULL", bytes.fromhex("0500")
  for t in sorted({tag - 2, tag - 1, tag + 1, tag + 2, 255}):
    if 0 <= t <= 255 and t != tag:
      yield f"changing tag value of {desc}", E(t, val)
  if len(val) >= 1:
    yield f"dropping value of {desc}", E(tag, bytes.fromhex(""))
    yield f"using composition for {desc}", (E(comp_tag, E(tag, val[:1])
                                + E(tag, val[1:])))
    if tag != asn.CONSTRUCTED_SEQUENCE:
      nval = _flipbit(val, 1)
      yield f"modifying first byte of {desc}", E(tag, nval)
      nval = _flipbit(val, -1)
      yield f"modifying last byte of {desc}", E(tag, nval)
  if len(val) >= 2:
    yield f"truncated {desc}", E(tag, val[:-1])
    yield f"truncated {desc}", E(tag, val[1:])
  # Checking for overflows such as CVE 2020-5734
  long_val = val + bytes(LARGE_SIZE)
  yield (f"{desc} of size {len(long_val)} to check for overflows",
         E(tag, long_val))


def generate_null(desc: Optional[str] = None) -> FuzzResult:
  """Yields modified encodings of NULL."""
  yield from generate_tag(asn.NULL, bytes.fromhex(""), desc)
  yield "composed null", bytes.fromhex("2580aa00bb000000")
  yield "incorrect null", bytes.fromhex("1f0500")


def generate_bigint(m: int, desc: Optional[str]=None) -> FuzzResult:
  """Yields modified encodings of an integer.

  Args:
    m: the integer for which the encoding is modified.
    desc: a description of the integer.
  """
  if desc is None:
    desc = "integer"
  # Flipping bits in integer.
  # Changing integers so that they overflow size_t can lead to problems.
  # E.g. CVE 2021-41990.
  for bit in (0, 32, 48, 64):
    modified = m ^ 2**bit
    res = asn.bigendian(modified, signed=True)
    yield f"flipped bit {bit} in {desc}", res
  for bit in (32, 64):
    maxint = 2**bit - 1
    if m < maxint:
      res = asn.bigendian(2**bit - 1, signed=True)
      yield f"changed {desc} to 2**{bit}-1", res

  res = asn.bigendian(m, signed=True)
  yield from generate_tag(asn.INTEGER, res, desc)
  yield f"leading ff in {desc}", E(0x02, bytes.fromhex("ff") + res)
  yield f"replaced {desc} by infinity", bytes.fromhex("090180")
  if m == 0:
    yield "encoding 0 as zero length integer", bytes.fromhex("0200")
  else:
    yield f"replacing {desc} with zero", bytes.fromhex("020100")

@util.type_check
def generate_bool(val: bool):
  content = bytes([int(val)])
  yield from generate_tag(asn.BOOLEAN, content, "Boolean")
  yield "boolean with no content", E(asn.BOOLEAN, bytes.fromhex(""))
  yield "boolean with too many bytes", E(asn.BOOLEAN, bytes(2))

@util.type_check
def generate_oid(val: bytes, val_type: Optional[str] = None) -> FuzzResult:
  """Yields modified encodings of an OID.

  Args:
     val: the oid converted into bytes.
  """
  def gen_oid(ba: bytes) -> bytes:
    return E(asn.OBJECT_IDENTIFIER, ba)

  def gen_oid_from_nodes(nodes: list[int]) -> bytes:
    return gen_oid(oid.nodes2bytes(nodes))

  yield from generate_tag(asn.OBJECT_IDENTIFIER, val, val_type)
  for md in ("SHA-1","SHA-256"):
    # TODO: Add algorithms
    other_oid = oid.oid_for_hash(md)
    if other_oid != val:
      yield "wrong oid", gen_oid(other_oid)
  nodes = oid.bytes2nodes(val)
  yield "longer oid", gen_oid_from_nodes(nodes + [1])
  yield ("oid with modified node",
         gen_oid_from_nodes(nodes[:-1] + [nodes[-1] + 16]))
  yield ("oid with modified node",
         gen_oid_from_nodes(nodes[:-1] + [nodes[-1] + 2**31]))
  yield ("large integer in oid",
         gen_oid_from_nodes(nodes[:-1] + [nodes[-1] + 2**64]))
  yield ("oid with invalid node",
         gen_oid(oid.nodes2bytes(nodes + [12345])[:-1]))
  yield ("oid with invalid node",
         gen_oid(val[:1] + bytes.fromhex("80") + val[1:]))
  many_nodes = nodes + [1] * 257
  yield f"oid with {len(many_nodes)} nodes", gen_oid_from_nodes(many_nodes)

def generate_md(md: str) -> bytes:
  """Yields modified encodings of a hash function.

  Args:
     md: the name of the hash function (e.g. SHA-256)
  """
  yield from generate_oid(oid.oid_for_hash(md))


def generate_bitstring(val: bytes,
                       unused_bits: int,
                       val_type: Optional[str] = None):
  """Yields modified encodings of a BIT_STRING.

  Args:
    val: The value of the BIT_STRING. val[0] contains the number of unused bits
      val[1:] the encoded bits of the BIT_STRING.
    val_type: a description of the value to encode
  """
  tag = asn.BIT_STRING
  if val_type is None:
    val_type = asn.describe_tag(tag)
  yield from generate_tag(tag, bytes([unused_bits]) + val, val_type)
  val2 = bytes([unused_bits + 1]) + val
  yield f"declaring bits as unused in {val_type}", E(tag, val2)
  val3 = bytes([unused_bits + 32]) + val + bytes([1, 2, 3, 4])
  yield f"unused bits in {val_type}", E(tag, val3)
  yield "unused bits in empty bit-string", E(tag, bytes([3]))
  if len(val) < 14:
    val4 = bytes([unused_bits + 8 * (len(val) + 2)]) + val
    yield "more unused bits than bit-string size", E(tag, val4)
  val5 = bytes([128]) + val
  yield "128 unused bits", E(tag, val5)


def generate_sequence(L: list[bytes], val_type: Optional[str] = None):
  """Yields modified encodings of a sequence.

  Args:
     L: a list of encoded values in the sequence.
     val_type: a description of the list to encode
  """
  seq_tag = asn.CONSTRUCTED_SEQUENCE
  yield from generate_tag(seq_tag, bytes().join(L), val_type)
  indef = asn.encode_indefinite(seq_tag, L)
  yield "indefinite length", indef
  yield "indefinite length with no delimiter", indef[:-2]
  yield "indefinite length with truncated delimiter", indef[:-1]
  yield ("indefinite length with additional element",
         asn.encode_indefinite(seq_tag, L + [bytes.fromhex("0500")]))
  yield ("indefinite length with truncated element",
         asn.encode_indefinite(seq_tag, L + [bytes.fromhex("06081122")]))
  yield "indefinite length with garbage", indef + bytes.fromhex("fe02beef")
  yield "indefinite length with nonempty EOC", indef[:-1] + bytes.fromhex(
      "02beef")
  yield "prepend empty sequence", asn.encode_sequence([bytes.fromhex("3000")] +
                                                      L)
  yield "append empty sequence", asn.encode_sequence(L +
                                                     [bytes.fromhex("3000")])
  yield "append zero", asn.encode_sequence(L + [bytes.fromhex("020100")])
  yield "append garbage with high tag number", asn.encode_sequence(
      L + [bytes.fromhex("bf7f00")])
  yield "append null with explicit tag", asn.encode_sequence(
      L + [bytes.fromhex("a0020500")])
  yield "append null with implicit tag", asn.encode_sequence(
      L + [bytes.fromhex("a000")])
  yield "sequence of sequence", asn.encode_sequence([asn.encode_sequence(L)])
  for dropped in range(1, min(len(L), 16) + 1):
    comment = f"truncated sequence: removed last {dropped} elements"
    yield comment, asn.encode_sequence(L[:-dropped])
  if len(L) > 0:
    yield "repeating element in sequence", asn.encode_sequence(L + L[-1:])

def generate_composition(val: asn.AsnComposition,
                         desc: Optional[str] = None) -> FuzzResult:
  tag = val.tag
  desc = asn.describe_tag(tag)
  prefix = val.prefix
  elem = val.elem
  asn_elem = asn.encode(elem)
  yield from generate_tag(tag, prefix + asn_elem)
  for err, e in generate(elem, val.desc):
    if err: yield err, E(tag, prefix + e)
  if prefix:
    yield f"dropping prefix in {desc}", E(tag, e)
    for k in (1, -1):
      modified = _flipbit(prefix, k)
      yield f"modifying prefix in {desc}", E(tag, modified + e)

def generate_explicit(val: asn.Explicit, val_type:Optional[str]=None) -> FuzzResult:
  der = val.value()
  tag = val.get_tag()
  encoded = asn.encode(val)
  yield from generate_tag(tag, der)
  for ident in [0, 1, 2, 30, 31]:
    modified_tag = asn.Tag(ident, tag.tag_class, tag.constructed)
    if modified_tag != tag:
      yield f"changed identifier to {ident}", E(modified_tag, der)
  for desc, tag_clazz in [("UNIVERSAL", asn.UNIVERSAL),
                          ("APPLICATION", asn.APPLICATION),
                          ("CONTEXT_SPECIFIC", asn.CONTEXT_SPECIFIC),
                          ("PRIVATE", asn.PRIVATE)]:
    modified_tag = asn.Tag(tag.identifier, tag_clazz, tag.constructed)
    if modified_tag != tag:
      yield f"changed tag class to {desc}", E(modified_tag, der)
  for comment, modified_der in generate(val.val):
    yield comment, E(tag, modified_der)
  yield "duplicating explicit element", encoded * 2
  yield "nested explicit element", E(tag, encoded)
  modified_tag = asn.Tag(tag.identifier ^ 1, tag.tag_class, tag.constructed)
  yield "nested explicit element with false tag", E(tag, E(modified_tag, der))

def generate_implicit(val: asn.Implicit, val_type:Optional[str]=None) -> FuzzResult:
  # TODO: generate more variants:
  #   ba = bytearray(encode(self.val))
  #   assert ba[0] & 31 != 31
  #   ba[0] = self.tag
  #   return bytes(ba)
  encoded = asn.encode(val.val)
  for bit in range(8):
    ba = bytearray(encoded)
    ba[0] ^= (1 << bit)
    yield f"changed tag to {ba[0]}", bytes(ba)
  yield "duplicating explicit element", encoded * 2
  yield "nested implicit element", E(val.tag, encoded)


def generate_wrapped_octets(val: asn.WrappedOctets):
  for comment, encoded in generate(val.elem):
    yield coment, val.wrap(encoded)
  yield from generate_tag(val.tag, val.val, val.description)


def generate_wrapped_bitstring(val: asn.WrappedBitString):
  for comment, encoded in generate(val.elem):
    yield comment, val.wrap(encoded)
  yield from generate_bitstring(val.val, val.unused, val.description)

# ASN structures are any of the following:
#   integers
#   lists
#   AsnElement
#   hexadecimal strings
#   bytearray, bytes
#   None -> empty
def generate(val: Any, val_type: Optional[str] = None) -> FuzzResult:
  if isinstance(val, str):
    # hexadecimal strings were used with python2. This is no longer supported.
    raise ValueError("strings are no longer supported")
  if isinstance(val, bytearray):
    val = bytes(val)
  if val is None:
    yield None, bytes.fromhex("")
    yield "replacing empty argument with Null", bytes.fromhex("0500")
  elif isinstance(val, asn.Named):
    yield from generate(val.val, val.name)
  elif isinstance(val, bytes):
    yield None, val
    yield "dropping value", bytes.fromhex("")
    yield "appending garbage", val + bytes.fromhex("0500")
  elif isinstance(val, int):
    yield from generate_bigint(val, val_type)
  elif isinstance(val, list):
    # TODO: eventually list should be replaced
    #   by sequence
    L = [asn.encode(x) for x in val]
    yield from generate_sequence(L, val_type)
    for i in range(len(val)):
      N = L[:]
      if isinstance(val_type, list) and len(val_type) > i:
        val_type_i = val_type[i]
      else:
        val_type_i = None
      for d,x in generate(val[i], val_type_i):
        N[i] = x
        yield d, asn.encode_sequence(N)
  elif isinstance(val, asn.Sequence):
    ids = [k for k,x in val.items()]
    vals = [x for k,x in val.items()]
    L = [asn.encode(x) for x in vals]
    yield from generate_sequence(L, val_type)
    for i in range(len(L)):
      N = L[:]
      for d,x in generate(vals[i], ids[i]):
        N[i] = x
        yield d, asn.encode_sequence(N)
  elif isinstance(val, asn.Explicit):
    yield from generate_explicit(val, val_type)
  elif isinstance(val, asn.Implicit):
    yield from generate_implicit(val, val_type)
  elif isinstance(val, asn.Null):
    yield from generate_null()
  elif isinstance(val, asn.BitStringElem):
    yield from generate_bitstring(val.val, val.unused, val_type)
  elif isinstance(val, asn.WrappedOctets):
    yield from generate_wrapped_octets(val)
  elif isinstance(val, asn.WrappedOctets):
    yield from generate_wrapped_bitstring(val)
  elif isinstance(val, asn.AsnElement):
    if val.tag == asn.OBJECT_IDENTIFIER:
      yield from generate_oid(val.val, val_type)
    elif val.tag == asn.BIT_STRING:
      yield from generate_bitstring(val.val[1:], val.val[0], val_type)
    else:
      yield from generate_tag(val.tag, val.val, val.description)
  elif isinstance(val, asn.AsnComposition):
    yield from generate_composition(val, val_type)
  else:
    converted = asn.to_asn(val)
    if converted is not None:
      generate(converted, val_type)
    else:
      raise Exception("not implemented:", val)


def generate_hex(val, val_type=None):
  for x,v in generate(val, val_type):
    yield x, v.hex()
