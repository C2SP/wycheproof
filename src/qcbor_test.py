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

import cbor

# Invalid encodings from qcbor
InvalidEncodings = [
  ("5f4100", "HIT_END"),
  # An indefinite length text string not closed off 
  ("7f6100", "HIT_END"),
  # All the chunks in an indefinite length string must be of the type of 
  # indefinite length string
  # indefinite length byte string with text string chunk
  ("5f6100ff", "INDEFINITE_STRING_CHUNK"),
  # indefinite length text string with a byte string chunk
  ("7f4100ff", "INDEFINITE_STRING_CHUNK"),
  # indefinite length byte string with an positive integer chunk
  ("5f00ff", "INDEFINITE_STRING_CHUNK"),
  # indefinite length byte string with an negative integer chunk
  ("5f21ff", "INDEFINITE_STRING_CHUNK"),
  # indefinite length byte string with an array chunk
  ("5f80ff", "INDEFINITE_STRING_CHUNK"),
  # indefinite length byte string with an map chunk
  ("5fa0ff", "INDEFINITE_STRING_CHUNK"),
  # indefinite length byte string with tagged integer chunk
  ("5fc000ff", "INDEFINITE_STRING_CHUNK"),
  # indefinite length byte string with an simple type chunk
  ("5fe0ff", "INDEFINITE_STRING_CHUNK"),
  ("5f5f4100ffff", "INDEFINITE_STRING_CHUNK"),
  # indefinite length text string with indefinite string inside
  ("7f7f6100ffff", "INDEFINITE_STRING_CHUNK"),
  ("5f4100", "INDEF_LEN_STRINGS_DISABLED"),
  # An indefinite length text string not closed off
  ("7f6100", "INDEF_LEN_STRINGS_DISABLED"),
  # All the chunks in an indefinite length string must be of the type of
  # indefinite length string
  # indefinite length byte string with text string chunk
  ("5f6100ff", "INDEF_LEN_STRINGS_DISABLED"),
  # indefinite length text string with a byte string chunk
  ("7f4100ff", "INDEF_LEN_STRINGS_DISABLED"),
  # indefinite length byte string with an positive integer chunk
  ("5f00ff", "INDEF_LEN_STRINGS_DISABLED"),
  # indefinite length byte string with an negative integer chunk
  ("5f21ff", "INDEF_LEN_STRINGS_DISABLED"),
  # indefinite length byte string with an array chunk
  ("5f80ff", "INDEF_LEN_STRINGS_DISABLED"),
  # indefinite length byte string with an map chunk
  ("5fa0ff", "INDEF_LEN_STRINGS_DISABLED"),
  # indefinite length byte string with tagged integer chunk
  ("5fc000ff", "INDEF_LEN_STRINGS_DISABLED"),
  # indefinite length byte string with an simple type chunk
  ("5fe0ff", "INDEF_LEN_STRINGS_DISABLED"),
  ("5f5f4100ffff", "INDEF_LEN_STRINGS_DISABLED"),
  # indefinite length text string with indefinite string inside
  ("7f7f6100ffff", "INDEF_LEN_STRINGS_DISABLED"),
  # Definte length maps and arrays must be closed by having the right number of items
  # A definte length array that is supposed to have 1 item, but has none
  ("81", "NO_MORE_ITEMS"),
  # A definte length array that is supposed to have 2 items, but has only 1
  ("8200", "NO_MORE_ITEMS"),
  # A definte length array that is supposed to have 511 items, but has only 1
  ("9a01ff00", "HIT_END"),
  # A definte length map that is supposed to have 1 item, but has none
  ("a1", "NO_MORE_ITEMS"),
  # A definte length map that is supposed to have s item, but has only 1
  ("a20102", "NO_MORE_ITEMS"),
  # Indefinte length maps and arrays must be ended by a break
  # Indefinite length array with zero items and no break
  ("9f", "NO_MORE_ITEMS"),
  # Indefinite length array with two items and no break
  ("9f0102", "NO_MORE_ITEMS"),
  # Indefinite length map with zero items and no break
  ("bf", "NO_MORE_ITEMS"),
  # Indefinite length map with two items and no break
  ("bf01020102", "NO_MORE_ITEMS"),
  # Nested maps and arrays must be closed off (some extra nested test vectors)
  # Unclosed indefinite array containing a closed definite length array
  ("9f8000", "NO_MORE_ITEMS"),
  # Definite length array containing an unclosed indefinite length array
  ("819f", "NO_MORE_ITEMS"),
  # Unclosed indefinite map containing a closed definite length array
  ("bf018000a0", "NO_MORE_ITEMS"),
  # Definite length map containing an unclosed indefinite length array
  ("a1029f", "NO_MORE_ITEMS"),
  # Deeply nested definite length arrays with deepest one unclosed
  ("818181818181818181", "QCBOR_ERR_NO_MORE_ITEMS"),
  # Deeply nested indefinite length arrays with deepest one unclosed
  ("9f9f9f9f9fffffffff", "QCBOR_ERR_NO_MORE_ITEMS"),
  # Mixed nesting with indefinite unclosed
  ("9f819f819f9fffffff", "QCBOR_ERR_NO_MORE_ITEMS"),
  # Mixed nesting with definite unclosed
  ("9f829f819f9fffffffff", "QCBOR_ERR_BAD_BREAK"),
  # Unclosed indefinite length map in definite length maps
  ("a101a202bfff02bf", "QCBOR_ERR_NO_MORE_ITEMS"),
  # Unclosed definite length map in indefinite length maps
  ("bf01bf02a1", "NO_MORE_ITEMS"),
  # Unclosed indefinite length array in definite length maps
  ("a101a2029fff029f", "QCBOR_ERR_NO_MORE_ITEMS"),
  # Unclosed definite length array in indefinite length maps
  ("bf01bf0281", "NO_MORE_ITEMS"),
  # Unclosed indefinite length map in definite length arrays
  ("8182bfffbf", "NO_MORE_ITEMS"),
  # Unclosed definite length map in indefinite length arrays
  ("9f9fa1", "NO_MORE_ITEMS"),
  # The "argument" for the data item is incomplete
  # Positive integer missing 1 byte argument
  ("18", "HIT_END"),
  # Positive integer missing 2 byte argument
  ("19", "HIT_END"),
  # Positive integer missing 4 byte argument
  ("1a", "HIT_END"),
  # Positive integer missing 8 byte argument
  ("1b", "HIT_END"),
  # Positive integer missing 1 byte of 2 byte argument
  ("1901", "HIT_END"),
  # Positive integer missing 2 bytes of 4 byte argument
  ("1a0102", "HIT_END"),
  # Positive integer missing 1 bytes of 7 byte argument
  ("1b01020304050607", "HIT_END"),
  # Negative integer missing 1 byte argument
  ("38", "HIT_END"),
  # Binary string missing 1 byte argument
  ("58", "HIT_END"),
  # Text string missing 1 byte argument
  ("78", "HIT_END"),
  # Array missing 1 byte argument
  ("98", "HIT_END"),
  # Map missing 1 byte argument
  ("b8", "HIT_END"),
  # Tag missing 1 byte argument
  ("d8", "HIT_END"),
  # Simple missing 1 byte argument
  ("f8", "HIT_END"),
  # half-precision with 1 byte argument
  ("f900", "HIT_END"),
  # single-precision with 2 byte argument
  ("fa0000", "HIT_END"),
  # double-precision with 3 byte argument
  ("fb000000", "HIT_END"),
  # Tag with no content
  ("c0", "HIT_END"),
  # Breaks must not occur in definite length arrays and maps
  # Array of length 1 with sole member replaced by a break
  ("81ff", "BAD_BREAK"),
  # Array of length 2 with 2nd member replaced by a break
  ("8200ff", "BAD_BREAK"),
  # Map of length 1 with sole member label replaced by a break
  ("a1ff", "BAD_BREAK"),
  # Map of length 1 with sole member label replaced by break
  # Alternate representation that some decoders handle differently
  ("a1ff00", "BAD_BREAK"),
  # Array of length 1 with 2nd member value replaced by a break
  ("a100ff", "BAD_BREAK"),
  # Map of length 2 with 2nd member replaced by a break
  ("a20000ff", "BAD_BREAK"),
  # Breaks must not occur on their own out of an indefinite length data item
  # A bare break is not well formed
  ("ff", "BAD_BREAK"),
  # A bare break after a zero length definite length array
  ("80ff", "BAD_BREAK"),
  # A bare break after a zero length indefinite length map
  ("9fffff", "BAD_BREAK"),
  # A break inside a definite length array inside an indefenite length array
  ("9f81ff", "BAD_BREAK"),
  # Complicated mixed nesting with break outside indefinite length array
  ("9f829f819f9fffffffff", "QCBOR_ERR_BAD_BREAK"),
  # Forbidden two byte encodings of simple types
  # Must use 0xe0 instead
  ("f800", "BAD_TYPE_7"),
  # Should use 0xe1 instead
  ("f801", "BAD_TYPE_7"),
  # Should use 0xe2 instead
  ("f802", "BAD_TYPE_7"),
  # Should use 0xe3 instead
  ("f803", "BAD_TYPE_7"),
  # Should use 0xe4 instead
  ("f804", "BAD_TYPE_7"),
  # Should use 0xe5 instead
  ("f805", "BAD_TYPE_7"),
  # Should use 0xe6 instead
  ("f806", "BAD_TYPE_7"),
  # Should use 0xe7 instead
  ("f807", "BAD_TYPE_7"),
  # Should use 0xe8 instead
  ("f808", "BAD_TYPE_7"),
  # Should use 0xe9 instead
  ("f809", "BAD_TYPE_7"),
  # Should use 0xea instead
  ("f80a", "BAD_TYPE_7"),
  # Should use 0xeb instead
  ("f80b", "BAD_TYPE_7"),
  # Should use 0xec instead
  ("f80c", "BAD_TYPE_7"),
  # Should use 0xed instead
  ("f80d", "BAD_TYPE_7"),
  # Should use 0xee instead
  ("f80e", "BAD_TYPE_7"),
  # Should use 0xef instead
  ("f80f", "BAD_TYPE_7"),
  # Should use 0xf0 instead
  ("f810", "BAD_TYPE_7"),
  # Should use 0xf1 instead
  ("f811", "BAD_TYPE_7"),
  # Should use 0xf2 instead
  ("f812", "BAD_TYPE_7"),
  # Must use 0xf3 instead
  ("f813", "BAD_TYPE_7"),
  # Must use 0xf4 instead
  ("f814", "BAD_TYPE_7"),
  # Must use 0xf5 instead
  ("f815", "BAD_TYPE_7"),
  # Must use 0xf6 instead
  ("f816", "BAD_TYPE_7"),
  # Must use 0xf7 instead
  ("f817", "BAD_TYPE_7"),
  # Must use 0xf8 instead
  ("f818", "BAD_TYPE_7"),
  # Reserved
  ("f81f", "BAD_TYPE_7"),
  # Integers with additional info indefinite length
  # Positive integer with additional info indefinite length
  ("1f", "BAD_INT"),
  # Negative integer with additional info indefinite length
  ("3f", "BAD_INT"),
  # CBOR tag with "argument" an indefinite length
  ("df00", "BAD_INT"),
  # CBOR tag with "argument" an indefinite length alternate vector
  ("df", "BAD_INT"),
  # Missing bytes from a deterministic length string
  # A byte string is of length 1 without the 1 byte
  ("41", "HIT_END"),
  # A text string is of length 1 without the 1 byte
  ("61", "HIT_END"),
  # Byte string should have 2^32-15 bytes, but has one
  ("5afffffff000", "HIT_END"),
  # Byte string should have 2^32-15 bytes, but has one
  ("7afffffff000", "HIT_END"),
  # Byte string should have 2^64 bytes, but has 3
  ("5bffffffffffffffff010203", "HIT_END"),
  # Text string should have 2^64 bytes, but has 3
  ("7bffffffffffffffff010203", "HIT_END"),
  # Byte string should have 2^32-15 bytes, but has one
  ("5a0000fff000", "HIT_END"),
  # Byte string should have 2^32-15 bytes, but has one
  ("7a0000fff000", "HIT_END"),
  # Byte string should have 2^16 bytes, but has 3
  ("5b000000000000ffff010203", "HIT_END"),
  # Text string should have 2^64 bytes, but has 3
  ("7b000000000000ffff010203", "HIT_END"),
  # Use of unassigned additional information values
  # Major type positive integer with reserved value 28
  ("1c", "UNSUPPORTED"),
  # Major type positive integer with reserved value 29
  ("1d", "UNSUPPORTED"),
  # Major type positive integer with reserved value 30
  ("1e", "UNSUPPORTED"),
  # Major type negative integer with reserved value 28
  ("3c", "UNSUPPORTED"),
  # Major type negative integer with reserved value 29
  ("3d", "UNSUPPORTED"),
  # Major type negative integer with reserved value 30
  ("3e", "UNSUPPORTED"),
  # Major type byte string with reserved value 28 length
  ("5c", "UNSUPPORTED"),
  # Major type byte string with reserved value 29 length
  ("5d", "UNSUPPORTED"),
  # Major type byte string with reserved value 30 length
  ("5e", "UNSUPPORTED"),
  # Major type text string with reserved value 28 length
  ("7c", "UNSUPPORTED"),
  # Major type text string with reserved value 29 length
  ("7d", "UNSUPPORTED"),
  # Major type text string with reserved value 30 length
  ("7e", "UNSUPPORTED"),
  # Major type array with reserved value 28 length
  ("9c", "UNSUPPORTED"),
  # Major type array with reserved value 29 length
  ("9d", "UNSUPPORTED"),
  # Major type array with reserved value 30 length
  ("9e", "UNSUPPORTED"),
  # Major type map with reserved value 28 length
  ("bc", "UNSUPPORTED"),
  # Major type map with reserved value 29 length
  ("bd", "UNSUPPORTED"),
  # Major type map with reserved value 30 length
  ("be", "UNSUPPORTED"),
  # Major type tag with reserved value 28 length
  ("dc", "UNSUPPORTED"),
  # Major type tag with reserved value 29 length
  ("dd", "UNSUPPORTED"),
  # Major type tag with reserved value 30 length
  ("de", "UNSUPPORTED"),
  # Major type simple with reserved value 28 length
  ("fc", "UNSUPPORTED"),
  # Major type simple with reserved value 29 length
  ("fd", "UNSUPPORTED"),
  # Major type simple with reserved value 30 length
  ("fe", "UNSUPPORTED"),
  # Maps must have an even number of data items (key & value)
  # Map with 1 item when it should have 2
  ("a100", "HIT_END"),
  # Map with 3 item when it should have 4
  ("a2000000", "HIT_END"),
  # Map with 1 item when it should have 2
  ("bf00ff", "BAD_BREAK"),
  # Map with 3 item when it should have 4
  ("bf000000ff", "BAD_BREAK"),
  # In addition to not-well-formed, some invalid CBOR
  # Text-based date, with an integer
  ("c000", "BAD_OPT_TAG"),
  # Epoch date, with an byte string
  ("c14133", "BAD_OPT_TAG"),
  # tagged as both epoch and string dates
  ("c1c000", "BAD_OPT_TAG"),
  # big num tagged an int, not a byte string
  ("c200", "BAD_OPT_TAG"),
]

def test_well_formed():
  for v, e in InvalidEncodings:
    try:
      cbor.check_well_formed(bytes.fromhex(v))
      print(v, ' is well formed')
    except cbor.CborDecodingError:
      pass

def test_decode():
  decoder = cbor.Decoder()
  encoder = cbor.Encoder()
  for v, e in InvalidEncodings:
    try:
      val = decoder.decode(bytes.fromhex(v))
      print(v, 'decoded as', val, '(', repr(val), ') reencoded', encoder.encode(val).hex())
      try:
        cbor.check_well_formed(bytes.fromhex(v))
      except cbor.CborDecodingError as ex:
        print(ex)
    except cbor.CborDecodingError:
      pass

if __name__ == "__main__":
  test_well_formed()
  test_decode()
