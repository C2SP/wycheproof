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

from typing import Optional
from asn1crypto.core import (Sequence, OctetString, BitString, OctetBitString,
    Integer, ObjectIdentifier, Any, Null, Boolean, Set,
    UTF8String, VisibleString, PrintableString)

ASN_NULL = "ASN_NULL" # used to distinguish between ASN-NULL and undefined
UNDEFINED = "UNDEFINED" 

K93 = "Kaliski, A layman's guide to a subset of ASN.1, DER, and BER, 1993"
# Also defines CER, which is an ASN encoding that uses indefinite encoding
# rules.
X690 = "ITU-T, X 690"

class Ktv:
  def __init__(
      self,
      encoding: str,
      der: Optional[str] = None,
      schema = None,
      native = None,
      ref: Optional[str] = None,
      section: Optional[str] = None,
      comment: Optional[str] = None):
    """Test vector for ASN encoding.

    Args:
      encoding: the encoding to test
      der: equivalent DER encoding if encoding is valid BER, None otherwise.
      schema: ans1crypto schema for the ASN.
      native: equivalent native python value (needs definition)
      ref: a reference for the KTV.
      section: a section in the reference
      comment: additional comment
    """
    self.encoding = encoding
    self.der = der
    self.schema = schema
    self.native = native
    self.ref = ref
    self.section = section
    self.comment = comment

def DerKtv(      
      encoding: str,
      schema = None,
      primitive = None,
      ref: Optional[str] = None,
      section: Optional[str] = None,
      comment: Optional[str] = None):
  return Ktv(encoding, encoding, schema, primitive, ref, section, comment)

DER_KTV = [
  DerKtv("020100", Integer, 0, K93, "5.7"),
  DerKtv("02017f", Integer, 127, K93, "5.7"),
  DerKtv("02020080", Integer, 128, K93, "5.7"),
  DerKtv("02020100", Integer, 256, K93, "5.7"),
  DerKtv("020180", Integer, -128, K93, "5.7"),
  DerKtv("0202ff7f", Integer, -129, K93, "5.7"),
  DerKtv("0304066e5dc0", BitString, "011011100101110111", K93, "5.4"),
  DerKtv("0500", Null, ASN_NULL, K93, "5.8"),
  DerKtv("04080123456789abcdef", OctetString, bytes.fromhex("0123456789abcdef"),
         K93, "5.10"),
]

# Valid BER encodings.
BER_KTV = [
  Ktv("0304066e5de0", "0304066e5dc0", BitString, "011011100101110111",
         K93, "5.4", "padding need not be zero"),
  Ktv("23090303006e5d030206c0","0304066e5dc0", BitString,
         "011011100101110111", K93, "5.4", "constructed"),
  Ktv("23800303006e5d030206c00000","0304066e5dc0", BitString,
         "011011100101110111", None, None, "indefinite-length, constructed"),
  Ktv("058100", "0500", Null, ASN_NULL, K93, "5.8",
      "long form encoding of NULL"),
  Ktv("0481080123456789abcdef", "04080123456789abcdef",
      OctetString, bytes.fromhex("0123456789abcdef"),
      K93, "5.10", "long form encoding"),
  Ktv("240c040401234567040489abcdef", "04080123456789abcdef",
      OctetString, bytes.fromhex("0123456789abcdef"),
      K93, "5.10", "constructed"),
  Ktv("2480040401234567040489abcdef0000", "04080123456789abcdef",
      OctetString, bytes.fromhex("0123456789abcdef"),
      K93, "5.10", "indefinite length constructed"),
  Ktv("0101ff", "010101", Boolean, True, X690, "8.2",
      "Any nonzero value represents True"),
  Ktv("02840000000105", "020105", Integer, 5, X690, "8.1.3",
      "The long form encoding may use more bytes for the length than needed"),
  Ktv("30800201010201020000", "3006020101020102", Sequence, [1,2],
      None, None, "indefinite length encoding of sequence"),
  Ktv("068109608648016503040201", "0609608648016503040201",
      ObjectIdentifier, None, None, None,
      "Long form encoding of OID"),
  # The example in the X690 standard uses octet strings to construct a
  # visible string. It is unclear to me if that is valid or a typo.
  Ktv("3a09040365666704026869", "1a056566676869", VisibleString,
      X690, "8.21.5", "Constructed string"),
  Ktv("3309130365666713026869", "13056566676869", PrintableString,
      K93, "5.11")
]

def InvalidKtv(asn: str,
               schema = None,
               reference: Optional[str] = None,
               section: Optional[str] = None,
               comment: Optional[str] = None):
  return Ktv(asn, None, schema, None, reference, section, comment)

# Invalid BER encodings:
# Encoding rules generally define rules for an encoder.
# It may be unclear if a decoder could be more lax and accept additional
# encodings. Hence, I'm collecting references where this is explicitly spelled
# out:
# E.g., X 690 defines in the summary that all encoding rules also apply for the
# decoder.
# References refer to a reference that appears to imply that the test vector
# is invalid.
INVALID_BER_KTV = [
  InvalidKtv("0308066e5d00", BitString, X690, "8.6",
      "Number of unused bits must be in the range 0..7"),
  InvalidKtv("2309030301066e030204c0",BitString, X690, "8.6",
      "All parts of a constructed Bitstring have a length divisible by 8, "
      "except possibly the last part"),
  InvalidKtv("2309020300066e030204c0", BitString, X690, "8.6",
      "The tags of the parts of a constructed BitString are always 3"),
  InvalidKtv("240c030401234567040489abcdef", OctetString, X690, "8.7",
      "The tags of the parts of a constructed OctetString are always 4."),
  InvalidKtv("0100", Boolean, X690, "8.2.1",
      "The length of a boolean must be one octet"),
  InvalidKtv("01020000",Boolean, X690, "8.2.1",
      "The length of a boolean must be one octet"),
  InvalidKtv("21021000", Boolean, X690, "8.2.1",
      "Booleans are primitive"),
  InvalidKtv("02ff" + "00"*126 + "0100", Integer,
      X690, "8.1.3", "length 127 is not valid for long form encoding"),
  InvalidKtv("02020001", Integer, X690, "8.3",
      "Integer encodings should use the minimal number of bytes"),
  InvalidKtv("0200", Integer, X690, "8.3",
      "Length of integer should be at least 1"),
  InvalidKtv("2203020101", Integer, X690, "8.3",
      "Integers are primitive"),
  InvalidKtv("020400000001", Integer, X690, "8.3",
      "Integers use a minimal number of bytes"),
  InvalidKtv("0580", Null, K93, "3.1",
      "The minimal length of the long form length is two bytes"),
  InvalidKtv("050100", Null, X690, "8.8",
      comment="Null does not have any content"),
  InvalidKtv("2500", Null, X690, "8.8",
      "The encoding of Null should be primitive"),
  InvalidKtv("25800000", Null, X690, "8.8",
      "The encoding of Null should be primitive"),
  InvalidKtv("1000", Sequence, X690, "8.9",
      "A sequence is constructed"),
  InvalidKtv("1100", Set, X690, "8.10",
      "A set is constructed"),
  InvalidKtv("260b0609608648016503040201",
      ObjectIdentifier, X690, "8.19", 
      "OIDs are primitive"),
]

# Test cases for which I don't have a good reference 
UNKNOWN_ASN_KTV = [
  Ktv("0580", "0500", Null, ASN_NULL, None, "invalid encoding of NULL"),
]


# TODO: Add more samples to ensure the following rules:
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
#   Sequence is constructed (done)
# Section 8.10:
#   Set is constructed
#   Order does not matter (but there is a definition for BER encoding)
# Section 8.19:
#   OIDs are primitive (done)
#   ... check rules for OID representation
# Section 8.20:
#   relative OID, don't know about this    
# 
