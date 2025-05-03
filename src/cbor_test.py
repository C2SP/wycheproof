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
from cbor import Indefinite, Simple, Tag, Float

Infinity = float("infinity")
NaN = float("nan")
undefined = Simple(23)
h = bytes.fromhex

# Tests from RFC 7049 (updated in RFC 8949)
TestVectors = [
    (0, "00"),
    (1, "01"),
    (10, "0a"),
    (23, "17"),
    (24, "1818"),
    (25, "1819"),
    (100, "1864"),
    (1000, "1903e8"),
    (1000000, "1a000f4240"),
    (1000000000000, "1b000000e8d4a51000"),
    (18446744073709551615, "1bffffffffffffffff"),
    (18446744073709551616, "c249010000000000000000"), # see errata for 2.4.2
    (-18446744073709551616, "3bffffffffffffffff"),
    (-18446744073709551617, "c349010000000000000000"),
    (-1, "20"),
    (-10, "29"),
    (-100, "3863"),
    (-1000, "3903e7"),
    (Float(0.0, 16), "f90000"),
    (Float(-0.0, 16), "f98000"),
    (Float(1.0, 16), "f93c00"),
    (Float(1.1, 64), "fb3ff199999999999a"),
    (Float(1.5, 16), "f93e00"),
    (Float(65504.0, 16), "f97bff"),
    (Float(100000.0, 32), "fa47c35000"),
    (Float(3.4028234663852886e+38, 32), "fa7f7fffff"),
    (Float(1.0e+300, 64), "fb7e37e43c8800759c"),
    (Float(5.960464477539063e-8, 16), "f90001"),
    (Float(0.00006103515625, 16), "f90400"),
    (Float(-4.0, 16), "f9c400"),
    (Float(-4.1, 64), "fbc010666666666666"),
    (Float(Infinity, 16), "f97c00"),
    (Float(NaN, 16), "f97e00"),
    (Float(-Infinity, 16), "f9fc00"),
    (Float(Infinity, 32), "fa7f800000"),
    (Float(NaN, 32), "fa7fc00000"),
    (Float(-Infinity, 32), "faff800000"),
    (Float(Infinity, 64), "fb7ff0000000000000"),
    (Float(NaN, 64), "fb7ff8000000000000"),
    (Float(-Infinity, 64), "fbfff0000000000000"),
    (False, "f4"),
    (True, "f5"),
    (None, "f6"),
    (undefined, "f7"),
    (Simple(16), "f0"),
    (Simple(255), "f8ff"),
    (Tag(0, "2013-03-21T20:04:00Z"),
      "c074323031332d30332d32315432303a30343a30305a"),
    (Tag(1, 1363896240), "c11a514b67b0"),
    (Tag(1, 1363896240.5), "c1fb41d452d9ec200000"),
    (cbor.DateTimeString("2013-03-21T20:04:00Z"),
      "c074323031332d30332d32315432303a30343a30305a"),
    (cbor.DateTimeNumeric(1363896240),  "c11a514b67b0"),
    (cbor.DateTimeNumeric(1363896240.5), "c1fb41d452d9ec200000"),
    (Tag(23, h("01020304")), "d74401020304"),
    (Tag(24, h("6449455446")), "d818456449455446"),
    (Tag(32, "http://www.example.com"), "d82076687474703a2f2f7777772e6578"
     "616d706c652e636f6d"),
    (h(""), "40"),
    (h("01020304"), "4401020304"),
    ("", "60"),
    ("a", "6161"),
    ("IETF", "6449455446"),
    ("\"\\", "62225c"),
    ("\u00fc", "62c3bc"),
    ("\u6c34", "63e6b0b4"),
    # ("\ud800\udd51", "64f0908591"),
    ([], "80"),
    ([1, 2, 3], "83010203"),
    ([1, [2, 3], [4, 5]], "8301820203820405"),
    (list(range(1, 26)),
     "98190102030405060708090a0b0c0d0e0f101112131415161718181819"),
    ({}, "a0"),
    ({
        1: 2,
        3: 4
    }, "a201020304"),
    ({
        "a": 1,
        "b": [2, 3]
    }, "a26161016162820203"),
    (["a", {
        "b": "c"
    }], "826161a161626163"),
    ({
        "a": "A",
        "b": "B",
        "c": "C",
        "d": "D",
        "e": "E"
    }, "a56161614161626142616361436164614461656145"),
    (Indefinite((h("0102"), h("030405"))), "5f42010243030405ff"),
    (Indefinite(("strea", "ming")), "7f657374726561646d696e67ff"),
    (Indefinite([]), "9fff"),
    (Indefinite([1, [2, 3], Indefinite([4, 5])]), "9f018202039f0405ffff"),
    (Indefinite([1, [2, 3], [4, 5]]), "9f01820203820405ff"),
    ([1, [2, 3], Indefinite([4, 5])], "83018202039f0405ff"),
    ([1, Indefinite([2, 3]), [4, 5]], "83019f0203ff820405"),
    (Indefinite(list(range(1, 26))),
     "9f0102030405060708090a0b0c0d0e0f101112131415161718181819ff"),
    (Indefinite({
        "a": 1,
        "b": Indefinite([2, 3])
    }), "bf61610161629f0203ffff"),
    (["a", Indefinite({"b": "c"})], "826161bf61626163ff"),
    (Indefinite({
        "Fun": True,
        "Amt": -2
    }), "bf6346756ef563416d7421ff"),
    (cbor.BigDecimal(-2, 27315),"c48221196ab3"), # Section 2.4.3
    (cbor.BigFloat(-1, 3), "c5822003"), # Section 2.4.3
]

NotWellFormed = [
  ("f818", "This was an incorrect test vector in RFC 7049 for simple(24)"),
]

# A list of potentially equivalent items.
Equivalent = [
  ([1, cbor.Float(1, 16), cbor.Float(1, 32), cbor.Float(1, 64),
   cbor.BigDecimal(1, 0), cbor.BigFloat(1, 0)], "Representations of 1"),

def test(log: bool = False):
  cnt = 0
  enc = cbor.Encoder()
  for v, e in TestVectors:
    try:
      encoded = enc.encode(v)
      if encoded is None:
        print("Got None for", v)
        continue
      if encoded.hex() == e:
        cnt += 1
      else:
        if log:
          print(repr(v), encoded.hex(), e)
    except cbor.CborEncodingError:
      print("did not encode:", v)
  print(cnt, "out of", len(TestVectors))
  assert cnt == len(TestVectors)

def test_decode(log: bool=False):
  cnt = 0
  dec = cbor.Decoder(keep_encoding=True)
  enc = cbor.Encoder()
  for v, e in TestVectors:
    try:
      decoded = dec.decode(bytes.fromhex(e))
      if decoded == v:
        cnt += 1
      else:
        # There are a number of reasons why decoded may not be equal to v:
        #  *  NaN != NaN
        #  *  the use of distinct data types such as float and Float
        # In these cases the result is encoded again an checked against its
        # input.
        print(repr(v), repr(decoded), e)
        encode_again = enc.encode(decoded)
        if encode_again.hex() == e:
          cnt += 1
        else:
          print("*** wrong encoding", encode_again.hex(), e)
    except cbor.CborDecodingError as ex:
      print("did not decode:", v, e, ex)
  print(cnt, "out of", len(TestVectors))
  assert cnt == len(TestVectors)

def test_well_formed():
  errors = 0
  for v, e in TestVectors:
    try:
      cbor.check_well_formed(bytes.fromhex(e))
    except cbor.CborDecodingError as ex:
      print("not well formed:", v, e, ex)
      errors += 1
  assert errors == 0

def test_not_well_formed():
  errors = 0
  for e, explanation in NotWellFormed:
    try:
      cbor.check_well_formed(bytes.fromhex(e))
      print("accepting:", e, explanation)
      errors += 1
    except cbor.CborDecodingError as ex:
      pass
  assert errors == 0

if __name__ == "__main__":
  test()
  test_decode(log=True)
  test_well_formed()
  test_not_well_formed()
