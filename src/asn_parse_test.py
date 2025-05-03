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
import asn_ktv
import asn_parse
import asn_parser

def parse(encoding: bytes, old:bool = False):
  if old:
    return asn_parse.parse(encoding)
  else:
    return asn_parser.AsnParser(strict=True).parse(encoding)

def test_encode_decode(ktvs):
  errors = 0
  for ktv in ktvs:
    encoding = bytes.fromhex(ktv.encoding)
    print(ktv.der)
    der = bytes.fromhex(ktv.der)
    try:
      parsed = parse(encoding)
    except asn.AsnError as ex:
      print(f"Could not parse: {ktv.encoding} {ex}: {ktv.comment}")
      errors += 1
      continue
    der2 = asn.encode(parsed)
    if der != der2:
      print(f"expected: {der.hex()} but got {der2.hex()}: {ktv.comment}")
      errors += 1
  assert errors == 0

def test_invalid(ktvs):
  errors = 0
  for ktv in ktvs:
    encoding = bytes.fromhex(ktv.encoding)
    try:
      parse(encoding)
      print(f"parsed {ktv.encoding}: {ktv.comment}")
      errors += 1
    except asn.AsnError:
      pass
    except Exception as ex:
      print(f"expected AsnError, but got {repr(ex)}")
      errors += 1
  assert errors == 0

if __name__ == "__main__":
  test_encode_decode(asn_ktv.DER_KTV)
  test_encode_decode(asn_ktv.BER_KTV)
  test_invalid(asn_ktv.INVALID_BER_KTV)
