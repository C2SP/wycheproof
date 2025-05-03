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
import asn_parser
import asn_ktv

# Decorator
TESTS = []
def Test(f):
  TESTS.append(f)
  return f

@Test
def test_sample(log = False):
  test = (
      '30819f300d06092a864886f70d010101050003818d00308189028181009e6233'
      '7ef7d4fabec2561bb45a18a362022b23666571bbc762c1c717a14a46d8f58119'
      '072aa26245e71fc6945540335163798fcbdea04b3104ee23f2c3874bbfb3e7e0'
      'c1ba5f1fca909265274414db6957a5eb668e0e36a388784355d528e51a6a4a9a'
      '9c6b6ab912812a268dac9dcacf1c13507768e63b1f82f8af29c3786a170203010001')
  parsed = asn_parser.parse(bytes.fromhex(test))
  if log:
    print(parsed)
  assert asn.encode_hex(parsed) == test


def test_encode_decode(ktvs):
  errors = 0
  for ktv in ktvs:
    case = f"case {repr(ktv.encoding)}\nComment: {ktv.comment}"
    encoding = bytes.fromhex(ktv.encoding)
    der = bytes.fromhex(ktv.der)
    try:
      parsed = asn_parser.parse(encoding)
    except asn.AsnError as ex:
      print(f"Could not parse {case}\nException: {ex}")
      errors += 1
      continue
    der2 = asn.encode(parsed)
    if der != der2:
      print(f"wrong encoding of {case}:\n"
            f"got      {repr(der2.hex())}\n"
            f"expected {repr(der.hex())}")
      errors += 1
  if errors:
    print(f"{errors} errors")
  # assert errors == 0

def test_invalid(ktvs):
  errors = 0
  for ktv in ktvs:
    encoding = bytes.fromhex(ktv.encoding)
    case = f"case {repr(ktv.encoding)}\nComment: {ktv.comment}"
    try:
      asn_parser.parse(encoding)
      print(f"parsed invalid {case}")
      errors += 1
    except asn.AsnError:
      pass
    except Exception as ex:
      print(f"wrong exception for {case}\n"
            f"expected AsnError, but got {repr(ex)}")
      errors += 1
  if errors:
    print(f"{errors} errors found")
  # assert errors == 0

@Test
def test_der():
  test_encode_decode(asn_ktv.DER_KTV)

@Test
def test_ber():
  test_encode_decode(asn_ktv.BER_KTV)

@Test
def test_invalid_ktv():
  test_invalid(asn_ktv.INVALID_BER_KTV)


if __name__ == "__main__":
  for test in TESTS:
    print('== %s ==' % test.__name__)
    test()

