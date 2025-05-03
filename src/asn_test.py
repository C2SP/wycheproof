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


# Decorator
TESTS = []
def Test(f):
  TESTS.append(f)
  return f

DER_ENCODINGS = [
    # boolean
    (True, '010101'),
    (False, '010100'),
    # integer
    (0, '020100'),
    (123, '02017b'),
    (127, '02017f'),
    (128, '02020080'),
    (-1, '0201ff'),
    (-128, '020180'),
    (-129, '0202ff7f'),
    (-256, '0202ff00'),
    (3**40, '020900a8b8b452291fe821'),
    # bit string
    (asn.BitString([0,1]), '0309003006020100020101'),
    # octet string
    (asn.OctetString(bytes.fromhex("00ff")), '040200ff'),
    (asn.OctetStringFromInt(12345, 2), '04023039'),
    # null
    (asn.Null(), '0500'),
    # float
    (0.125, '090380fd01'),
    (0.5, '090380ff01'),
    (-2.5, '090380fffb'),
    (float('nan'), '090142'),
    # list
    ([], '3000'),
    ([1, 2, 3], '3009020101020102020103'),
    # set
    # Utf8String
    (asn.Utf8String('123'), '0c03313233'),
  ]

@Test
def test_der():
  errors = 0
  for struct, der_encoded in DER_ENCODINGS:
    encoded = asn.encode(struct).hex()
    if encoded != der_encoded:
      print(f"invalid encoding for {struct} \n"
            f"expected:{der_encoded}, got: {encoded}")
      errors += 1
  assert not errors

def all_tests():
  for test in TESTS:
    print('== %s ==' % test.__name__)
    test()

if __name__ == "__main__":
  all_tests()

