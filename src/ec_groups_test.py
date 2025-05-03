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

import ec
import ec_groups
import oid_util

def test_completeness():
  """Tests that named curves have a name."""
  print("===== test_completeness =====")
  curves = ec_groups.all_curves
  for name in dir(ec_groups):
    val = getattr(ec_groups, name)
    if isinstance(val, ec_groups.EcNamedGroup):
      if val not in curves:
        raise AssertionError("missing curve:" + name)
    elif isinstance(val, ec_groups.Isomorphism):
      if val not in ec_groups.isomorphisms:
        raise AssertionError("missing isomorphism" + name)


def test_infinity():
  """Checks the order of the curve.
  
  This test catches a large number of typos in the parameters
  of the curve."""
  print("===== test_infinitiy =====")
  for c in ec_groups.all_curves:
    assert not c.generator() * c.n


def test_params():
  """Simple checks for the parameters of the curves.
  
  E.g. the order of a prime order curve is expected to be prime.
  """
  print("===== test_params =====")
  # Some simple checks for incorrect parameters
  for c in ec_groups.all_prime_order_curves:
    assert pow(3, c.p, c.p) == 3
    assert pow(3, c.n, c.n) == 3
    assert not c.generator() * c.n


def test_isomorphisms():
  """Checks the isomorphisms between curves.
  
  Some curves (i.e. the brainpool curves) have isomorphic curves.
  This can be checked.
  """
  print("===== test_isomorphisms =====")
  # Sanity check for group isomorphisms
  for i in ec_groups.isomorphisms:
    ga = i.A.generator()
    gb = i.B.generator()
    assert i.fromAtoB(ga) == gb
    assert i.fromBtoA(gb) == ga
    assert i.fromAtoB(12345 * ga) == 12345 * gb


def test_oid():
  """Compares OIDs against a table extracted from RFCs.
  
  Some curves have alternative names. Hence this test simply prints
  curves with non-matching names."""
  print("===== test_oid =====")
  for c in ec_groups.all_curves:
    oid = c.get_oid()
    if not oid:
      # Not a bug.
      print(c.name, "has no OID")
      continue
    oid_util.lookup(oid)
    if not oid.description:
      print(c.name, "OID has no description")
      continue
    if c.name != oid.description:
      # A number of curves have multiple names. E.g.,
      # Alternative name: secp256r1 prime256v1 oid = 1.2.840.10045.3.1.7
      # Alternative name: secp192r1 prime192v1 oid = 1.2.840.10045.3.1.1
      print("Alternative name:", c.name, oid.description, "oid =", str(oid))
    print(c.name, oid.reference)

if __name__ == "__main__":
  ec.EcVerify = True
  test_completeness()
  test_params()
  test_infinity()
  test_isomorphisms()
  test_oid()
