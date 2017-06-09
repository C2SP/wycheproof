# Copyright 2017 Google Inc. All Rights Reserved.
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
# ==============================================================================
#
# Note(quannguyen): the current implementation is not complete, but it's enough
# for me to get started.
"""Implements Elliptic Curve Digital Signature Algorithm (ECDSA)."""
from sage.all_cmdline import inverse_mod
import util


def _truncate_hash(curve, digest):
  h = util.bytes2int(digest)
  return h >> max(0, h.bit_length() - int(curve.n).bit_length())


def ecdsa_sign_hash(curve, digest, priv_key):
  """Computes ECDSA signature."""
  z = _truncate_hash(curve, digest)
  n = int(curve.n)
  while True:
    k = util.randint(1, n)
    (x1, _, _) = k * curve.g
    r = int(x1) % n
    if r == 0:
      continue
    s = (inverse_mod(k, n) * (z + priv_key * r)) % n
    if s == 0:
      continue
    return (r, s)


def ecdsa_verify_hash(curve, digest, qx, qy, r, s):
  """Verifies ECDSA signature."""
  n = int(curve.n)
  if not (1 <= r < n and 1 <= s < n and util.isint(r) and util.isint(s)):
    return False
  z = _truncate_hash(curve, digest)
  q = curve.ec(qx, qy)
  w = inverse_mod(s, curve.n)
  u1 = (z * w) % n
  u2 = (r * w) % n
  (x1, _, _) = u1 * curve.g + u2 * q
  return int(x1) % n == r % n
