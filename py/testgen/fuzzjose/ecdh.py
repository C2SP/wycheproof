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
# Run as:
#     sage -python ecdh.py
#
# Note(quannguyen): the current implementation is not complete, but it's enough
# for me to get started.
"""Implements Elliptic Curve Diffie-Hellman(ECDH)."""

import util


def compute_shared_secret(curve, priv, qx, qy):
  """Computes shared secret based on our private key and peer's public key."""
  # The constructor checks whether (qx, qy) is on the curve.
  q = curve.ec(qx, qy)
  (sx, _, _) = priv * q
  # Pad zeros to sx to curve's size bytes.
  size = (int(curve.n).bit_length() + 7) // 8
  return util.int2bytes(int(sx), size)
