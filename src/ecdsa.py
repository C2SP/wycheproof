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

import group as gp
import ec_key
import ec_groups
from typing import Any, Callable, Optional, List, Union, Tuple
import util
import prand

Group = ec_groups.EcGroup

def truncated_hash(group: Group, digest: bytes) -> int:
  h = int.from_bytes(digest, "big")
  truncate_bits = len(digest) * 8 - group.n.bit_length()
  if truncate_bits > 0:
    h >>= truncate_bits
  return h

def truncated_hash_from_msg(group: Group, md: str, msg: bytes) -> int:
  digest = util.hash(md, msg)
  return truncated_hash(group, digest)

# TODO: Add class EcdsaSignature
#   contains, r, s, curve, hash, pubkey, is_valid (expected to be valid),
#   verified (is_valid has been verified)
#   methods: encode_asn, encode_p1363

class EcdsaSigner:
  @util.type_check
  def __init__(self,
               priv: ec_key.EcPrivateKey,
               verify_signatures: bool = True,
               normalize: bool = False):
    self.priv = priv
    self.verifier = EcdsaVerifier(priv.public())
    self.verify_signatures = verify_signatures

  def get_k(self, label: str=None):
    """Returns the value k used for the signature generation.
    
    Args:
      label: if this parameter None then a random k is returned. Otherwise
        k is deterministic and depends on the label and the priavate key.
    """
    if label is None:
      label = os.urandom(32).hex()
    return prand.randrange(1, self.priv.group.n, str(self.priv.s), label)

  def sign_hash_deterministic(self,
                              digest: bytes,
                              salt=""):
    '''Returns a deterministic signature for hash of a message.

    Most of the test vectors use deterministic signatures, since
    pseudorandom signatures allows to check differences during
    code reviews.

    Args:
      digest: the hash of the message to sign
      salt: a salt that can be used to randomize the signature
    Returns:
      a signature as a pair of integers [r,s]
    '''
    group = self.priv.group
    h = truncated_hash(group, digest)
    cnt = 0
    while True:
      label = digest.hex() + salt + str(cnt)
      cnt += 1
      k = self.get_k(label)
      v = k * group.generator()
      r = int(v.affine_x()) % group.n
      if r == 0:
        continue
      s = pow(k, -1, group.n) * (h + r * self.priv.s) % group.n
      if s == 0:
        continue
      if normalize and 2*s > group.n:
        s = group.n - s
      if self.verify_signatures:
        assert self.verifier.verify(r, s, digest)
      return [r,s]


  @util.type_check
  def sign(self,
           md: str,
           message: bytes):
    '''Returns a randomized signature.

    Most of the test vectors use pseudorandom signatures, since
    pseudorandom signatures allows to check differences during
    code reviews.

    Args:
      md: the hash function (e.g. 'SHA-256')
      message: the message to sign
    Returns:
      a signature as a pair of integers [r,s]
    '''
    group = self.priv.group
    digest = util.hash(md, message)
    h = truncated_hash(group, digest)
    while True:
      k = self.get_k()
      v = k * group.generator()
      r = int(v.affine_x()) % group.n
      if r == 0:
        continue
      s = pow(k, -1, group.n) * (h + r * self.priv.s) % group.n
      if s == 0:
        continue
      if self.verify_signatures:
        assert self.verifier.verify_hash(r, s, digest)
      return [r, s]


class EcdsaVerifier:

  def __init__(self, public_key: ec_key.EcPublicKey):
    self.public_key = public_key
    if self.public_key.w is None:
      raise ValueError("w is unknown")
    wx, wy = self.public_key.affine()
    self.pub_point = self.public_key.group.get_point(wx, wy)


  @util.type_check
  def verify_hash(self, r: int, s: int, digest: bytes) -> bool:
    """Verifies an ECDSA signatures given the hash of the message.

    Args:
      r:  the r value of the signature
      s:  the s value of the signature
      digest: the (untruncated) hash of the message
    Returns:
      True if the signature is valid, False otherwise
    """
    group = self.public_key.group
    n = group.n
    if r <= 0 or r >= n or s <= 0 or s>=n:
      return False
    h = truncated_hash(group, digest)
    w = pow(s, -1, n)
    u1 = h * w % n
    u2 = r * w % n
    pt = u1 * group.generator() + u2 * self.pub_point
    if not pt:
      return False
    return int(pt.affine_x()) % n == r
