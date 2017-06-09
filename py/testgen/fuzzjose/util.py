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
"""Utility for common tasks."""

import hashlib
from os import urandom


def bytes2int(bs):
  """Transforms big-endian bytes array to integer."""
  res = 0
  for b in bs:
    res = res * 256 + ord(b)
  return res


def int2bytes(x, size):
  """Transforms integer to big-endian bytes array of length size."""
  return ''.join([chr((x >> ((size - i - 1) * 8)) % 256) for i in range(size)])


def randint(x, y):
  """Generates a random integer in range [x, y)."""
  size = (y - x).bit_length() / 8  + 8  # add 8 to reduce bias.
  res = 0
  for b in urandom(size):
    res = res * 256 + ord(b)
  return x + res % (y - x)


def compute_hash(hash_name, msg):
  if hash_name == 'SHA-256':
    md = hashlib.sha256()
  elif hash_name == 'SHA-384':
    md = hashlib.sha384()
  elif hash_name == 'SHA-512':
    md = hashlib.sha512()
  md.update(msg)
  return md.digest()


def isint(x):
  return isinstance(x, int) or isinstance(x, long)


