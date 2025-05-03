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

import kdf
import util
from typing import Union


def _as_bytes(s: Union[bytes, bytearray, str]) -> bytes:
  """Converts a string or bytearray into bytes.

  This function is a leftover from python2 to python3 conversion
  and is deprecated.

  Args:
    s: the input to convert

  Returns:
    the input as bytes
  """
  if isinstance(s, str):
    return bytes(ord(x) for x in s)
  elif isinstance(s, bytearray):
    return bytes(s)
  else:
    return s


def randbytes(cnt: int,
              seed: Union[bytes, bytearray, str] = b"",
              label: Union[bytes, bytearray, str] = b"") -> bytes:
  """Returns pseudorandom bytes.

  This function is deterministic.

  Args:
    cnt: the number of bytes to generate
    seed: the seed for the generation
    label: an additional label used in the generation of the bytes

  Returns:
    the pseudorandom bytes
  """
  return kdf.kdfX963Sha1(_as_bytes(seed), _as_bytes(label), cnt)


def randrange(a: int,
              b: int,
              seed: Union[bytes, bytearray, str] = b"",
              label: Union[bytes, bytearray, str] = b"") -> int:
  """Returns a pseudorandom integer.

  This function is deterministic.
  Args:
    a: the lower bound (inclusive)
    b: the upper bound (exclusive)
    seed: the seed of the pseudorandom generator (str or bytes)
    label: and additional label that is used to derive the random bytes

  Returns:
    an integer in range(a, b).
  """
  d = b - a
  assert d > 0
  ba = 8 + d.bit_length() // 8
  res = 0
  for x in kdf.kdfX963Sha1(_as_bytes(seed), _as_bytes(label), ba):
    res = (res << 8) + x
  return a + res % d
