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

def i2osp(n: int, m: int) -> bytes:
  """Computes the function I2OSP defined in RFC 3447 Section 4.1.

  I2OSP converts a positive integer into an octet string using
  bigendian representation.

  Args:
    n: the integer to convert
    m: the number of bytes to use

  Returns:
    n converted to an octet string (rsp. just bytes)
  Raises:
    OverflowError: if n is negative or too large
  """
  return n.to_bytes(m, "big")


def os2ip(b: bytes) -> int:
  """Computes the function OS2ISP defined in RFC 3447 Section 4.2.

  OS2ISP converts an octet string into a positive integer using
  bigendian representation.

  Args:
    b: the octet string to converted to an integer.

  Returns:
    the octet string converted to an integer.
  """
  return int.from_bytes(b, "big")
