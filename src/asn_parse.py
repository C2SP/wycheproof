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

import util
import asn

AsnError = asn.AsnError

def parse_int(content: bytes, signed: bool = True) -> int:
  if len(content)==0: return 0
  res = 0
  for x in content:
     res = 256 * res + x
  if signed and content[0] >= 128:
     res -= 256**len(content)
  return res
  
def parse_indefinite(tag: int, b: bytes):
  if not (tag & 0x20):
    raise AsnError("Invalid tag for indefinite encoding")
  if tag == 0x30:
    L = []
    while True:
      if len(b) < 2:
        raise AsnError("missing delimiter of indefinite encoding")
      if b[0] == b[1] == 0:
        return L, b[2:]
      v,b = parse_first(b)
      L.append(v)
  else:
    val = bytes()
    while True:
      if len(b) < 2:
        raise AsnError("missing delimiter of indefinite encoding")
      if b[0] == b[1] == 0:
        return asn.AsnElement(tag - 0x20, val), b[2:]
      v,b = parse_first(b)
      if not isinstance(v, asn.AsnElement):
        raise AsnError("Unexpected element in indefinite encoding")
      val += v.val

def parse_first(b: bytes):
  if len(b) < 2:
    raise AsnError("truncated element")
  # get tag, length and content
  tag = b[0]
  if b[1] == 128:
    return parse_indefinite(tag, b[2:])
  elif b[1] < 128:
    length = b[1]
    offset = 2
  else:
    lengthsize = b[1] - 128
    if lengthsize + 2 > len(b):
      raise AsnError("Not enough bytes for the length")
    length = 0
    for i in range(lengthsize):
      length = 256 * length + b[i+2]
    offset = 2 + lengthsize
  end = offset + length
  if end > len(b):
    raise AsnError("length of element longer than sequence")
  content = b[offset:end]
  remainder = b[end:]
  if tag == 0x01:
    res = asn.Boolean(content)
  elif tag == 0x02:
    res = parse_int(content)
  elif tag == 0x03:
    if len(content) < 1:
      raise AsnError("unused bits in BitString missing")
    unused_bits = content[0]
    if unused_bits >= 8:
      raise AsnError("Number of unused bits too large")
    if unused_bits > 0 and len(content) < 2:
      raise AsnError("Cannot truncate empty BitString")
    if unused_bits > 0:
      content = content[:-1] + bytes([content[-1] & (0xff << unused_bits)])
    res = asn.BitString(content[1:], unused_bits)
  elif tag == 0x04:
    res = asn.OctetString(content)
  elif tag == 0x05:
    if len(content) != 0:
      raise AsnError("NULL must not have any content")
    res = asn.Null()
  elif tag == 0x06:
    res = asn.Oid(content)
  elif tag == asn.UTF8_STRING:
    res = asn.Utf8String(str(content, 'utf8'))
  elif tag == 0x0a:
    res = asn.Enumerated(content)
  elif tag == 0x30:
    res = parse_list(content)
  elif tag == 0x31:
    res = parse_set(content)
  elif tag < 31:
    res = asn.AsnElement(tag, content, description=asn.describe_tag(tag))
  elif 0 <= tag % 32 < 31:
    cls = tag & 0xc0
    if cls in [asn.APPLICATION, asn.CONTEXT_SPECIFIC, asn.PRIVATE]:
      num = tag % 32
      constructed = (tag & asn.CONSTRUCTED) != 0
      try:
        val = parse(content)
        res = asn.Explicit(num, val, cls, constructed)
      except Exception:
        res = asn.AsnElement(tag, content)
    else:
      raise AsnError("Unknown tag:%s content:%s" % (tag, content.hex())) 
  else:
    # TODO: These are long form tags. They should be parsed
    #   better.
    res = asn.AsnElement(tag, content)
  return res, remainder

def parse_list(s: bytes) -> list:
  L = []
  while len(s):
    res, s = parse_first(s)
    L.append(res)
  return L

def parse_set(s: bytes) -> list:
  L = []
  while len(s):
    res, s = parse_first(s)
    L.append(res)
  return asn.Set(L)

def parse(s):
  # TODO: Just allow bytes
  assert isinstance(s, bytearray) or isinstance(s, bytes)
  res, rem = parse_first(s)
  if rem:
    raise AsnError("Unused bytes at the end of element")
  return res

def parse_fromhex(s: str):
  '''
  >>> parse_fromhex('3009020101020102020103')
  [1, 2, 3]
  >>> parse_fromhex('30800201050201060201070000')
  [5, 6, 7]
  '''
  return parse(bytes.fromhex(s))

if __name__ == "__main__":
  import doctest
  doctest.testmod()

