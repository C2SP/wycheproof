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

# python3

import typing
import util

# only used in this module
def nodes2bytes(nodes: typing.List[int]) -> bytes:
  assert len(nodes) >= 2
  # TODO: there are additional rules for encoding oids where the
  # second node is larger than 39. Documentation is a bit sparse.
  # E.g. /Joint-ISO-ITU-T/Example has an OID of 2.999
  # I have no idea how to encode this.
  assert 0 <= nodes[0] < 3
  assert 0 <= nodes[1] < 40
  b = bytearray()
  b.append(nodes[0] * 40 + nodes[1])
  for x in nodes[2:]:
    # variable length encoded
    x,q = divmod(x, 128)
    v = bytearray()
    v.append(q)
    while x:
      x,q = divmod(x, 128)
      v.append(q + 128)
    b += v[::-1]
  return bytes(b)

# used in asn_fuzzing.py
def nodes2hex(nodes: typing.List[int]) -> str:
  return nodes2bytes(nodes).hex()

# used in asn_fuzzing.py
def bytes2nodes(ba: bytes) -> typing.List[int]:
  if not ba:
    raise ValueError("empty OID")
  nodes = list(divmod(ba[0], 40))
  next = 0
  for b in ba[1:]:
    if b < 128:
      nodes.append(next * 128 + b)
      next = 0
    else:
      next = 128 * next + (b - 128)
  if next:
    raise ValueError("truncated OID")
  return nodes

class Oid:
  @util.type_check
  def __init__(self,
               nodes: typing.List[int],
               description: typing.Optional[str] = None,
               reference: typing.Optional[str] = None):
    """
    Constructs an OID.

    Args:
      nodes: the list of nodes defining the OID
      description: the ASN name of the OID
      reference: A description where the OID is defined
    """
    self.nodes = nodes
    self.description = description
    self.reference = reference


  def __str__(self):
    return '.'.join(str(x) for x in self.nodes)

  def __repr__(self):
    if self.reference:
      return 'Oid(%s, %s, %s)' % (repr(self.nodes), repr(self.description),
                                  repr(self.reference))
    elif self.description:
      return 'Oid(%s, %s)' % (repr(self.nodes), repr(self.description))
    else:
      return 'Oid(%s)' % repr(self.nodes)

  def __add__(self, nodes: typing.List[int]) -> typing.List[int]:
    '''Allows iterative definitions like
       pkcs_1 = Oid([1,2,840,113549,1,1], "pkcs_1")
       rsa_encryption = Oid(pkcs_1 + [1], "rsaEncryption")
    '''
    return self.nodes + nodes

  def bytes(self):
    return nodes2bytes(self.nodes)

  def hex(self):
    return self.bytes().hex()

  def json(self):
    return str(self)

# Factory methods
def frombytes(ba: bytes,
              description: typing.Optional[str] = None,
              reference: typing.Optional[str] = None) -> Oid:
  """Creates an Oid from an ASN encoding.

      E.g. oid_sha256 = oid.frombytes(bytes.fromhex("608648016503040201"))
   """
  return Oid(bytes2nodes(ba), description, reference)

def fromstr(val: str,
            description: typing.Optional[str] = None,
            reference: typing.Optional[str] = None) -> Oid:
  """Create an Oid from an string.

      E.g. oid_sha256 = oid.fromstr("2.16.840.1.101.3.4.2.1")
   """
  nodes = [int(x) for x in val.split(".")]
  return Oid(nodes, description, reference)

HASHES = [
  ("MD2", "2a864886f70d0202", "1.2.840.113549.2.2"),
  ("MD5", "2a864886f70d0205", "1.2.840.113549.2.5"),
  ("SHA-1", "2b0e03021a", "1.3.14.3.2.26"),
  # https://csrc.nist.gov/projects/computer-security-objects-register/algorithm-registration#Hash
  ("SHA-256", "608648016503040201", "2.16.840.1.101.3.4.2.1"),
  ("SHA-384", "608648016503040202", "2.16.840.1.101.3.4.2.2"),
  ("SHA-512", "608648016503040203", "2.16.840.1.101.3.4.2.3"),
  ("SHA-224", "608648016503040204", "2.16.840.1.101.3.4.2.4"),
  # Defined in RFC 8017.
  ("SHA-512/224", "608648016503040205", "2.16.840.1.101.3.4.2.5"),
  ("SHA-512/256", "608648016503040206", "2.16.840.1.101.3.4.2.6"),
  ("SHA3-224", "608648016503040207", "2.16.840.1.101.3.4.2.7"),
  ("SHA3-256", "608648016503040208", "2.16.840.1.101.3.4.2.8"),
  ("SHA3-384", "608648016503040209", "2.16.840.1.101.3.4.2.9"),
  ("SHA3-512", "60864801650304020a", "2.16.840.1.101.3.4.2.10"),
  ("SHAKE128", "60864801650304020b", "2.16.840.1.101.3.4.2.11"),
  ("SHAKE256", "60864801650304020c", "2.16.840.1.101.3.4.2.12"),
]

def oid_for_hash(name: str) -> bytes:
  for n, oid, _ in HASHES:
    if n == name: return bytes.fromhex(oid)
  raise Exception("unknown:" + name)

def test():
  errors = 0
  for name, hex_str, readable in HASHES:
    oid1 = fromstr(readable)
    oid2 = frombytes(bytes.fromhex(hex_str))
    if oid1.nodes != oid2.nodes or oid1.hex() != hex_str:
      errors += 1
      print(oid1.nodes)
      print(oid2.nodes)
      print(oid1.hex())
      print(oid2.hex())
  assert not errors

if __name__ == "__main__":
  test()
