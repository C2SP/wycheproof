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

from pyasn1.type.univ import BitString, OctetString, Integer, Sequence, Boolean
from pyasn1.type.univ import SetOf
from pyasn1.type.namedtype import NamedTypes, NamedType, OptionalNamedType
from pyasn1.type.namedtype import DefaultedNamedType
from pyasn1.type import tag
from pyasn1.codec.der import encoder
import asn_parser

class Record(Sequence):
  _id_type = NamedType('id', Integer())
  _room_type = OptionalNamedType('room',
      Integer().subtype(
          explicitTag=tag.Tag(
              tag.tagClassContext,
              tag.tagFormatSimple, 0)))
  _house_type = DefaultedNamedType("house",
      Integer(0).subtype(
          explicitTag=tag.Tag(
               tag.tagClassContext,
               tag.tagFormatSimple, 1)))
  componentType = NamedTypes(_id_type, _room_type, _house_type)


def test():
  record = Record()
  record['id'] = 123
  record['room'] = 3
  record['house'] = 2

  b = encoder.encode(record)
  print(b.hex())
  print(asn_parser.parse(encoding))
  
if __name__ == "__main__":
  test()
  
