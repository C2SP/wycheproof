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

import json
import oid
import typing
import util

OID_TABLE = None
def table():
  global OID_TABLE
  if OID_TABLE is None:
    OID_TABLE = json.load(open('../tables/oid_table.json'))
  return OID_TABLE

def lookup(v: oid.Oid) -> bool:
  """Checks if the OID is in the OID_TABLE and completes information."""
  t = table()
  val = str(v)
  if val not in t:
    return False
  else:
    s = t[val]
    for name, refs in s["refs"].items():
      if refs:
        if v.description is None:
          v.description = name
        if v.reference is None:
          v.reference = refs[0]
    return True
