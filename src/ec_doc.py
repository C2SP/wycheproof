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

import doc
import ec_groups
import oid
import oid_util


def groups():
  return ec_groups.all_curves

def get_oid(group, lookup:bool):
  oid = group.get_oid()
  if not oid:
    return None
  if lookup:
    oid_util.lookup(oid)
  return oid

def make_table():
  prefered_references = [
    "RFC 5639",
    "RFC 7748",
    "RFC 8032",
    "RFC 8037"]
  t = {}
  for g in groups():
    gdoc = {}
    if g.jwk():
      gdoc["jwk name"] = g.jwk()
    oid = get_oid(g, True)
    if oid:
      gdoc["oid"] = str(oid)
    if g.ref:
      gdoc["ref"] = g.ref
    else:
      if oid.reference:
        gdoc["ref"] = "e.g. " + oid.reference
    t[g.name] = gdoc
  # sort by name
  res = {}
  for n in sorted(t):
    res[n] = t[n]
  return res

def print_table():
  f = doc.G3doc()
  f.format_dict(make_table(), first="Curve name",
                cols=["jwk name", "oid", "ref"])

if __name__ == "__main__":
  print_table()
