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

import AST
import collections
import doc
import json
import pathlib
import reflection
import test_vector
import typing

# TODO:
#   - add subtypes (e.g. RsaPublicKey)
#   - include generic infos
#   - refactor this and gen_schema.py
#   - find a type for JSON structures (rsp. describe the JSON structures)
#   - better format the comments (e.g. remove line breaks)
#   - test this with go
Type = typing.Union[str, type]

class GoTypeGenerator():
  def __init__(self):
    self.tabs = []

  def flush(self):
    if self.tabs:
      maxlen = [0] * max(len(v) for v in self.tabs)
      for v in self.tabs:
        for i,s in enumerate(v):
          maxlen[i] = max(maxlen[i], len(s))
      pos = [0] * len(maxlen)
      for i in range(1, len(maxlen)):
        pos[i] = pos[i-1] + maxlen[i-1] + 1
      for v in self.tabs:
        line = ''
        for i, val in enumerate(v):
          if val:
            line += ' ' * (pos[i] - len(line)) + val
        print(line)
      self.tabs = []

  def line(self, s):
    self.flush()
    print(s)

  def struct_start(self, name):
    self.line("type %s struct {" % name)

  def struct_end(self):
    self.line("}")
    self.line("")

  def tab(self, *args):
    self.tabs.append(args)

  def golang_name(self, n):
    return n[0].upper() + n[1:]

  def golang_type(self, clz: Type) -> str:
    if isinstance(clz, str):
      return clz
    elif isinstance(clz, type):
      if issubclass(clz, str):
        return "string"
      return clz.__name__
    elif isinstance(clz, typing._GenericAlias):
      orig = clz.__origin__
      if orig == typing.List or orig == list:
        elem_types = clz.__args__
        assert len(elem_types) == 1
        return '[]' + self.golang_type(elem_types[0])
    raise ValueError("unknown type:" + str(clz) + ":" + str(type(clz)))

  def typedef(self, json_name, defn):
    clz = defn["type"]
    golang_name = self.golang_name(json_name)
    golang_type = self.golang_type(clz)
    attribute = '`json:"%s"`' % json_name
    if "short" in defn:
      comment = "// " + defn["short"]
    elif "desc" in defn:
      comment = "// " + defn["desc"]
    else:
      comment = ""
    comment = comment.replace("\n", " ")
    self.tab(' ', golang_name , golang_type, attribute, comment)

  def format_comment(self, s):
    lines = s.split("\n")
    for l in lines: self.line("// " + l.strip())
    
  def gen_test_groups(self):
    classes = reflection.all_subclasses([test_vector.TestGroup])
    for n in sorted(classes):
      val = classes[n]
      if val == test_vector.TestGroup:
        continue
      if val.__doc__:
        self.format_comment(val.__doc__)
      schema = val.schema   
      self.struct_start(n)
      for name in schema:
        self.typedef(name, schema[name])
      test_type = {
        "type" : typing.List[val.vectortype],
      }
      self.typedef("tests", test_type)
      self.struct_end()


  def gen_test_vectors(self):
    classes = reflection.all_subclasses([test_vector.TestVector])
    for n in sorted(classes):
      val = classes[n]
      if val.__doc__:
        self.format_comment(val.__doc__)
      self.struct_start(n)
      for field_name in val.fields():
        defn = val.definition(field_name)
        self.typedef(field_name, defn)
      self.struct_end()



  def gen_all(self):
    """Generates type definitions for test groups and test vectors."""
    self.gen_test_groups()
    self.gen_test_vectors()

if __name__ == "__main__":
  g = GoTypeGenerator()
  g.gen_all()

