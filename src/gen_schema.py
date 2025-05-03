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

import args
import AST
import collections
import doc
import json
import reflection
import test_vector
from typing import Union, ForwardRef
import types

# Generates JSON schemas for each group type.

def format_description(s):
  """Format a description of a field.
     The descriptions are often doc strings and hence contain newlines
     and repeated spaces. Since the schema description is just a string,
     these formattings are removed."""
  lines = s.split("\n")
  lines = [x.strip() for x in lines]
  lines = [x for x in lines if x]
  return " ".join(lines)

Type = Union[str, type]

def get_ref(ty: type):
  return "#/definitions/%s" % ty.__name__

def is_generic(clz):
  return (isinstance(clz, typing._GenericAlias) or
          isinstance(clz, types.GenericAlias))

def is_generic_list(clz):
  if (isinstance(clz, typing._GenericAlias) or
     isinstance(clz, types.GenericAlias)):

    orig = clz.__origin__
    return orig == typing.List or orig == list
  else:
    return False

def is_union(clz):
  if isinstance(clz, typing._GenericAlias):
    orig = clz.__origin__
    return orig == typing.Union
  else:
    return False

def json_const(val):
  """Defines a property that is constant.
     Version 6.0 of JSON schema adds a new keyword const
     which would allow a somewhat simpler encoding:
     {"const" : val}
  """
  return {"enum" : [val]}

def json_type_definition(ty: Type, defns):
  """Returns a type definition for a given type.

  The result is a new ordered dict. So that additional
  information i.e. a description can be added.

  Simple type return a JSON type. E.g. str returns
  { "type" : "string" }

  Some predefined types return simple descriptions.
  E.g. AST.BigInt returns
  {
    "type" : "string",
    "format" : "BigInt",
  }

  Unions return a description of the union.
  {
    "anyOf": [
      { "type": "string" },
      { "type": "integer" }
    ]
  }

  Complex types return a reference:
  { "$ref" : "#/definitions/EcGroup" }
  and add ad the definition of EcGroup to definitions

  Args:
    type: the type to convers
    defns:
      type definitions
      TODO: needs a structured definition.
  """
  res = collections.OrderedDict()
  if ty == int:
    res["type"] = "integer"
  elif ty == str:
    res["type"] = "string"
  elif ty == type(None):
    res["type"] = "null"
  elif ty == AST.HexBytes:
    res["type"] = "string"
    res["format"] = "HexBytes"
  elif ty == AST.BigInt:
    res["type"] = "string"
    res["format"] = "BigInt"
  elif is_generic_list(ty):
    res["type"] = "array"
    elem_types = ty.__args__
    assert len(elem_types) == 1
    res["items"] = json_type_definition(elem_types[0], defns)
  elif is_union(ty):
    types = []
    for elem_type in ty.__args__:
      types.append(json_type_definition(elem_type, defns))
      res["anyOf"] = types
  elif is_generic(ty):
    raise ValueError("Type not implemented" + str(type(ty)) + ":"+ str(ty))

  elif isinstance(ty, typing.ForwardRef):
    res["type"] = "object"
    res["format"] = repr(ty.__forward_arg__)
  elif isinstance(ty, str):
    if ty.upper() == "JSON":
      res["type"] = "object"
      # TODO: We might further define the object
      #   rsp. add a generict JSON type.
      # defn["additionalProperties"] = {"$ref" : ??? }
      # or
      # defn["properties"] = { .... }
    else:
      res["type"] = "string"
      res["format"] = ty
  elif isinstance(ty, type):
    if hasattr(ty, "schema"):
      res["$ref"] = get_ref(ty)
      add_definitions(ty, defns)
    elif hasattr(ty, "type_info"):
      res = json_schema_type_doc(ty.type_info, defns)
    elif issubclass(ty, str):
      res["type"] = "string"
      res["format"] = ty.__name__
    else:
      #TODO: undefined type
      res["type"] = "object"
      res["format"] = ty.__name__
  else:
    raise Exception("Unknown type:" + repr(ty) + ":" + repr(type(ty)))
  return res

def json_schema_type_doc(td: dict, definitions):
  """Returns a type definition from a dictionary with
     additional information about the type.
     I.e. documentation.
  """
  if "type" in td:
    res = json_type_definition(td["type"], definitions)
  else:
    # No type defined. Not sure what to do here.
    res = collections.OrderedDict()
  if "short" in td:
    res["description"] = format_description(td["short"])
  elif "desc" in td:
    res["description"] = format_description(td["desc"])
  # Elements that can be copied
  for n in ("enum",):
    if n in td:
      res[n] = td[n]
  return res

def add_definitions(ty:type, defns):
  if ty.__name__ not in defns:
    defns[ty.__name__] = None
    additional_properties = True
    required_fields = None
    if issubclass(ty, test_vector.TestVector):
      properties = test_vector_properties(ty, defns)
      required_fields = ty.required_fields()
    elif issubclass(ty, test_vector.TestGroup):
      properties = test_group_properties(ty, defns)
      required_fields = ty.required_fields()
    elif hasattr(ty, "schema"):
      properties = collections.OrderedDict()
      schema = ty.schema
      fields = sorted(schema)
      for name in fields:
        td = schema[name]
        properties[name] = json_schema_type_doc(td, defns)
    else:
      # Undefined: not sure what to do.
      properties = {}
  obj_type = collections.OrderedDict(
         (("type", "object"),
          ("properties", properties)))
  if not additional_properties:
    obj_type["additionalProperties"] = False
  if required_fields is not None:
    obj_type["required"] = required_fields
  defns[ty.__name__] = obj_type

def test_vector_properties(clz, defns):
  def type_doc(clz, name):
    if name in clz.schema:
      return clz.schema[name]
    if name in test_vector.TestVector.schema:
      return test_vector.TestVector.schema[name]
    return {}

  """Returns the JSON-Schema for the test vector."""
  properties = collections.OrderedDict()
  for name in clz.fields():
    td = type_doc(clz, name)
    properties[name] = json_schema_type_doc(td, defns)
  return properties

def test_group_properties(clz: type, defns):
  """Returns the JSON-Schema for the test group."""
  properties = collections.OrderedDict()
  schema = clz.schema
  fields = sorted(schema)
  properties["type"] = json_const(clz.testtype.__name__)
  for name in fields:
    td = schema[name]
    if name == "type":
      continue
    properties[name] = json_schema_type_doc(td, defns)
  # Additional properties:
  # "tests" = List of vectortype
  vt = {
     "type" : list[clz.vectortype],
  }
  properties["tests"] = json_schema_type_doc(vt, defns)
  return properties

def json_schema_test(test: type, test_group: type, file_name: str):
  """Returns the JSON-Schema for the test group.
       Args:
           test: a subclass of TestType
           test_group: a subclass of TestGroup
           file_name: the file name of the JSON schema
    """
  vectortype = test_group.vectortype
  properties = collections.OrderedDict()
  defns = collections.OrderedDict()
  if hasattr(test, "schema"):
    schema = test.schema
  else:
    schema = {}
  fields = sorted(schema)
  for name in fields:
    td = schema[name]
    properties[name] = json_schema_type_doc(td, defns)
  doc = {
    "type" : list[test_group]
  }
  properties["testGroups"] = json_schema_type_doc(doc, defns)
  if "schema" in properties:
    properties["schema"] = json_const(file_name)
  return collections.OrderedDict(
       (("type", "object"),
        ("definitions", defns),
        ("properties", properties)))

def all_subclasses(class_list, include_alpha: bool = False):
  res = dict()
  for mod in reflection.all_modules():
    if not include_alpha and getattr(mod, "STATUS", "") == "alpha":
      continue
    for n in dir(mod):
      obj = getattr(mod, n)
      if isinstance(obj, type):
        if any(issubclass(obj, clz) for clz in class_list):
          if not include_alpha and getattr(obj, "status", "") == "alpha":
            continue
          if n == obj.__name__:
            res[n] = obj
  return res

def gen_all_groups(include_alpha: bool, out_dir:str):
  classes = all_subclasses([test_vector.TestGroup], include_alpha)
  for n,val in classes.items():
    if val == test_vector.TestGroup:
      continue
    if getattr(val, "testtype", None) is None:
      # This is an abstract TestGroup.
      # TODO: Maybe there is a better way to define abstract
      #   classes.
      continue
    assert isinstance(val.testtype, type)
    name = val.testtype.__name__
    lower = ""
    for i,c in enumerate(name):
      if "A" <= c <= "Z" and i:
        lower += "_"
      lower += c.lower()
    file_name = lower + "_schema.json"
    with open(out_dir + "/" + file_name, "w") as f:
      schema = json_schema_test(test_vector.Test, val, file_name)
      json.dump(schema, f, indent=2)
      f.write("\n")

def print_all_groups():
  classes = all_subclasses([test_vector.TestGroup])
  for n,val in classes.items():
    if val == test_vector.TestGroup:
      continue
    print()
    print(n)
    schema = json_schema_test(test_vector.Test, val)
    print(json.dumps(schema, indent=2))

def get_parser() -> args.Parser:
  """Generates the JSON schemas for the test vectors."""
  parser = args.Parser()
  parser.add_argument(
    "--out_dir",
    type=str,
    help="the directory for the JSON schemas",
    default="")
  parser.add_argument(
      "--alpha",
      help="include test vectors that are experimental or buganizer entries",
      action="store_true")
  return parser

if __name__ == "__main__":
  parser = get_parser()
  namespace = parser.parse_args()
  out_dir = namespace.out_dir
  if out_dir == "":
    out_dir = "../schemas_v1"
  gen_all_groups(namespace.alpha, out_dir)
