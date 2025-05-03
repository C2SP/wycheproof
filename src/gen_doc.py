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

import argparse
import collections
import doc
import test_vector
import typing
import reflection

def get_classes():
  res = {}
  for n, clz in reflection.all_classes().items():
    if getattr(clz, "status", "") == "alpha":
      continue
    if hasattr(clz, "schema"):
      res[n] = clz
  # We might sort the classes differently at some time.
  # For now this uses alphabetic order.
  return collections.OrderedDict((n, res[n]) for n in sorted(res))

def is_type(tp):
  return isinstance(tp, type) or isinstance(tp, typing._GenericAlias)

def is_union(tp):
  if isinstance(tp, typing._GenericAlias):
    return tp.__origin__ == typing.Union
  return False

def is_list(tp):
  if isinstance(tp, typing._GenericAlias):
    return (tp.__origin__ in (list, typing.List))
  return False

def get_back_refs(classes):
  def add_type(n, types):
    if types is None:
      return
    elif isinstance(types, type):
      back_ref[types.__name__].append(n)
    elif isinstance(types, tuple):
      for t in types:
        add_type(n, t)
    elif is_union(types) or is_list(types):
      for t in types.__args__:
        add_type(n, t)
    else:
      raise Exception("Unexpected type:", type(types))

  back_ref = collections.defaultdict(list)
  for n, obj in classes.items():
    if getattr(obj, "vectortype", None) is not None:
      add_type(n, obj.vectortype)
    if hasattr(obj, "testtype") and hasattr(obj.testtype, "vectortype"):
      add_type(n, obj.testtype.vectortype)
  return back_ref

def format_list(f, tp_list):
  res = " or ".join(format_type(f, tp) for tp in tp_list)
  if len(tp_list) != 1:
    return "(" + res + ")"
  else:
    return res

def format_type(f, tp) -> str:
  if tp == type(None):
    return "null"
  elif isinstance(tp, typing.ForwardRef):
    return tp.__forward_arg__
  elif is_union(tp):
    return format_list(f, tp.__args__)
  elif is_list(tp):
    return "list of " + format_list(f, tp.__args__)
  elif isinstance(tp, type):
    name = tp.__name__
    if hasattr(tp, "reference"):
      fname, anchor = tp.reference
      return f.inline_ref(name, anchor, fname)
    elif issubclass(tp, test_vector.TestVector):
      return f.inline_ref(name, name, "types")
    elif issubclass(tp, test_vector.TestGroup):
      return f.inline_ref(name, name, "types")
    elif issubclass(tp, test_vector.TestType):
      return f.inline_ref(name, name, "files")
    return tp.__name__
  elif isinstance(tp, str):
    return tp
  else:
    assert str(tp).find("typing.") == -1, str(tp)
    return str(tp)

def get_type_dict(f, clz):
  schema = getattr(clz, "schema")
  
  # Python dicts are now ordered.
  fieldorder = list(schema)
  res = collections.OrderedDict()
  # Print the type of a TestGroup first.
  if issubclass(clz, test_vector.TestGroup):
    res["type"] = {
        "type": str,
        "desc": "the type of the test",
    }
    if isinstance(clz.testtype, type):
      ref = format_type(f, clz.testtype)
      res["type"]["enum"] = f'"{ref}"'

  for attr in fieldorder:
    if attr not in schema:
      raise ValueError(f"schema of {clz} does not define {attr}.")
    val = schema[attr]
    if is_type(val):
      val = format_type(f, val)
    res[attr] = val
  if issubclass(clz, test_vector.TestVector):
    # There are more fields from test vector.
    # The documentation does not list them
    pass
  elif issubclass(clz, test_vector.TestGroup):
    # There are more fields from test group
    # The important one is
    # "tests" = List of vectortype
    ty = clz.vectortype
    if ty is None:
      itemtype = "List"
    elif isinstance(ty, tuple):
      tylist = " or ".join(format_type(f, x) for x in ty)
      itemtype = "List of (" + tylist + ")"
    elif is_union(ty):
      itemtype = "List of " + format_list(f, ty.__args__)
    elif is_list(ty):
      itemtype = "List of " + format_type(f, ty)
    elif isinstance(ty, type):
      itemtype = "List of " + format_type(f, ty)
    res["tests"] = {"type": itemtype, "desc": "a list of test vectors"}
  return res

def printclass(f, name, clz, back_refs):
  def format_func(col_name, val):
    if col_name == "enum":
      if isinstance(val, list) or isinstance(val, tuple):
        return ", ".join(repr(x) for x in val)
    if is_type(val):
      return format_type(f, val)
    return val

  f.line()
  f.format_heading(name, level=2, anchor=name)
  f.line()
  if clz.__doc__:
    f.format(clz.__doc__)
    f.line()

  if issubclass(clz, test_vector.TestVector) and clz != test_vector.TestVector:
    type_info = "Fields additional to the fields in TestVector are:"
    f.format(type_info)
    f.line()
  elif issubclass(clz, test_vector.TestGroup):
    type_info = "Fields in %s are:" % clz.__name__
    f.format(type_info)
    f.line()

  schema = get_type_dict(f, clz)
  f.format_dict(
      schema, cols=["type", "desc"], skip=["short"], format_func=format_func)
  if name in back_refs:
    f.line()
    class_names = back_refs[name]
    refs = [f.inline_ref(n, n) for n in class_names]
    f.line("Used in " + ", ".join(refs) + ".")

def printdoc(formatter):
  formatter.format_file_header()
  formatter.format_heading("Test vector types", level=1)
  version = "Version: %s" % test_vector.GENERATOR_VERSION
  formatter.format(version)
  formatter.format_table_of_contents()

  classes = get_classes()
  back_refs = get_back_refs(classes)

  for n, obj in classes.items():
    printclass(formatter, n, obj, back_refs)
  formatter.format_file_end()

if __name__ == "__main__":
  parser = argparse.ArgumentParser()
  parser.add_argument(
      "--format",
      type=str,
      choices=["g3doc", "html"],
      help="the format of the output",
      default="g3doc")
  parser.add_argument(
      "--out",
      type=str,
      help="The file name of the output. Prints to the console if empty.",
      default="")
  namespace = parser.parse_args()
  f = None
  if namespace.out:
    f = open(namespace.out, "w")
  if namespace.format == "g3doc":
    printdoc(doc.G3doc(f))
  elif namespace.format == "html":
    printdoc(doc.Html(f))
  else:
    raise ValueError("Unknown format:" + namespace.format)
