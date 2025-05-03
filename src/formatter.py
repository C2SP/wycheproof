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

import collections
import json
import test_vector
from typing import Any, Union

# Type hints
# An input value is a recursive structure that can contain the following
#  - list
#  - dict
#  - tuple
#  - integer
#  - string
#  - bytes or bytearray
#  - TestVector
#  - any object that implements .json() and returns a represention of
#    the object
# There may be a more consize way to define a type hint. I'm not sure
# how to define types that just implement .json()
InputValue = Any

class Formatter:
  pass

class JsonFormatter(Formatter):
  """Converts test vectors into JSON format."""

  def __init__(self, filename: str = ""):
    """Constructs a Formatter for JSON.

    Args:
      filename: the name of the file to write. If this is empty then the values
        to format are simply printed to the console.
    """
    self.lang = "json"
    self.filename = filename
    self.file = None

  def line(self, s: str) -> None:
    if self.file is None:
      print(s)
    else:
      self.file.write(s)
      self.file.write("\n")

  def open(self) -> None:
    if self.filename:
      self.file = open(self.filename, "w")
    else:
      self.file = None

  def close(self) -> None:
    if self.file:
      self.file.close()
    self.file = None

  def format_dict(self,
                  val: Union[collections.OrderedDict, dict[str, InputValue]],
                  indent: int = 0,
                  prefix: str = "",
                  separator: str = "") -> None:
    if isinstance(val, collections.OrderedDict) or isinstance(val, dict):
      # Keeps the order of key if the dictionary is ordered
      key_order = list(val)
    else:
      # TODO: this is old code written befor dicts in python were ordered.
      # Sorts the keys, so that primitives are first,
      # dictionary next, and lists are last.
      primitives=[]
      dicts=[]
      lists=[]
      for k,y in val.items():
        if isinstance(y, list) or isinstance(y, tuple):
          lists.append(k)
        elif isinstance(y, dict):
          dicts.append(k)
        else:
          primitives.append(k)
      key_order = sorted(primitives) + sorted(dicts) + sorted(lists)
    self.line(" " * indent + prefix + "{")
    for i, k in enumerate(key_order):
      s = "," if i != len(key_order) - 1 else ""
      self.format_value(val[k], indent + 2, f'"{k}" : ', s)
    self.line(" " * indent + "}" + separator)

  def format_test_vector(self, val: InputValue, indent: int,
                         separator: str) -> None:
    self.line(" " * indent + "{")
    f = val.fields()
    for i, k in enumerate(f):
      s = "," if i != len(f) - 1 else ""
      self.format_value(getattr(val, k, None), indent + 2, f'"{k}" : ', s)
    self.line(" " * indent + "}" + separator)

  def format_value(self,
                   val: InputValue,
                   indent: int = 0,
                   prefix: str = "",
                   separator: str = "",
                   compact: bool = False) -> None:
    """Formats a value.

    Args:
      val: the value to format
      indent: the number of spaces indent the value
      prefix: a prefix printed before the value. This can be used to print
        prefix and value on the same line.
      separator: used to separate values
      compact: a compact representation is attempted if True
    """

    def rec(val: InputValue) -> None:
      return self.format_value(val, indent, prefix, separator, compact)

    if hasattr(val, "compact_json"):
      compact = getattr(val, "compact_json")

    if isinstance(val, bytearray) or isinstance(val, bytes):
      rec(val.hex())
    elif val == NotImplemented:
      rec("NotImplemented")
    elif isinstance(val, list) or isinstance(val, tuple):
      if len(val) == 0:
        self.line(" " * indent + prefix + "[]" + separator)
      elif compact and all(isinstance(v, int) for v in val):
        self.line(" " * indent + prefix + repr(val) + separator)
      else:
        self.line(" " * indent + prefix + "[")
        for i, v in enumerate(val):
          s = "," if i < len(val) - 1 else ""
          self.format_value(v, indent + 2, "", s)
        self.line(" " * indent + "]" + separator)
    elif isinstance(val, test_vector.TestVector):
      self.format_test_vector(val, indent, separator)
    elif isinstance(val, dict):
      self.format_dict(val, indent, prefix, separator)
    elif hasattr(val, "json"):
      if isinstance(val, type):
        rec(val.json(val))
      else:
        rec(val.json())
    else:
      try:
        self.line(" " * indent + prefix + json.dumps(val) + separator)
      except Exception as ex:
        print("Cannot dump value of type:", type(val), val)
        raise ex
