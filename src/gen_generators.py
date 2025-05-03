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
import producer
import reflection
import test_vector
import types
import typing

def get_producers(skiplist=None):
  if skiplist is None:
    skiplist = []
  res = {}
  for mod in reflection.all_modules():
    name = mod.__name__
    if name in skiplist:
      continue
    for n in dir(mod):
      obj = getattr(mod, n)
      if isinstance(obj, type) and issubclass(obj, producer.Producer):
        if obj != producer.Producer:
          res[name] = obj
  return collections.OrderedDict((n, res[n]) for n in sorted(res))

def get_dict(parser, skip_options=None):
  res = collections.OrderedDict()
  for a in parser._actions:
    if skip_options:
      if any(s in a.option_strings for s in skip_options):
        continue
    t = {}
    if isinstance(a, argparse._HelpAction):
      continue
    # Copy the fields that we want in the documentation.
    # Other fields are dest, nargs, const, metavar.
    for name in ['default', 'choices', 'type', 'help']:
      if hasattr(a, name):
        t[name] = getattr(a, name)
    options = a.option_strings
    res[', '.join(options)] = t
  return res

def printclass(f, name, clz, back_refs):
  f.line()
  f.format_heading(name, level=2, anchor=name)
  f.line()
  if clz.__doc__:
    f.format(clz.__doc__)
    f.line()

  type_info = ''
  if issubclass(clz, test_vector.TestVector) and clz != test_vector.TestVector:
    type_info = 'Fields additional to the fields in TestVector are:'
  elif issubclass(clz, test_vector.TestGroup):
    type_info = 'Fields additional to the fields in TestGroup are:'
  f.format(type_info)
  f.line()
  schema = get_type_dict(clz)
  f.format_dict(schema, cols=['type', 'desc'], skip=["short"])
  if name in back_refs:
    f.line()
    class_names = back_refs[name]
    refs = [f.inline_ref(n, n) for n in class_names]
    f.line("Used in " + ", ".join(refs) + ".")

def printproducer(f, producer):
  name = producer.__module__
  parser = producer().parser()
  f.line()
  f.format_heading(name, level=2)
  f.line()
  if producer.__doc__:
    f.format(producer.__doc__)
    f.line()
  # Skips common options
  # skip_options = ['--alpha', '--internal', '--release']
  skip_options = []
  d = get_dict(parser, skip_options=skip_options)
  f.format_dict(d, first="option", cols=["type", "choices", "default", "help"])

def printproducers(formatter):
  formatter.format_file_header()
  formatter.format_heading("Test vector generators", level=1)
  version = 'Version: %s' % test_vector.GENERATOR_VERSION
  formatter.format(version)

  producers = get_producers()

  for n, prod in producers.items():
    printproducer(formatter, prod)
  formatter.format_file_end()

if __name__ == "__main__":
  parser = argparse.ArgumentParser()
  parser.add_argument('--format',
                      type=str,
                      choices=["g3doc", "html"],
                      default='g3doc',
                      help='the format of the output file')
  parser.add_argument(
      '--out',
      type=str,
      help='the output file name',
      default='')
  namespace = parser.parse_args()
  if namespace.out:
    f = open(namespace.out, 'w')
  else:
    f = None
  if namespace.format == "g3doc":
    formatter = doc.G3doc(f)
  elif namespace.format == "html":
    formatter = doc.Html(f)
  else:
    raise ValueError("Unknown format:" + namespace.format)
  printproducers(formatter)
