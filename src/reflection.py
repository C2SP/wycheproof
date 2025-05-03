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
import pathlib
import types
import typing

_all_classes = None
_all_modules = None

def all_modules(paths=None,
                allow_skip:bool=True,
                log:bool=False)-> typing.List[types.ModuleType]:
  global _all_modules
  if paths is None:
    if _all_modules is not None:
      return _all_modules
    else:
      files = pathlib.Path('.').glob("*.py")
  else:
    files = paths
  res = []
  for path in files:
    name = str(path).split('.')[0]
    try:
      mod = __import__(name)
    except Exception as ex:
      if allow_skip:
        if log:
          print(f"Failed to import {name}.py")
          print(ex)
        continue
      else:
        raise ex
    res.append(mod)
  if paths is None:
    _all_modules = res
  return res

def all_classes(paths=None)-> typing.Dict[str, type]:
  global _all_classes
  if paths is None:
    if _all_classes is not None:
      return _all_classes
  res = {}
  for mod in all_modules(paths):
    for n in dir(mod):
       obj = getattr(mod, n)
       if isinstance(obj, type):
         if obj.__name__ == n:
           res[n] = obj
  # We might sort the classes differently at some time.
  # For now this uses alphabetic order.
  classes = collections.OrderedDict((n, res[n]) for n in sorted(res))
  if paths is None:
    _all_classes = classes
  return classes

def all_subclasses(class_list: list, paths=None) -> list:
  """Returns a list of subclasses.

  Args:
    class_list: a list of classes
    paths: a list of paths

  Returns:
    all the subclasses of any list in class_list found in the
    source code.
  """
  res = dict()
  for mod in all_modules(paths):
    if getattr(mod, "STATUS", '') == 'alpha':
      continue
    for n in dir(mod):
      obj = getattr(mod, n)
      if isinstance(obj, type):
        if any(issubclass(obj, clz) for clz in class_list):
          if getattr(obj, "status", '') == 'alpha':
            continue
          if n == obj.__name__:
            res[n] = obj
  return res


