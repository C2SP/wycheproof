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
import reflection
import typing
import types
import test_vector

def print_redefinitions():
  print('===== Redefinitions =====')
  for n, clz in reflection.all_classes().items():
    if clz.__name__ != n:
      print(n, clz.__name__)

def print_dependencies():
  cnt = collections.Counter()
  for m in reflection.all_modules():
    for x in dir(m):
      val = getattr(m, x)
      if isinstance(val, types.ModuleType):
        # print(m.__name__, val.__name__)
        cnt[val.__name__] += 1
  print('===== Dependency count =====')
  for n,c in cnt.items():
    print(n, c)
  print('total', sum(cnt.values()))

def print_test_attributes():
  print('===== Test attributes =====')
  classes = reflection.all_subclasses([test_vector.TestVector])
  for name, clz in classes.items():
    attrs = list(clz.schema)
    if not hasattr(clz, "test_attributes"):
      print(name, 'has no test_attributes')
    elif clz.test_attributes != attrs:
      print("mismatched test_attributes", name, attrs, clz.test_attributes)
    for n in clz.fields():
      schema = clz.definition(n)

def test_definitions():
  print('===== Test definitions =====')
  classes = reflection.all_subclasses([test_vector.TestVector])
  for name, clz in classes.items():
    for n in clz.fields():
      schema = clz.definition(n)
      assert schema

if __name__ == "__main__":
  print_redefinitions()
  print_dependencies()
  print_test_attributes()
  test_definitions()





