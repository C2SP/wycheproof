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

import pathlib
import time

def test_import():
  '''Simply import all the files an see what happens.'''
  src_path = pathlib.Path('.')
  for path in src_path.glob("*.py"):
    name = str(path).split('.')[0]
    print(name)
    # Modules that do long precomputations should use lazy evaluations.
    start = time.time()
    try:
      mod = __import__(name)
    except Exception as ex:
      print("  *** failed:", ex)
      continue
    elapsed = time.time() - start
    if elapsed > 0.2:
      print("  *** time to load: %0.2f" % elapsed) 

if __name__ == "__main__":
  test_import()
