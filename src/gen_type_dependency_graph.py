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

import directed_graph
import reflection
import test_vector

# Generates graphs for type dependencies.

def shorten(name):
  if '.' in name:
    return name.split('.')[-1]
  else:
    return name

def dependency_graph(modules=None):
  if modules is None:
    modules = reflection.all_modules()
  g = directed_graph.DirectedGraph()
  for m in modules:
    for x in dir(m):
      val = getattr(m, x)
      if isinstance(val, type):
        if issubclass(val, test_vector.TestGroup):
          if isinstance(val.testtype, type):
            t = val.testtype.__name__
            g.add_edge(val.__name__, t)
          elif val.testtype is None:
            pass
          else:
            raise ValueError("testtype is not a type:" + repr(val))
          if isinstance(val.vectortype, type):
            v = val.vectortype.__name__
            g.add_edge(v, val.__name__)
          elif val.vectortype is None:
            pass
          else:
            raise ValueError("vecortype is not a type:" + repr(val))
  return g

def gen_dependency_graphs(modules=None):
  g = dependency_graph(modules)
  g.sort()
  r = sorted(g.roots())
  print('# Dependency graphs')
  for m in r:
    mlist = g.reachable(m)
    print('## %s' % m)
    print('')
    print('```dot')
    print('digraph {')
    for md in mlist:
      for c in g.children[md]:
        print('  ', shorten(md), '->', shorten(c))
    print('}')
    print('```')
    print('')
   
if __name__ == "__main__":
  gen_dependency_graphs()


