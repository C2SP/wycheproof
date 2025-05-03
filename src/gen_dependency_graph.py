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
import types

def shorten(name):
  if '.' in name:
    return name.split('.')[-1]
  else:
    return name

def dependency_graph(modules=None, include_other=True):
  if modules is None:
    modules = reflection.all_modules()
  g = directed_graph.DirectedGraph()
  for m in modules:
    for x in dir(m):
      val = getattr(m, x)
      if isinstance(val, types.ModuleType):
        if include_other or val in modules:
          g.add_edge(m.__name__, val.__name__)
  return g

def gen_dependency_graphs(modules = None,
                          include_other: bool = False,
                          skip_tests: bool = True,
                          skip_list = ['util']):
  g = dependency_graph(modules, include_other)
  g.sort()
  r = sorted(g.roots())
  print('# Dependency graphs')
  for m in r:
    if skip_tests and m[-5:] == "_test":
      continue
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

def gen_dependency_graph_full(modules=None, include_other=False):
  g = dependency_graph(modules, include_other)
  g.sort()
  print('```dot')
  print('digraph {')
  for m in sorted(g.nodes):
    for c in g.children[m]:
      print('  ', shorten(m), '->', shorten(c))
  print('}')
  print('```')

def gen_full_graph():
  # A list of modules that are frequently used.
  # Including them into the full graph just makes the graph unreadable and
  # hence unusable.
  skiplist = set((
      'aes',
      'asn',
      'asn_fuzzing',
      'args',
      'AST',
      'bigendian',
      'footnotes',
      'mod_arith',
      'oid',
      'test_vector',
      'util'
    ))
  modules = reflection.all_modules()
  modules = [m for m in modules if shorten(m.__name__) not in skiplist]
  gen_dependency_graph_full(modules, False)
 
if __name__ == "__main__":
  gen_dependency_graphs()


