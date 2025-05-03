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
import typing

class DirectedGraph:
  def __init__(self):
    self.nodes = set()
    self.children = collections.defaultdict(list)
    self.parents = collections.defaultdict(list)

  def add_edge(self, src:typing.Hashable, sink:typing.Hashable):
    self.nodes.add(src)
    self.nodes.add(sink)
    self.children[src].append(sink)
    self.parents[sink].append(src)
    
  def roots(self):
    return [x for x in self.nodes if len(self.parents[x]) == 0]

  def leaves(self):
    return [x for x in self.nodes if len(self.children[x]) == 0]

  def sort(self):
    '''Sorts the parent and children list.
       Sorting does not change the graph. It just makes it
       behaviour more deterministic. This is mostly used to
       preserve the order of the output of some algorithms.'''
    for x,c in self.children.items():
      self.children[x] = sorted(c)
    for x,p in self.parents.items():
      self.parents[x] = sorted(p)

  def reachable(self, node):
    '''Returns a list of nodes that are reachable from node.'''
    res = [node]
    S = set(node)
    done = 0
    while done < len(res):
      n = res[done]
      done += 1
      for c in self.children[n]:
        if c not in S:
          S.add(c)
          res.append(c)
    return res

