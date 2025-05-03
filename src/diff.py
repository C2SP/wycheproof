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


from collections import defaultdict
import json
def sigs(f:str):
  f = open(f)
  S = f.read()
  t = json.loads(S)
  res = defaultdict(list)
  for g in t["testGroups"]:
    for tc in g["tests"]:
      res[tc["sig"]].append(tc["tcId"])
  return res

def missing(A, B, txt):
  for x in A:
   if len(A[x]) > len(B[x]):
     print(txt, x,  A[x], B[x])

def diff(A, B):
  s1 = sigs(A)
  s2 = sigs(B)
  missing(s1,s2, "in A but not B")
  missing(s2,s1, "in B but not A")

diff("tmp", "tmp2")
