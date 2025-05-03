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

import ec_groups
import json


def eval_results(file, verbose: bool = False):
  f = open(file)
  results = json.load(f)
  found = 0
  for r in results:
    curve = r['curve']
    c = ec_groups.named_curve(curve)
    pub = r['pub']
    assert len(pub) % 4 == 2 and pub[:2] == "04"
    xy = pub[:2]
    px = int(xy[:len(xy)//2], 16)
    py = int(xy[len(xy)//2:], 16)
    print('pub', pub)
    for desc, guesses in r['guesses'].items():
      if verbose:
        print(desc, len(guesses))
      for g in guesses:
        p = c.generator() * g
        x,y = p.affine()
        if px == x or py == y:
          print('private key found', g, desc)
          found += 1
  print(f'found {found} private keys')

if __name__ == "__main__":
  eval_results("ecdsa_results.json")
