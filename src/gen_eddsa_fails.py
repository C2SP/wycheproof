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

import args
import eddsa
import test_vector
import typing
import util
import eddsa_fails

from gen_eddsa import EddsaTestVector, EddsaVerify, EddsaTestGroup

def failures_experiment(fname):
  txt = open(fname).read()
  lines = txt.split('\n')
  L = []
  for line in lines:
    parts = line.split(' ')
    key = None
    msg = None
    for p in parts:
      v = p.split(":", 1)
      if len(v) == 2:
        if v[0] == 'key':
          key = v[1]
        elif v[0] == 'msg':
          msg = v[1]
    if key and msg:
      L.append((key, msg))
  return L

def tests():
  for x in eddsa_fails.FAILURES:
    yield x
  filenames = ['test.log', 'test2.log', 'test3.log',
               'test4.log', 'test5.log']
  for fname in filenames:
    L = failures_experiment(fname)
    for x in L:
      yield x

def generate(namespace):
  test_signing = True
  test_verifying = False
  alg = "ed25519"
  tv = test_vector.Test("EDDSA")
  group = eddsa.ed25519_group

  # Tink overflow.
  for key_hex, msg_hex in tests():
    sk = eddsa.EddsaPrivateKey(bytes.fromhex(key_hex), group)
    gid = sk.pk.hex()
    if gid in tv.testgroups:
      g = tv.testgroups[gid]
    else:
      g = EddsaTestGroup(sk, test_signing=test_signing)
      tv.add_group(gid, g)
    msg = bytes.fromhex(msg_hex)
    comment = "regression test for arithmetic error"
    sig = sk.sign(msg)
    g.add_test_sig("valid", comment, msg, sig)

  formatter = args.get_formatter(namespace)
  tv.format_all_vectors(formatter)

@args.commandline_parser
def get_parser() -> args.Parser:
  parser = args.default_parser()
  return parser

if __name__ == "__main__":
  parser = get_parser()
  namespace = parser.parse_args()
  generate(namespace)

