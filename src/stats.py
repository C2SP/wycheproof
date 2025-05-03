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
import json
from collections import Counter

def print_counter(n, c):
  assert isinstance(c, Counter)
  print('Field : ' + n)
  printed = 0
  others = 0
  if len(c) <= 20:
    for n, val in sorted(c.items()):
      val = c[n]
      if len(str(n)) < 30:
        print(repr(n),':', val)
        printed += 1
      else:
        others += val
  if printed == 0:
    print(sum(c.values()), 'occurrences')
    print(len(c), 'distinct values')
    others = 0
  if others > 0:
    print('others:', others)
  print('------')

def print_dict(c):
  assert isinstance(c, dict)
  for n in sorted(c):
    v = c[n]
    if isinstance(v, Counter):
      print_counter(n, v)
    elif isinstance(v, dict):
      print_dict(v)
    else:
      print(n, ':', v)

def count(test, d):
  for tg in test['testGroups']:
    countdict(tg, d)

def countval(group, d):
  if isinstance(group, dict):
    countdict(group, d)
  elif isinstance(group, list):
    for x in group:
      countval(x, d)
  else:
    print(type(group))

def countdict(group, d):
  for n, val in group.items():
    if n == 'tests':
      if n not in d:
        d[n] = dict()
      countval(val, d[n])
    elif isinstance(val, str) or isinstance(val, int):
      if n not in d:
        d[n] = Counter()
      d[n][val] += 1
    elif isinstance(val, list):
      if n not in d:
        d[n] = Counter()
      for x in val:
        if isinstance(x, dict):
          print(n)
        else:
          d[n][x] += 1
    elif isinstance(val, dict):
      if n not in d:
        d[n] = dict()
      countdict(val, d[n])

def countspecial(test):
  acceptable_no_flags = 0
  for g in test['testGroups']:
    for t in g['tests']:
      if 'result' in t and t['result'] == 'acceptable':
        if 'flags' not in t or not t['flags']:
          acceptable_no_flags += 1
  print('acceptable_no_flags', acceptable_no_flags)

def print_stats(filename):
  """Prints some statistics of a file containing

     JSON encoded test vectors. This is mainly used
     to compare two JSON files after heavy refactoring
     of the test vectors.
  """
  f = open(filename, 'r')
  test = json.load(f)
  d = dict()
  count(test, d)
  print_dict(d)
  countspecial(test)

def get_parser() -> args.Parser:
  parser = args.Parser()
  parser.add_argument(
      '--inp',
      type=str,
      default='',
      help='a file with test vectors')
  return parser

if __name__ == '__main__':
  parser = get_parser()
  namespace = parser.parse_args()
  print_stats(namespace.inp)
