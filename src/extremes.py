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

import util

# This file contains functions that are used to precompute values with
# special properties. Values that have already precomputed are in
# special_values.py.
# https://events.ccc.de/congress/2017/Fahrplan/events/9021.html

hashes = ["SHA-1", "SHA-224", "SHA-256", "SHA-384", "SHA-512"]

def words():
  with open('/usr/share/dict/words') as f:
    for w in f.readlines():
      yield w.rstrip()

def inputs():
  words = ["Hello", "Test", "Text", "Message", "Msg", "Txt", "Plaintext",
           "Ptext", "Input", "Plain"]
  for w in words: yield w
  for w in words: yield w.lower()
  for w in words: yield w.upper()
  for w in ["hydroplane's", '123400', '345221', 'possums', 'raise', 
            'nonplused']:
      yield w

def hashWithZerosOld():
  '''Find hash digests with 0's.
     This allows to check for signature schemes that do not properly verify
     hashes.'''
  for w in inputs():
    for h in hashes:
      d = util.hash(h, w)
      if chr(0) in d:
        print(h, w, d.hex())

def hashWithZeros():
  for w in words():
    try:
      for h in hashes:
        if chr(0) not in util.hash(h, w):
          break
      else:
        print(w)
        for h in hashes:
           print(h, util.hash(h, w).hex())
    except Exception:
      # Some words contain non-ascii chars.
      pass

def extreme_hash(md, minrep=4):
  '''md is a function (not a string, not a context ,e.g. hashlib.sha256)'''
  from collections import defaultdict
  cnt = 0
  T = defaultdict(int)
  while True:
    msg = b'%d' % cnt
    cnt += 1
    ctx = md()
    ctx.update(msg)
    d = ctx.digest()
    for pos in range(len(d)):
      bp = d[pos]
      if bp not in (0,0xff):
        continue
      if pos > 0 and d[pos-1] == bp:
        continue
      j = pos + 1
      while j < len(d) and d[j] == bp:
        j += 1
      reps = j - pos
      if reps >= minrep and reps > T[bp,pos]:
        T[bp,pos]=reps
        print((bp, pos, msg, d.hex()))

def extreme_shake(md, size: int, minrep: int = 4):
  '''md is a function (not a string, not a context ,e.g. hashlib.shake_128)'''
  from collections import defaultdict
  cnt = 0
  T = defaultdict(int)
  while True:
    msg = b'%d' % cnt
    cnt += 1
    ctx = md()
    ctx.update(msg)
    d = ctx.digest(size)
    for pos in range(len(d)):
      bp = d[pos]
      if bp not in (0,0xff):
        continue
      if pos > 0 and d[pos-1] == bp:
        continue
      j = pos + 1
      while j < len(d) and d[j] == bp:
        j += 1
      reps = j - pos
      if reps >= minrep and reps > T[bp,pos]:
        T[bp,pos]=reps
        print((bp, pos, msg, d.hex()))

def extreme_y(group, x0, step, quot=2**24):
  def log(comment, x, y, q):
    print('  (%s, (%s, %s), %d),' % (repr(comment), hex(x), hex(y), q))
 
  p = group.p
  assert p % 4 == 3
  a = group.a
  b = group.b

  minval = p//quot

  miny = minval
  # least one bit
  maxlby = quot
  # least zero bit
  maxlzy = quot

  x = x0 - step
  while True:
    x += step
    y = group.get_y(x)
    if y is None: continue
    if y < miny:
      miny = y
      log('miny:', x, y, p // miny)
    lby = y & -y
    if lby > maxlby:
      maxlby = lby
      log('lby:', x, y, lby.bit_length())
    lzy = (y + 1) ^ y
    if lzy > maxlzy:
      maxlzy = lzy
      log('lzy:', x, y, lzy.bit_length())
    y2 = p - y
    if y2 < miny:
      miny = y2
      log('miny:', x, y2, p // miny)
    lby = y2 & -y2
    if lby > maxlby:
      maxlby = lby
      log('lby:', x, y2, lby.bit_length())
    lzy = (y2 + 1) ^ y2
    if lzy > maxlzy:
      maxlzy = lzy
      log('lzy:', x, y2, lzy.bit_length())

def extreme_points(group, quot = 2**20):
  '''Finds extreme points with known DL.
     minx: x-coordinate is minimal
     maxx: x-coordinate is maximal
     miny: y-coordinate is minimal
     lbx: number or least significant 0-bits of x is maximal
     lby: number of least significant 0-bits of y is maximal
     lzx: number of least significant 1-bits of x is maximal
     lzy: number of least signiticant 1-bits of y is maximal
  '''
  p = group.p
  G = group.generator()
  x = util.randomint(1, group.n)
  P = x * G
  minval = group.p // quot
  maxx = p - minval
  minx = minval
  miny = minval
  # least one bit
  maxlbx = quot
  maxlby = quot
  # least zero bit
  maxlzx = quot
  maxlzy = quot
  while True:
    P += G
    x += 1
    if P.x < minx:
      minx = P.x
      print('minx:', x, p // minx)
    if P.x > maxx:
      maxx = P.x
      print('maxx:', x, p // (p - maxx))
    lbx = P.x & -P.x
    if lbx > maxlbx:
      maxlbx = lbx
      print('lbx:', x, lbx.bit_length())
    lzx = (P.x + 1) ^ P.x
    if lzx > maxlzx:
      maxlzx = lzx
      print('lzx:', x, lzx.bit_length())

    if P.y < miny:
      miny = P.y
      print('miny:', x, p // miny)
    lby = P.y & -P.y
    if lby > maxlby:
      maxlby = lby
      print('lby:', x, lby.bit_length())
    lzy = (P.y + 1) ^ P.y
    if lzy > maxlzy:
      maxlzy = lzy
      print('lzy:', x, lzy.bit_length())
    y2 = p - P.y
    if y2 < miny:
      miny = y2
      print('miny:', group.n - x, p // miny)
    lby = y2 & -y2
    if lby > maxlby:
      maxlby = lby
      print('lby:', group.n - x, lby.bit_length())
    lzy = (y2 + 1) ^ y2
    if lzy > maxlzy:
      maxlzy = lzy
      print('lzy:', group.n - x, lzy.bit_length())
  



