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

import typing
import json
import asn
import asn_parser
import math
import collections

# Evaluates results from a timing experiment.

# the directory with timing statistics.
TIMING_DIR = '../timings/'

class Stats:
  def __init__(self, L = None):
    if L is None:
      L = []
    self.n = len(L)
    self.sum = sum(L)
    self.sumsqr = sum(x * x for x in L)
    self.min = None
    self.max = None
    if L:
      S = sorted(L)
      self.median = S[len(S) // 2]
      self.quart = S[len(S) // 4]
      self.min = min(L)
      self.max = max(L)

  def update(self, L):
    self.n += len(L)
    self.sum += sum(L)
    self.sumsqr += sum(x * x for x in L)
    if self.min is not None:
      self.min = min(self.min, min(L))
    else:
      self.min = min(L)
    if self.max is not None:
      self.max = max(self.max, max(L))
    else:
      self.max = max(L)
    self.median = None
    self.quart = None
   
  def avg(self):
    return self.sum / self.n

  def var(self):
    return (self.sumsqr - self.sum **2 / self.n) / (self.n - 1)

  def std_dev(self):
    return math.sqrt(self.var())

  def cv(self):
    return self.std_dev() / self.avg()

  def indexOfDispersion(self):
    return self.var() / self.avg()

  def description(self):
    return 'samples:%d avg:%s std:%s, cv:%s iod:%s' % (self.n, self.avg(),
        self.std_dev(), self.cv(), self.indexOfDispersion()) 

  __str__ = description

# Format of timing results:
# { "curve" : curve_name,
#   "privKeys" : [ privkey_0, privkey_1, ...],
#   "timings" : list[n][2][m],
# }
#
# where privkey_i is a PKCS8 encoded private key
# timings is a 3-dimensional list of timings in ns
# where timings[i][j][k] is the k-th experiment with
# point j and private key i.
class TimingResult:
  def __init__(self, files, warmup=8):
    self.files = files
    self.curves = set()
    self.reload(warmup)

  def reload(self, warmup):
    self.timings = []
    self.privKeys = []
    for fn in self.files:
      f = open(TIMING_DIR + fn)
      raw = json.load(f)
      self.timings += raw['timings'][warmup:]
      self.privKeys += raw['privKeys'][warmup:]
      self.curves.add(raw['curve'])

  def private_key(self, i: int) -> int:
    encoded = self.privKeys[i]
    priv_struct = asn_parser.parse(bytes.from_hex(encoded))
    octet_str = priv_struct[2]
    if not isinstance(octet_str, asn.AsnElement):
      raise ValueError("private key has wrong format")
    if octet_str.tag != asn.OCTET_STRING:
      raise ValueError("private key is not an OCTET_STRING")
    val = asn_parser.parse(octet_str.val)
    octet_str2 = val[1]
    if not isinstance(octet_str2, asn.AsnElement):
      raise ValueError("private key has wrong format")
    if octet_str2.tag != asn.OCTET_STRING:
      raise ValueError("private key is not an OCTET_STRING")
    return int.from_bytes(octet_str2.val, 'big')
    
  def print_stats(self):
    def I(p):
      try:
        H = -(math.log(p)*p + math.log(1-p)*(1-p))/math.log(2)
        return 1 - H
      except Exception:
        return float('nan')

    def ps(cmt: str, cnt, n, length):
      p = cnt/n
      print(cmt, cnt, p, I(p)/length)
      
    timings = self.timings
    print("curves:", self.curves)
    print("number of private keys", len(self.privKeys))
    samples_per_key = len(timings[0][0])
    print("number of samples per key", samples_per_key)
    for length in [1, 2, 4, 8, 16, 32, 64]:
      if length > samples_per_key:
        continue
      cnt_min = 0
      cnt_max = 0
      cnt_avg = 0
      cnt_median = 0
      cnt_pairs = 0
      q = samples_per_key // length
      for T in timings:
       for j in range(q):
        samples = [sorted(s[j*length:(j+1)*length]) for s in T]
        x, y = [Stats(s) for s in samples]
        if x.min < y.min: cnt_min += 1
        if x.max < y.max: cnt_max += 1
        if x.avg() < y.avg(): cnt_avg += 1
        if x.median < y.median: cnt_median += 1
        m = sum(x < y for x,y in zip(*samples))
        if 2*m > length:
          cnt_pairs += 1
        if 2*m == length:
          cnt_pairs += 0.5
      n = len(timings) * q
      print('samples:', length, n)
      ps('cnt_min:    ', cnt_min, n, length)
      ps('cnt_avg:    ', cnt_avg, n, length)
      ps('cnt_median: ', cnt_median, n, length)
      ps('cnt_max:    ', cnt_max, n, length)
      ps('cnt_pairs:  ', cnt_pairs, n, length)

  def print_variance(self):
    timings = self.timings
    samples_per_key = len(timings[0][0])
    for length in [samples_per_key]:
      for i in range(2):
        tot = Stats()
        averages = Stats()
        mins = Stats()
        std_devs = Stats()
        for T in timings:
          L = T[i][:length]
          tot.update(L)
          S = Stats(L)
          averages.update([S.avg()])
          std_devs.update([S.std_dev()])
          mins.update([S.min])
        print('total', tot.description())
        print('avgs ', averages.description())
        print('mins ', mins.description())
        print('std_dev', std_devs.description())

  def histogram(self, block):
    H = [collections.defaultdict(int) for i in range(2)]
    D = collections.defaultdict(int)
    for L in self.timings:
      for i in range(2):
        for val in L[i]:
          c = math.floor(val/block)*block
          H[i][c] += 1
      for x,y in zip(*L):
        c = math.floor((x-y)/block)*block
        D[c] += 1
    for k in sorted(set(list(H[0]) + list(H[1]))):
      print(k, H[0][k], H[1][k])
    for k in sorted(D):
      print(k, D[k])

def test1():
  groups = [
  [ # special case after 1 doubling
    "timing_0_2048_16.txt",
    "timing_1_2048_16.txt" ],

  [ # secp384r1
    "timing_2_2048_16.txt",
    "timing_3_2048_16.txt"],

  [ "timing_0_512_64.txt",
    "timing_0_512_64_2.txt",
    "timing_0_512_64_3.txt",
    "timing_0_512_64_4.txt",
    "timing_0_512_64_5.txt",
    "timing_0_512_64_6.txt",
    "timing_0_512_64_7.txt",
    "timing_0_512_64_8.txt"],
  ]
  for files in groups:
    t = TimingResult(files)
    t.print_stats()
    t.print_variance()
    t.histogram(100000)

def test2(m = 64):
  files = [
    "timing_0_512_64.txt",
    "timing_0_512_64_2.txt",
    "timing_0_512_64_3.txt",
    "timing_0_512_64_4.txt",
    "timing_0_512_64_5.txt",
    "timing_0_512_64_6.txt",
    "timing_0_512_64_7.txt",
    "timing_0_512_64_8.txt"]
  D = [Stats() for i in range(m)]
  X = [Stats() for i in range(m)]
  Y = [Stats() for i in range(m)]
  quot = 64 // m
  t = TimingResult(files)
  for A,B in t.timings:
    for j in range(quot):
      R = sorted(A[j*m:(j+1)*m])
      S = sorted(B[j*m:(j+1)*m])
      for i in range(m):
        # print(i, len(D), len(R), len(S))
        D[i].update([S[i] - R[i]])
        X[i].update([R[i]])
        Y[i].update([S[i]])
  print('m=%s' % m)
  for j in range(m):
    print('j:%s D:%s' % (j, D[j]))

if __name__ == "__main__":
  # test2(4)
  # test2(8)
  # test2(16)
  # test2(32)
  # test2(64)
  test1()
  

