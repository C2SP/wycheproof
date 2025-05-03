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

# Implements some experiments for testing randomness

import collections
import math
import os
import util
import time
import typing

Complex = typing.Union[float, complex]
Samples = typing.List[Complex]

def expi(x: float):
  '''Computes exp(1j * f)'''
  return math.cos(x) + math.sin(x)*1j

def random_unit() -> Complex:
  r = 0
  for b in os.urandom(8):
    r = (r + b) / 256
  return expi(r * 2 * math.pi)
  
def avg(L: Samples) -> Complex:
  return sum(L) / len(L)

def var(L: Samples) -> Complex:
  sum_x = sum(x for x in L)
  sum_sqr = sum(x * x.conjugate() for x in L)
  n = len(L)
  return (sum_sqr - sum_x*sum_x.conjugate()/n)/(n - 1)

def test_var(n):
  '''The variance of the sample is expected to be 1.'''
  L = [random_unit() for _ in range(n)]
  print('avg:', avg(L), 'var:', var(L))

def test_sum(m, n, steps=5):
  '''
  Tests the distribution of sums of n variables.
  Does m experiments.

  The distribution was described by
  (I can't find the reference) Abramowitz and Stegun.

  I.e. the probability that abs(n X) / sqrt std dev(X) > L
  is approximately exp(-L^2).
  This can also be derived by assuming that n X / sqrt(n) approximates
  a standard complex normal distribution, which has a density
  f_Z(z) = exp(-abs(z)^2) / pi
  https://en.wikipedia.org/wiki/Complex_normal_distribution

  An example of a long run is:
  test_sum 50000000 500
  [0.0, 0.2] 1957604 1960528
  [0.2, 0.4] 5427161 5432283
  [0.4, 0.6] 7718101 7723373
  [0.6, 0.8] 8517197 8519195
  [0.8, 1.0] 7978677 7970649
  [1.0, 1.2] 6550084 6547584
  [1.2, 1.4] 4809946 4803467
  [1.4, 1.6] 3181554 3177684
  [1.6, 1.8] 1907336 1907042
  [1.8, 2.0] 1042109 1042413
  [2.0, 2.2] 518466 520429
  [2.2, 2.4] 236425 237797
  [2.4, 2.6] 98591 99594
  [2.6, 2.8] 37842 38278
  [2.8, 3.0] 13033 13513
  [3.0, 3.2] 4187 4385
  [3.2, 3.4] 1239 1309
  [3.4, 3.6] 338 359
  [3.6, 3.8] 78 91
  [3.8, 4.0] 26 21
  [4.0, 4.2] 5 4.5
  [4.2, 4.4] 1 0.8960319758494966
  '''
  start = time.time()
  R = collections.defaultdict(int)
  std_dev = math.sqrt(n)
  for i in range(m):
    L = [random_unit() for _ in range(n)]
    s = abs(sum(L))
    c = s/std_dev
    R[int(c * steps)] += 1
  print('test_sum', m, n)
  for i in sorted(R):
    upper = (i + 1) / steps
    lower = (i) / steps
    expected = m * (math.exp(-lower**2) - math.exp(-upper**2))
    if expected > 10:
      expected = round(expected)
    elif expected > 1:
      expected = round(expected, 1)
    print([lower, upper], R[i], expected)
  print('time:', time.time()-start)


if __name__ == "__main__":
  test_var(10000)
  test_sum(1000, 10)
  # takes 20 sec
  test_sum(100000, 100)
  # takes 200 sec
  test_sum(1000000, 100)
  # takes 2000 sec
  test_sum(5000000, 200)
  # takes 6 h
  test_sum(20000000, 500)
  # takes 60 h
  test_sum(200000000, 500)

