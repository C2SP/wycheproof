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

"""Tests for google3.third_party.py"""
import collections
import cProfile
import io
import os
import pstats
import time

import google3
import ecdsa

from google3.pyglib import resources
from google3.testing.pybase import googletest
from google3.testing.pybase import parameterized

CURVES = {
    'secp256k1': ecdsa.SECP256k1,
    'secp192r1': ecdsa.NIST192p,
    'secp224r1': ecdsa.NIST224p,
    'secp256r1': ecdsa.NIST256p,
    'secp384r1': ecdsa.NIST384p,
    'secp521r1': ecdsa.NIST521p
}

def countAddSub(n: int) -> int:
  '''Computes the additions an substrctions in
     the addition-subtraction chain of n'''
  cnt = 0
  n3 = 3 * n
  b = 2**(n.bit_length() - 1)
  while b > 1:
    if (n3 & b) != (n & b): cnt += 1
    b //= 2
  return cnt
 
def description(proc):
  filename, linenr, name = proc
  shortname = filename.split("/")[-1]
  return "%s in %s" % (name, shortname)

def printStats(k, prof):
  S = sorted(zip(k, prof))
  print("bitlength of k", [k.bit_length() for k,x in S])
  print("additions subtractions for k", [countAddSub(k) for k,x in S])
  stats = [pstats.Stats(p).stats for k,p in S]
  t = collections.defaultdict(list)
  for s in stats:
    for proc in s:
      t[proc].append(s[proc])
  avgs = []
  for proc, entries in t.items():
     timings = [e[2] for e in entries]
     avgs.append((sum(timings) / len(timings), proc))
  # Sort procedures from slowest to fastest
  avgs = sorted(avgs)[::-1]

  for avg, proc in avgs:
    desc = description(proc)
    if any(proc not in s for s in stats):
      print("no calls to %s in some profiles" % desc)
      continue
    entries = [s[proc] for s in stats]
    calls = [e[0] for e in entries]
    timings = [e[2] for e in entries]
    if len(set(calls)) != 1:
      print("Different call cnt for %s (avg time %s): %s" % (desc, avg, calls))

 
class SideChannelTest(parameterized.TestCase):

  # @parameterized.named_parameters(*CURVES.items())
  @parameterized.named_parameters(('NISTP256', ecdsa.NIST256p))
  def testSideChannel(self, curve):
    """
    """
    tests = 12
    print('curve', curve.name)
    print('baselen', curve.baselen)
    k = [int.from_bytes(os.urandom(curve.baselen), "big") for _ in range(tests)]
    prof = []
    for x in k:
      pr = cProfile.Profile()
      pr.enable()
      res = curve.generator * x
      pr.disable()
      prof.append(pr)
    printStats(k, prof)



if __name__ == '__main__':
  googletest.main()

