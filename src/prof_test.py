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

# Goal: Determine, how far it is possible to determine whether a method is
# constant time by using a profile. Profiles allow to remove some of the noise
# from the crypto and hence detect variances with less samples.
import cProfile
import pstats
import io

def diff_profiles(prof1, prof2):
  print("diff_profiles")
  assert isinstance(prof1, cProfile.Profile)
  assert isinstance(prof2, cProfile.Profile)
  s1 = pstats.Stats(prof1).stats
  s2 = pstats.Stats(prof2).stats
  for t in s1:
    if t not in s2:
      print('Missing entry in prof2', t, s1[t])
  for t in s2:
    if t not in s1:
      print('Missing entry in prof1', t, s2[t])
  for t in s1:
    if t not in s2: continue
    c1, r1, t1, cum1, cl1 = s1[t]
    c2, r2, t2, cum2, cl2 = s2[t]
    if c1 != c2 or r1 != r2:
      filename, linenr, name = t
      shortname = filename.split("/")[-1]
      print('Different call cnt for %s in %s' % (name, shortname))
      print('prof1:', c1, r1)
      print('prof2:', c2, r2)

def print_profile(prof):
  print("print_profile")
  assert isinstance(prof, cProfile.Profile)
  s = io.StringIO()
  ps = pstats.Stats(prof, stream=s).sort_stats("cumulative")
  ps.print_stats()
  print(s.getvalue())

def print_profile_short(prof):
  print("print_profile_short")
  assert isinstance(prof, cProfile.Profile)
  ps = pstats.Stats(prof)
  for k,v in ps.stats.items():
    filename, linenr, name = k
    cnt, cntc, tottime, cumtime, L = v
    shortname = filename.split("/")[-1]
    print("%-20s %-20s %8d %12f" % (shortname, name, cnt, tottime))

def print_profile2(prof):
  print("print_profile2")
  assert isinstance(prof, cProfile.Profile)
  for t in prof.getstats():
    code = t.code
    if isinstance(code, str):
      print(code, t.callcount, t.inlinetime, t.reccallcount, t.totaltime)
    else:
      print(code.co_name, t.callcount, t.inlinetime, t.reccallcount, t.totaltime)
  

def test1():
  from eddsa import EddsaPrivateKey, ed25519_group
  key = b"abcdefghijklmnopqrstuvwxyz012345"
  msg = b"123400"
  pr = cProfile.Profile()
  pr.enable()
  sk = EddsaPrivateKey(key, ed25519_group)
  pk = sk.publickey()
  sig = sk.sign(msg)
  pk.verify(msg, sig)
  pr.disable()
  pr2 = cProfile.Profile()
  pr2.enable()
  sk = EddsaPrivateKey(key, ed25519_group)
  pk = sk.publickey()
  msg = b"123401"
  sig = sk.sign(msg)
  pk.verify(msg, sig)
  pr2.disable()
  
  print_profile(pr)
  print_profile_short(pr)
  print_profile2(pr)
  diff_profiles(pr, pr2)

if __name__ == "__main__":
  test1()


