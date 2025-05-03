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

from gf import mersenne_factorization
from pseudoprimes import is_probable_prime

def divisors_from_factors(plist):
  if not plist:
    return {1}
  d = divisors_from_factors(plist[1:])
  return d | set(x * plist[0] for x in d)

def mersenne_divisors(m):
  return divisors_from_factors(mersenne_factorization(m))

def plist(m):
  res = []
  for d in mersenne_divisors(m):
    if is_probable_prime(2*d+1):
      res.append(2*d+1)
  return sorted(res)

def est_bl(L, max=1025):
  T = [0] * max
  T[0] = 1
  for p in L:
    U = T
    w = p.bit_length()
    for i in range(w, max):
      T[i] += U[i-w]
  return T

if __name__ == "__main__":
  print('here')
  for m in [128, 256, 512, 1024]:
    primes = plist(m)
    print()
    print(m,len(primes))
    print(est_bl(primes, m+1)[m])
    print(primes)
