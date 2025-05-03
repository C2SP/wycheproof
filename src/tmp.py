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

import math

# Order of secp256r1
n=int("1157920892103562487626974469494075735299969552241357603424222590"
          "61068512044369")

print(hex(n))

R = 2**260
t, r = divmod(R, n)

print(r.bit_length())
# r elements have probability p = (t+1) / R
# n-r elements have probability q = t / R
p = (t+1) / R
q = t / R
print(p, q)
assert r * (t+1) + (n-r) * t == R

# The Shannon entropy of the result is
# H = - r * p * log(p) - (n-r) * q * log(q)
H = -r * p * math.log2(p) - (n-r) * q * math.log2(q)
print(H)
H2 = -r * (t+1)/R * (math.log2(t+1) - math.log2(R)) - (n-r) * (t/R) * (math.log2(t) - math.log2(R))
print(H2)
H3 = -r * (t+1)/R * (math.log2(t+1) - 260) - (n-r) * (t/R) * (math.log2(t) - 260)
print(H3)
H4 = -r * (t+1)/R * math.log2(t+1) - (n-r) * (t/R) * math.log2(t) + 260 * (r * (t+1)/R + (n-r) * (t/R))
H5 = -r * (t+1)/R * math.log2(t+1) - (n-r) * (t/R) * math.log2(t) + 260
print(H4)
print(H5)
print()
print(math.log2(n))
print(math.log2(n/2**256))
I = math.log2(n) - H
print(I, I*10**11)

