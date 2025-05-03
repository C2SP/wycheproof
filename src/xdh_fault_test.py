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

import xdh

# Does a point multiplication
# faults is a dictionary
#   faults[i] == (idx, mask)
# means flipping the bits in mask in step i for the
# variable (x_2, x_3, z_2, z_3)[idx]
def faultypoint_mult(group, u, k, debug = False, faults = {}):
   def cswap(bit, x, y):
     mask = -bit
     y ^= x
     x ^= y & mask
     y ^= x
     return x,y

   p = group.p
   a24 = group.a24
   curveA = group.A

   x_1 = u
   x_2 = 1
   z_2 = 0
   x_3 = u
   z_3 = 1
   swap = 0

   bits = k.bit_length()
   for t in range(bits-1, -1, -1):
       # simulate bit-flips.
       if t in faults:
         idx, mask = faults[t]
       else:
         idx, mask = None, None

       k_t = (k >> t) & 1
       swap ^= k_t
       (x_2, x_3) = cswap(swap, x_2, x_3)
       (z_2, z_3) = cswap(swap, z_2, z_3)
       swap = k_t
       A = (x_2 + z_2) % p 
       AA = A**2 % p
       B = (x_2 - z_2) % p
       BB = B**2 % p
       E = (AA - BB) % p
       C = (x_3 + z_3) % p
       D = (x_3 - z_3) % p
       DA = D * A % p
       CB = C * B % p
       x_3 = (DA + CB)**2 % p
       z_3 = x_1 * (DA - CB)**2 % p
       x_2 = AA * BB % p
       z_2 = E * (AA + a24 * E) % p

       if idx != None:
         if idx == 0:
           x_2 ^= mask
         elif idx == 1:
           x_3 ^= mask
         elif idx == 2:
           z_2 ^= mask
         elif idx == 3:
           z_3 ^= mask
         elif idx == 4:
           assert z_2 != 0
           z_2 = 0
         elif idx == 5:
           assert z_3 != 0
           z_3 = 0
       if debug:
         if z_2 and z_3:
           # Loop invariant
           u2 = x_2 * pow(z_2, -1, p) % p
           u3 = x_3 * pow(z_3, -1, p) % p
           R = u + u2 + u3
           S = u * u2 + u2 * u3 + u3 * u
           T = u * u2 * u3
           U = 4 * (R + curveA) * T - (S - 1)**2
           print('t:', t, idx)
           print('U%p:', U%p)
           print('u2:', u2)
           print('u3:', u3)
           print('R:', R)
           print('S:', S)
           print('T:', T)

   (x_2, x_3) = cswap(swap, x_2, x_3)
   (z_2, z_3) = cswap(swap, z_2, z_3)
   assert z_2 != 0
   u2 = x_2 * pow(z_2, -1, p) % p
   # verify the result: Same as the loop invariant but without modular
   # inversion of z_3
   V = u * u2
   W = 4 * ((u + u2 + curveA) * z_3 + x_3) * (V * x_3) 
   X = ((V - 1) * z_3 + x_3 * (u + u2))**2
   assert (W - X) % p == 0
   if faults:
     print("Verification succeeded despite faults")
     print("  faults:%s" % faults)
     print("  result:%s" % u2)
     print("  correct result:%s" % group.point_mult(u, k))
     print("  x_3: %s" % x_3)
     print("  z_3: %s" % z_3)
     if z_3:
       print("  u_3:%s" % (x_3 * pow(z_3, -1, p) % p))
   return u2

def xdh_faults_test(group, debug=False):
  '''Performs some X25519 or X448 multiplications, where in some of the
     steps are modified. Ideally the modification is detected
     by the check for collinearity.
     The check for collinearity does not detect modifications
     of the exponent. As a result, it does not detect if points on
     the curve are negated or if they are set to 0 at the beginning
     of the point multiplication.'''
  from time import time
  start = time()
  M = pow(12314231, 7623, group.p)
  M -= M % 8
  passed = 0
  tests = 0
  Masks = [1 << i for i in range(group.bits)]
  Masks += [(1 << i) - 1 for i in range(1, group.bits)]
  Masks += [group.p - (1 << i) for i in range(group.bits)]
  NoMasks = [None]
  for idx in range(4,6):
    for step in range(M.bit_length()):
      for mask in (Masks if idx < 4 else NoMasks):
        faults = {step: (idx, mask)}
        tests += 1
        try:
          u2 = faultypoint_mult(group, group.pu, M, faults=faults)
          if debug:
            faultypoint_mult(group, group.pu, M, faults=faults, debug=debug)
          passed += 1
        except AssertionError:
          pass
  print('%d tests done. passed = % s, time = %s'%(tests, passed, time() - start))
  # assert passed == 0
  # Failures found so far:
  #   - Setting x_2 to 0 in first iteration may not be detected

def test_fault():
  faults = { 30 : [0, 2**16] }
  u = 19824719827391827419827319827319898231231241231312
  k = 0xfedcba98
  faultypoint_mult(xdh.x448, u, k, debug=True, faults=faults)

if __name__ == "__main__":
  # xdh_faults_test(xdh.x25519)
  # xdh_faults_test(xdh.x448)
  test_fault()
