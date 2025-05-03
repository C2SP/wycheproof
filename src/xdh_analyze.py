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
from typing import List
import time
import xdh_util
import xdh


def array_to_int(array: List[int]) -> int:
  res = 0
  for i in range(10):
    exp = 51 * (i // 2)
    if i % 2 == 1:
      exp += 26
    res += array[i] << exp
  return res


def text_to_int(text: str, p=2**255 - 19) -> int:
  elems = {}
  for line in text.split('\n'):
    parts = line.split('=')
    if len(parts) == 2:
      elems[int(parts[0])] = int(parts[1])
  a = [elems[i] for i in range(10)]
  return array_to_int(a) % p


def bytes_to_int(a: List[int]) -> int:
  return sum((b & 0xff) << (8 * i) for i, b in enumerate(a))


# A do-nothing decorator
namespace = lambda x: x


@namespace
class Valid:
  comment = 'Valid'
  q = 9
  resultx = array_to_int([
      -34594664, 30155331, -43087212, 27714541, 23846138, -12927219, 18617095,
      10321539, 44624538, -5686674
  ])
  nqpqx = array_to_int([
      -54366775, 2390290, 21417325, 11097012, 38828237, -14460453, 52039877,
      -2655672, -64697646, -11070046
  ])
  nqpqz = array_to_int([
      1032997, -26236993, 21999015, 2195229, -45126885, -2912411, 31932717,
      -19874231, 57740032, 28388691
  ])
  nqx = array_to_int([
      52739111, -30950707, 50119769, -24053039, -31575777, 32449219, -31017695,
      -13904156, 53657112, 6774329
  ])


# https://github.com/google/tink/blob/a8ec74d083068cd5e1ebed86fd8254630617b592/java_src/src/main/java/com/google/crypto/tink/subtle/Curve25519.java#L330
@namespace
class Sample1:
  comment = 'Failure 1'
  resultx = array_to_int([
      1992933, 29956733, 52373488, 27625874, 49845042, 30373766, 34828877,
      15146922, 21300034, 15420598
  ])
  q = 9
  nqx = array_to_int([
      53027435, -24386040, 41878080, 13069104, 32345495, 463829, 43435978,
      25883210, 7509820, 20285233
  ])
  nqpqz = array_to_int([
      1457507, -12933025, 28978369, 21887722, -66679696, -29855840, 10248620,
      -8552178, 46679088, 19866335
  ])
  nqz = array_to_int([
      10152317, 13798231, 44829778, -30070598, 36690813, 29661800, 21975409,
      -2067506, 57168743, 22130255
  ])
  nqpqx = array_to_int([
      57181216, 31614960, 23773565, -5586896, -50425233, -19969388, 61022867,
      8868798, 45166179, 16240376
  ])
  n = bytes_to_int([
      119, 127, 11, -105, -122, -51, -112, 119, -27, 112, -79, 72, -59, 105,
      100, 111, 119, -18, 81, -76, 104, -81, 55, 8, 42, -77, -1, 39, 64, 124,
      83, -69
  ])


@namespace
class SampleBad:
  nqz2 = text_to_int("""
     0 = 45185616
     1 = 3530251
     2 = 50834176
     3 = 19996608
     4 = 38044881
     5 = 29927412
     6 = 48867509
     7 = 15766442
     8 = 21375258
     9 = 4767718""")
  nqx2 = text_to_int("""
     0 = -17705510
     1 = -31013958
     2 = -32420914
     3 = 25184866
     4 = -28400441
     5 = 7343207
     6 = 53834980
     7 = -10362917
     8 = -36455097
     9 = -526367""")
  q = 9
  nqx = text_to_int("""
     0 = -13289003
     1 = -10610101
     2 = -18822941
     3 = -3960770
     4 = -57737899
     5 = -24248441
     6 = 40184955
     7 = -20523275
     8 = -53805819
     9 = -12115052""")
  t = text_to_int("""
     0 = -42396762
     1 = 32573719
     2 = 19522769
     3 = -7608187
     4 = -58958572
     5 = 31624897
     6 = -59902917
     7 = -4328963
     8 = 41332531
     9 = -21973665""")
  nqpqz = text_to_int("""
     0 = 53564129
     1 = 2391810
     2 = 8131740
     3 = -27336635
     4 = -49293555
     5 = -28564448
     6 = -99334344
     7 = -27814812
     8 = -41282175
     9 = 39659080""")
  nqz = text_to_int("""
     0 = 19763376
     1 = -10564373
     2 = -29260126
     3 = 26529191
     4 = -65979188
     5 = 24630338
     6 = -19875359
     7 = -17410715
     8 = -76249426
     9 = 17286941""")
  nqpqx = text_to_int("""
     0 = -33888280
     1 = -3535166
     2 = -29970780
     3 = 33749767
     4 = 79648845
     5 = -19336894
     6 = -66951686
     7 = -31797160
     8 = 76925311
     9 = -33196060""")
  nqpqx2 = text_to_int("""
     0 = 53086822
     1 = -1843793
     2 = -39731732
     3 = 30248979
     4 = 25348476
     5 = -18871103
     6 = -2036603
     7 = -20918257
     8 = 7639146
     9 = 18695526""")
  nqpqz2 = text_to_int("""
     0 = -42396762
     1 = 32573719
     2 = 19522769
     3 = -7608187
     4 = -58958572
     5 = 31624897
     6 = -59902917
     7 = -4328963
     8 = 41332531
     9 = -21973665""")


@namespace
class SampleGood:
  nqz2 = text_to_int("""
     0 = 40133839
     1 = -9341466
     2 = 23485589
     3 = 2405851
     4 = -44800608
     5 = 33210076
     6 = 29932283
     7 = -6097046
     8 = 11593227
     9 = 30295768""")
  nqx2 = text_to_int("""
     0 = -27472587
     1 = 32120790
     2 = -9990470
     3 = -24893618
     4 = 63492569
     5 = 9908767
     6 = -25343264
     7 = 21129989
     8 = -41177338
     9 = -16168640""")
  q = 9
  nqx = text_to_int("""
     0 = -46341382
     1 = -10655829
     2 = -8385756
     3 = 18607651
     4 = -49496610
     5 = -23866544
     6 = 40184955
     7 = -23635835
     8 = -31362212
     9 = -41517045""")
  t = text_to_int("""
     0 = 6189584
     1 = 6775515
     2 = 10667804
     3 = 32351880
     4 = -53167743
     5 = -6099218
     6 = -15172353
     7 = 6661304
     8 = 26463674
     9 = 17895025""")
  nqpqz = text_to_int("""
     0 = 53564129
     1 = 2391810
     2 = 8131740
     3 = -27336635
     4 = -49293555
     5 = -28564448
     6 = -99334344
     7 = -27814812
     8 = -41282175
     9 = 39659080""")
  nqz = text_to_int("""
     0 = 19763376
     1 = -10564373
     2 = -29260126
     3 = 26529191
     4 = -65979188
     5 = 24630338
     6 = -19875359
     7 = -17410715
     8 = -76249426
     9 = 17286941""")
  nqpqx = text_to_int("""
     0 = -14212431
     1 = -9462142
     2 = -68073300
     3 = 33749767
     4 = 79648845
     5 = -10109340
     6 = -34569028
     7 = -35779508
     8 = 76925311
     9 = -26733040""")
  nqpqx2 = text_to_int("""
     0 = 10260358
     1 = -30021433
     2 = 40459179
     3 = -29376862
     4 = 395335
     5 = -7458912
     6 = 21290421
     7 = -24039334
     8 = 55786738
     9 = 281679""")
  nqpqz2 = text_to_int("""
     0 = 6189584
     1 = 6775515
     2 = 10667804
     3 = 32351880
     4 = -53167743
     5 = -6099218
     6 = -15172353
     7 = 6661304
     8 = 26463674
     9 = 17895025""")


@namespace
class SampleBefore:
  nqz2 = text_to_int("""
    0 = 118653293
    1 = -21393957
    2 = 12599726
    3 = 6658997
    4 = -28649192
    5 = 9721633
    6 = 35165139
    7 = -6518631
    8 = 8636159
    9 = 25009867""")
  nqx2 = text_to_int("""
    0 = 4551917
    1 = -35566825
    2 = 30679176
    3 = -49042125
    4 = 33959350
    5 = -51247417
    6 = 25326443
    7 = -343911
    8 = 60861973
    9 = -5123335""")
  q = 9
  nqx = text_to_int("""
    0 = -13289003
    1 = -10610101
    2 = -18822941
    3 = 22568421
    4 = -57737899
    5 = 381897
    6 = 10154798
    7 = -20523275
    8 = -53805819
    9 = -12115052""")
  t = text_to_int("""
    0 = -30510928
    1 = -6294382
    2 = -43370296
    3 = 49473031
    4 = -52932073
    5 = 27254547
    6 = -19779468
    7 = 8064868
    8 = -6501857
    9 = -19368463""")
  nqpqz = text_to_int("""
    0 = -33888280
    1 = -5926976
    2 = -38102520
    3 = 30543201
    4 = 64471200
    5 = 9227554
    6 = 32382658
    7 = -3982348
    8 = 59103743
    9 = -33196060""")
  nqz = text_to_int("""
    0 = -33052379
    1 = -45728
    2 = 10437185
    3 = -3960770
    4 = 8241289
    5 = -24248441
    6 = 30030157
    7 = -3112560
    8 = 22443607
    9 = -29401993""")
  nqpqx = text_to_int("""
    0 = 19675849
    1 = -3535166
    2 = -29970780
    3 = 3206566
    4 = 15177645
    5 = -19336894
    6 = -66951686
    7 = -31797160
    8 = 17821568
    9 = 6463020""")
  nqpqx2 = text_to_int("""
    0 = 76089964
    1 = 1448286
    2 = 13522696
    3 = -2877139
    4 = 60125253
    5 = 2338875
    6 = 17324566
    7 = -58455066
    8 = 44414287
    9 = 24217527""")
  nqpqz2 = text_to_int("""
    0 = -30510928
    1 = -6294382
    2 = -43370296
    3 = 49473031
    4 = -52932073
    5 = 27254547
    6 = -19779468
    7 = 8064868
    8 = -6501857
    9 = -19368463""")


def print_namespace(ns, mod):
  print('-----', ns.__name__, '-----')
  for n in dir(ns):
    if n[:2] != '__':
      val = getattr(ns, n)
      if isinstance(val, int):
        val = hex(val % mod)
      print(n, val)


def try_locate(p,
               a24,
               x_1,
               x_2,
               z_2,
               x_3,
               z_3,
               xx_2,
               zz_2,
               xx_3,
               zz_3,
               verbose=True):
  """Tries to locate a faulty computation.

    x_2, z_2, x_3, z_3 the state before a multiply step
    xx_2, zz_2, xx_3, zz_3 the state after a multiply step

  """
  # Forward:
  A = (x_2 + z_2) % p
  AA = A**2 % p
  B = (x_2 - z_2) % p
  BB = B**2 % p
  E = (AA - BB) % p
  C = (x_3 + z_3) % p
  D = (x_3 - z_3) % p
  DA = D * A % p
  CB = C * B % p
  correct_xx_3 = (DA + CB)**2 % p
  correct_zz_3 = x_1 * (DA - CB)**2 % p
  correct_xx_2 = AA * BB % p
  correct_zz_2 = E * (AA + a24 * E) % p

  # Check for errors in the multiplication DA and CB
  # x_2 = AA * BB
  # z_2 = E * (AA + a24 * E)
  # E = AA - BB
  # -> BB = x_2/AA
  # -> z_2 = (AA - x2/AA) * (AA + a24 * (AA-x2/AA)
  # -> z_2*A4 = (A4 - x2) * (A4 + a24 * (A4 - x2))

  div_2 = pow(2, -1, p)
  sum_da_cb = xdh_util.mod_square_roots(xx_3, p)
  diff_da_cb = xdh_util.mod_square_roots(xdh_util.moddiv(zz_3, x_1, p), p)
  print('DA =', hex(DA))
  for s in sum_da_cb:
    for d in diff_da_cb:
      da = (s + d) * div_2 % p
      print('da =', hex(da))
  print('CB =', hex(CB))
  for s in sum_da_cb:
    for d in diff_da_cb:
      cb = (s - d) * div_2 % p
      print('cb =', hex(cb))


def compare_namespace(ns1, ns2, mod):
  print('-----', ns1.__name__, ns2.__name__, '-----')
  for n in dir(ns1):
    if n[:2] != '__':
      val1 = getattr(ns1, n)
      val2 = getattr(ns2, n, None)
      if val2 is None:
        continue
      if val1 == val2:
        print(n, 'equal')
        continue
      if isinstance(val1, int):
        val1 = hex(val1 % mod)
      if isinstance(val2, int):
        val2 = hex(val2 % mod)
      print(n, 'different')
      print(val1)
      print(val2)


def test_faulty_step(before=None, after=None):
  if before is None:
    before = SampleBefore
  if after is None:
    after = SampleBad
  state_before = (before.nqx, before.nqz, before.nqpqx, before.nqpqz)
  state_after = (after.nqx2, after.nqz2, after.nqpqx2, after.nqpqz2)
  p = 2**255 - 19
  a24 = 121665
  try_locate(p, a24, before.q, *state_before, *state_after)


def test_samples():

  def mul_step(sample):
    return xdh_util.multiply_step(p, a24, sample.q, sample.nqx, sample.nqz,
                                  sample.nqpqx, sample.nqpqz)

  def inv_step(sample):
    pass

  p = 2**255 - 19
  a24 = 121665
  for s in [SampleGood, SampleBad, SampleBefore]:
    print_namespace(s, p)
  compare_namespace(SampleGood, SampleBad, p)
  print('----mul_step(SampleBefore)')
  for val in mul_step(SampleBefore):
    print(hex(val))
  state_before = (SampleBefore.nqx, SampleBefore.nqz, SampleBefore.nqpqx,
                  SampleBefore.nqpqz)
  set_before = set(state_before)
  for s, d in [(SampleGood, True), (SampleBad, True)]:
    print(s.__name__)
    for state in xdh_util.inverse_multiply_step(p, a24, s.q, s.nqx2, s.nqz2,
                                                s.nqpqx2, s.nqpqz2, d):
      print(state)
      if set(state) & set_before:
        print('---- possible state ----')
        for v in state:
          print(hex(v))


if __name__ == '__main__':
  test_samples()
  # test_multiply()
  test_faulty_step()
