# Copyright 2017 Google Inc. All Rights Reserved.
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
# ==============================================================================
#
# TODO(quannguyen): Add more functionalities.
"""Elliptic curve utility."""

# from sage.all_cmdline import *  # import sage library
from sage.all_cmdline import EllipticCurve
from sage.all_cmdline import GF
from sage.all_cmdline import Integer
import util


class Curve(object):

  def __init__(self, p, n, a, b, gx, gy):
    if not (util.isint(p) and util.isint(n) and util.isint(a) and
            util.isint(b) and util.isint(gx) and util.isint(gy)):
      raise ValueError('p, n, a, b, gx, gy must be integer')
    self.ec = self._curve(Integer(p), Integer(a), Integer(b))
    self.g = self.ec(Integer(gx), Integer(gy))
    self.n = Integer(n)

  def _curve(self, p, a, b):
    k = GF(p)
    return EllipticCurve(k, [Integer(0), Integer(0), Integer(0), a, b])


def ec_generate_key(curve):
  k = util.randint(1, int(curve.n))
  (qx, qy, _) = k * curve.g
  return (k, qx, qy)


curveP256 = Curve(  # pylint: disable=invalid-name
    int('1157920892103562487626974469494075735300861434152903141955336313088670'
        '97853951'),
    int('1157920892103562487626974469494075735299969552241357603424222590610685'
        '12044369'),
    int('1157920892103562487626974469494075735300861434152903141955336313088670'
        '97853948'),
    int('4105836372515214212932612978004726840911444101599372555483525631403946'
        '7401291'),
    int('6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296', 16),
    int('4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5', 16))
curveP384 = Curve(  # pylint: disable=invalid-name
    int('3940200619639447921227904010014361380507973927046544666794829340424572'
        '1771496870329047266088258938001861606973112319'),
    int('3940200619639447921227904010014361380507973927046544666794690527962765'
        '9399113263569398956308152294913554433653942643'),
    int('3940200619639447921227904010014361380507973927046544666794829340424572'
        '1771496870329047266088258938001861606973112316'),
    int('b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac65639'
        '8d8a2ed19d2a85c8edd3ec2aef', 16),
    int('aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f2'
        '5dbf55296c3a545e3872760ab7', 16),
    int('3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1'
        'ce1d7e819d7a431d7c90ea0e5f', 16))

curveP521 = Curve(  # pylint: disable=invalid-name
    int('6864797660130609714981900799081393217269435300143305409394463459185543'
        '1833976560521225596406614545549772963113914808580371219879997166438125'
        '74028291115057151'),
    int('6864797660130609714981900799081393217269435300143305409394463459185543'
        '1833976553942450577463332171975329639963713633211138647686124403803403'
        '72808892707005449'),
    int('6864797660130609714981900799081393217269435300143305409394463459185543'
        '1833976560521225596406614545549772963113914808580371219879997166438125'
        '74028291115057148'),
    int('51953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e15619'
        '3951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00', 16),
    int('c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b'
        '5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66', 16),
    int('011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97'
        'ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650', 16))
