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
# Run as:
#     sage -python ecdsa_test.py
"""Tests for testgen.ecdsa."""

import binascii
import ecdsa
import ecutil
import util


class TestVector(object):

  def __init__(self, curve, msg, qx, qy, r, s, hash_name):
    self.curve = curve
    self.msg = binascii.unhexlify(msg)
    self.qx = int(qx, 16)
    self.qy = int(qy, 16)
    self.r = int(r, 16)
    self.s = int(s, 16)
    self.hash_name = hash_name


test_vectors = [
    TestVector(
        ecutil.curveP256,
        '5905238877c77421f73e43ee3da6f2d9e2ccad5fc942dcec0cbd25482935faaf416983'
        'fe165b1a045ee2bcd2e6dca3bdf46c4310a7461f9a37960ca672d3feb5473e253605fb'
        '1ddfd28065b53cb5858a8ad28175bf9bd386a5e471ea7a65c17cc934a9d791e91491eb'
        '3754d03799790fe2d308d16146d5c9b0d0debd97d79ce8',
        '1ccbe91c075fc7f4f033bfa248db8fccd3565de94bbfb12f3c59ff46c271bf83',
        'ce4014c68811f9a21a1fdb2c0e6113e06db7ca93b7404e78dc7ccd5ca89a4ca9',
        'f3ac8061b514795b8843e3d6629527ed2afd6b1f6a555a7acabb5e6f79c8c2ac',
        '8bf77819ca05a6b2786c76262bf7371cef97b218e96f175a3ccdda2acc058903',
        'SHA-256'),
    TestVector(
        ecutil.curveP384,
        '6b45d88037392e1371d9fd1cd174e9c1838d11c3d6133dc17e65fa0c485dcca9f52d41'
        'b60161246039e42ec784d49400bffdb51459f5de654091301a09378f93464d52118b48'
        'd44b30d781eb1dbed09da11fb4c818dbd442d161aba4b9edc79f05e4b7e401651395b5'
        '3bd8b5bd3f2aaa6a00877fa9b45cadb8e648550b4c6cbe',
        'c2b47944fb5de342d03285880177ca5f7d0f2fcad7678cce4229d6e1932fcac11bfc3c'
        '3e97d942a3c56bf34123013dbf',
        '37257906a8223866eda0743c519616a76a758ae58aee81c5fd35fbf3a855b7754a36d4'
        'a0672df95d6c44a81cf7620c2d',
        '50835a9251bad008106177ef004b091a1e4235cd0da84fff54542b0ed755c1d6f25160'
        '9d14ecf18f9e1ddfe69b946e32',
        '0475f3d30c6463b646e8d3bf2455830314611cbde404be518b14464fdb195fdcc92eb2'
        '22e61f426a4a592c00a6a89721', 'SHA-384'),
    TestVector(
        ecutil.curveP521,
        '9ecd500c60e701404922e58ab20cc002651fdee7cbc9336adda33e4c1088fab1964ecb'
        '7904dc6856865d6c8e15041ccf2d5ac302e99d346ff2f686531d25521678d4fd3f76bb'
        'f2c893d246cb4d7693792fe18172108146853103a51f824acc621cb7311d2463c3361e'
        'a707254f2b052bc22cb8012873dcbb95bf1a5cc53ab89f',
        '0061387fd6b95914e885f912edfbb5fb274655027f216c4091ca83e19336740fd81aed'
        'fe047f51b42bdf68161121013e0d55b117a14e4303f926c8debb77a7fdaad1',
        '00e7d0c75c38626e895ca21526b9f9fdf84dcecb93f2b233390550d2b1463b7ee3f58d'
        'f7346435ff0434199583c97c665a97f12f706f2357da4b40288def888e59e6',
        '004de826ea704ad10bc0f7538af8a3843f284f55c8b946af9235af5af74f2b76e099e4'
        'bc72fd79d28a380f8d4b4c919ac290d248c37983ba05aea42e2dd79fdd33e8',
        '0087488c859a96fea266ea13bf6d114c429b163be97a57559086edb64aed4a18594b46'
        'fb9efc7fd25d8b2de8f09ca0587f54bd287299f47b2ff124aac566e8ee3b43',
        'SHA-512')
]


def test_sign_verify():
  curve = ecutil.curveP256
  (d, qx, qy) = ecutil.ec_generate_key(curve)
  digest = util.compute_hash('SHA-256', 'Hello')
  (r, s) = ecdsa.ecdsa_sign_hash(curve, digest, d)
  assert ecdsa.ecdsa_verify_hash(curve, digest, int(qx), int(qy), int(r),
                                 int(s))
  assert not ecdsa.ecdsa_verify_hash(curve, digest + '\x00',
                                     int(qx), int(qy), int(r), int(s))


def test_test_vectors():
  for test in test_vectors:
    assert ecdsa.ecdsa_verify_hash(test.curve,
                                   util.compute_hash(test.hash_name, test.msg),
                                   test.qx, test.qy, test.r, test.s)


if __name__ == '__main__':
  test_sign_verify()
  test_test_vectors()
