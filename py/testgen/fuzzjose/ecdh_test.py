# Copyright 2017 Google Inc. All Rights Reserved.
#
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
#     sage -python ecdh_test.py

import binascii
import ecdh
import ecutil
import util


class TestVector(object):

  def __init__(self, curve, priv, qx, qy, z):
    self.curve = curve
    self.priv = binascii.unhexlify(priv)
    self.qx = binascii.unhexlify(qx)
    self.qy = binascii.unhexlify(qy)
    self.z = binascii.unhexlify(z)


test_vectors = [
    TestVector(
        ecutil.curveP256,
        '7d7dc5f71eb29ddaf80d6214632eeae03d9058af1fb6d22ed80badb62bc1a534',
        '700c48f77f56584c5cc632ca65640db91b6bacce3a4df6b42ce7cc838833d287',
        'db71e509e3fd9b060ddb20ba5c51dcc5948d46fbf640dfe0441782cab85fa4ac',
        '46fc62106420ff012e54a434fbdd2d25ccc5852060561e68040dd7778997bd7b'),
    TestVector(
        ecutil.curveP521,
        '0000017eecc07ab4b329068fba65e56a1f8890aa935e57134ae0ffcce802735151f4ea'
        'c6564f6ee9974c5e6887a1fefee5743ae2241bfeb95d5ce31ddcb6f9edb4d6fc47',
        '000000685a48e86c79f0f0875f7bc18d25eb5fc8c0b07e5da4f4370f3a949034085433'
        '4b1e1b87fa395464c60626124a4e70d0f785601d37c09870ebf176666877a2046d',
        '000001ba52c56fc8776d9e8f5db4f0cc27636d0b741bbe05400697942e80b739884a83'
        'bde99e0f6716939e632bc8986fa18dccd443a348b6c3e522497955a4f3c302f676',
        '005fc70477c3e63bc3954bd0df3ea0d1f41ee21746ed95fc5e1fdf90930d5e136672d7'
        '2cc770742d1711c3c3a4c334a0ad9759436a4d3c5bf6e74b9578fac148c831'
    )
]


def test_basic():
  for curve in [ecutil.curveP256, ecutil.curveP384, ecutil.curveP521]:

    (priv1, qx1, qy1) = ecutil.ec_generate_key(curve)
    (priv2, qx2, qy2) = ecutil.ec_generate_key(curve)
    assert ecdh.compute_shared_secret(curve, priv1, qx2,
                                      qy2) == ecdh.compute_shared_secret(
                                          curve, priv2, qx1, qy1)


def test_test_vectors():
  for test in test_vectors:
    assert test.z == ecdh.compute_shared_secret(test.curve,
                                                util.bytes2int(test.priv),
                                                util.bytes2int(test.qx),
                                                util.bytes2int(test.qy))


if __name__ == '__main__':
  test_basic()
  test_test_vectors()
