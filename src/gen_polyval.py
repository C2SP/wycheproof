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

import aes_gcm_siv
import gf
import mac_test_vector
import producer
import util
import test_vector

class PolyValTestVectorGenerator(mac_test_vector.MacTestVectorGenerator):
  def __init__(self):
    super().__init__("PolyVal")

  @util.type_check
  def mac(self, key: bytes, msg: bytes, macsize: int = None) -> bytes:
    if macsize is None:
      macsize = 16
    elif macsize != 16:
      raise ValueError("Result must be 16 bytes")
    if len(key) != 16:
      raise ValueError("Expecting an element of GF(2^128) in little endian order")
    if len(msg) % 16 != 0:
      raise ValueError("PolyVal is only defined for multiples of 16")
    h = aes_gcm_siv.bytes2gf(key)
    g = h * h.field([h.field.degree()]).inverse()
    s = gf.F128siv(0)
    for i in range(0, len(msg), 16):
      x = aes_gcm_siv.bytes2gf(msg[i:i+16])
      s = (s + x) * g
    return aes_gcm_siv.gf2bytes(s)

  def generate_simple(self):
    """Generates simple test vectors that are useful for debugging."""
    zero = bytes(16)
    one = bytes([1]) + bytes(15)
    two = bytes([2]) + bytes(15)
    msb = bytes(15) + bytes([0x80])
    all_one = bytes([0xff]) * 16
    ran = bytes(range(1, 17))
    for key, msg in [
      (one, one),
      (one, msb),
      (one, all_one),
      (one, ran),
      (two, one + zero),
      (two, one + 2 * zero),
      (ran, ran)
    ]:
      self.add_mac(key, msg, 16)

  def generate_prand(self):
    key_sizes = [16]
    mac_sizes = [16]
    # cnt, keysize, msgsize, macsize
    self.generate_pseudorandom(1, key_sizes, [0], mac_sizes, "empty message")
    self.generate_pseudorandom(1, key_sizes, list(range(16, 129, 16)), mac_sizes,
                               "")
  def generate_special(self):
    for key in [bytes([0xff]) * 16,
                bytes(15) + bytes([1]),
                bytes([1]) + bytes(15)]:
      for msg in [bytes([0xff])*32, bytes([0xff]*64)]:
        self.add_mac(key, msg, 16)

  def generate_all(self):
    self.generate_simple()
    self.generate_prand()
    self.generate_special()


class PolyvalProducer(producer.Producer):

  def parser(self):
    return self.default_parser()

  def generate_test_vectors(self, namespace):
    tv = PolyValTestVectorGenerator()
    tv.generate_all()
    return tv.test


# DEPRECATED: Use Producer.produce() instead
def main(namespace):
  PbkdfProducer().produce(namespace)


if __name__ == "__main__":
  PbkdfProducer().produce_with_args()
