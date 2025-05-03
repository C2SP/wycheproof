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

import sip_hash
import mac_test_vector
import producer
import util
import typing
import test_vector

ALGORITHMS = ["SipHash-1-3", "SipHash-2-4", "SipHashX-2-4", "SipHash-4-8"]


class SipHashTestVectorGenerator(mac_test_vector.MacTestVectorGenerator):

  def __init__(self, name: str, namespace):
    super().__init__(name, namespace)
    self.alg = name

    if name == "SipHash-1-3":
      self.c = 1
      self.d = 3
      self.mac_size = 8
      self.keysizes = [16]
    elif name == "SipHash-2-4":
      self.c = 2
      self.d = 4
      self.mac_size = 8
      self.keysizes = [16]
    elif name == "SipHashX-2-4":
      self.c = 2
      self.d = 4
      self.mac_size = 16
      self.keysizes = [16]
    elif name == "SipHash-4-8":
      self.c = 4
      self.d = 8
      self.mac_size = 8
      self.keysizes = [16]
    else:
      raise ValueError("Unsupported name:" + name)

  @util.type_check
  def mac(self, key: bytes, msg: bytes, mac_size_in_bytes: int) -> bytes:
    if self.mac_size != mac_size_in_bytes:
      raise ValueError("Wrong MAC size")
    p = sip_hash.SipHash(key, out_len=self.mac_size, c=self.c, d=self.d)
    return p.prf(msg).to_bytes(self.mac_size, "little")

  def gen_prand(self, key_sizes: list[int]):
    mac_sizes = [self.mac_size]
    # cnt, keysize, msgsize
    self.generate_pseudorandom(1, key_sizes, [0], mac_sizes, "empty message")
    # small sizes:
    for i in range(33):
      self.generate_pseudorandom(1, key_sizes, [i], mac_sizes,
                                 f"message of size {i}")
    for i in [47, 48, 49, 112, 127, 128, 255]:
      self.generate_pseudorandom(1, key_sizes, [i], mac_sizes,
                                 f"message of size {i}")

  def generate_all(self):
    key_sizes = self.keysizes
    self.gen_prand(key_sizes)


def generate(namespace):
  alg = namespace.algorithm
  tv = SipHashTestVectorGenerator(alg, namespace)
  tv.generate_all()
  return tv.test

class SipHashProducer(producer.Producer):

  def parser(self):
    res = self.default_parser()
    res.add_argument(
        "--algorithm",
        type=str,
        choices=ALGORITHMS,
        default="SipHash24",
        help="the name of the algorithm")
    return res

  def generate_test_vectors(self, namespace):
    return generate(namespace)


# DEPRECATED: Use Producer.produce() instead
def main(namespace):
  SipHashProducer().produce(namespace)


if __name__ == "__main__":
  SipHashProducer().produce_with_args()
