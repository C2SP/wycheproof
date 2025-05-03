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

class Test(object):

  def __init__(self, **args):
    for k, v in args.items():
      self.__setattr__(k, v)


XCHACHA_POLY1305_KTV = [
    Test(
        pt="4c616469657320616e642047656e746c656d656e206f662074686520636c6173"
        "73206f66202739393a204966204920636f756c64206f6666657220796f75206f"
        "6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73"
        "637265656e20776f756c642062652069742e",
        aad="50515253c0c1c2c3c4c5c6c7",
        key="808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
        nonce="404142434445464748494a4b4c4d4e4f5051525354555657",
        polykey="7b191f80f361f099094f6f4b8fb97df8"
        "47cc6873a8f2b190dd73807183f907d5",
        ct="bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb"
        "731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452"
        "2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9"
        "21f9664c97637da9768812f615c68b13b52e",
        tag="c0875924c1c7987947deafd8780acf49",
        comment="draft-arciszewski-xchacha-02"),
]
