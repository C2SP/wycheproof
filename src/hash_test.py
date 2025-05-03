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

import hashlib
# Format Name, input, hex-result.
TESTVECTORS = [
 # Test vectors from python
 ('blake2b', b'abc',
   'ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923'),
 ('blake2s', b'abc',
   '508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982'),
 ('md5', b'abc',
   '900150983cd24fb0d6963f7d28e17f72'),
 ('md5-sha1', b'abc',
   '900150983cd24fb0d6963f7d28e17f72a9993e364706816aba3e25717850c26c9cd0d89d'),
 ('sha1', b'abc',
   'a9993e364706816aba3e25717850c26c9cd0d89d'),
 ('sha224', b'abc',
   '23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7'),
 ('sha256', b'abc',
   'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'),
 ('sha384', b'abc',
   'cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7'),
 ('sha3_224', b'abc',
   'e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf'),
 ('sha3_256', b'abc',
   '3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532'),
 ('sha3_384', b'abc',
   'ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25'),
 ('sha3_512', b'abc',
   'b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0'),
 ('sha512', b'abc',
   'ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f'),
 ('sha512_224', b'abc',
   '4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa'),
 ('sha512_256', b'abc',
   '53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23'),
 ('sm3', b'abc',
   '66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0'),
 # Online:
 ('keccak224', b'abc',
  'c30411768506ebe1c2871b1ee2e87d38df342317300a9b97a95ec6a8'),
 ('keccak256', b'abc',
  'e75f20377d6574b67399702947cb56849d2e02f7112c1d021603346c345b37f8'),
 ('keccak384', b'abc',
  'f7df1165f033337be098e7d288ad6a2f74409d7a60b49c36642218de161b1f99f8c681e4afaf31a34db29fb763e3c28e'),
 ('keccak512', b'abc'
  '18587dc2ea106b9a1563e32b3312421ca164c7f1f07bc922a9c83d77cea3a1e5d0c69910739025372dc14ac9642629379540c17e2a65b19d77aa511a9d00bb96'),
]

def test_hashlib(msg = b'abc'):
  print(f"hashes for {msg!r}")
  for name in sorted(hashlib.algorithms_available):
    try:
      md = hashlib.new(name)
      md.update(msg)
      print(f" ({name!r}, {msg!r},\n"
            f"   {md.digest().hex()!r}),")
    except Exception as ex:
      print(f"#  {name!r} : {str(ex)},")
    


if __name__ == "__main__":
  test_hashlib()
