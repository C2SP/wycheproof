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


# TODO: Unify the format of KTVs.

# message,
# keyMaterial,
# nonce,
# aad,
# ciphertext,
# tag
AES_GCM_KTV = [
    { "msg" : "001d0c231287c1182784554ca3a21908",
      "key" : "5b9604fe14eadba931b0ccf34843dab9",
      "iv" : "028318abc1824029138141a2",
      "aad" : "",
      "ct" : "26073cc1d851beff176384dc9896d5ff",
      "tag" : "0a3ea7a5487cb5f7d70fb6c58d038554"},
    { "msg" : "001d0c231287c1182784554ca3a21908",
      "key" : "5b9604fe14eadba931b0ccf34843dab9",
      "iv" : "921d2507fa8007b7bd067d34",
      "aad" : "00112233445566778899aabbccddeeff",
      "ct" : "49d8b9783e911913d87094d1f63cc765",
      "tag" : "1e348ba07cca2cf04c618cb4"},
    { "msg" : "2035af313d1346ab00154fea78322105",
      "key" : "aa023d0478dcb2b2312498293d9a9129",
      "iv" : "0432bc49ac34412081288127",
      "aad" : "aac39231129872a2",
      "ct" : "eea945f3d0f98cc0fbab472a0cf24e87",
      "tag" : "4bb9b4812519dadf9e1232016d068133"},
    { "msg" : "2035af313d1346ab00154fea78322105",
      "key" : "aa023d0478dcb2b2312498293d9a9129",
      "iv" : "0432bc49ac344120",
      "aad" : "aac39231129872a2",
      "ct" : "64c36bb3b732034e3a7d04efc5197785",
      "tag" : "b7d0dd70b00d65b97cfd080ff4b819d1"},
    { "msg" : "02efd2e5782312827ed5d230189a2a342b277ce048462193",
      "key" : "2034a82547276c83dd3212a813572bce",
      "iv" : "3254202d854734812398127a3d134421",
      "aad" : "1a0293d8f90219058902139013908190bc490890d3ff12a3",
      "ct" : "64069c2d58690561f27ee199e6b479b6369eec688672bde9",
      "tag" : "9b7abadd6e69c1d9ec925786534f5075"},
    { "msg" : "00010203040506070809",
      "key" : "92ace3e348cd821092cd921aa3546374299ab46209691bc28b8752d17f123c20",
      "iv" : "00112233445566778899aabb",
      "aad" : "00000000ffffffff",
      "ct" : "e27abdd2d2a53d2f136b",
      "tag" : "9a4a2579529301bcfb71c78d4060f52c"},
    { "msg" : "",
      "key" : "29d3a44f8723dc640239100c365423a312934ac80239212ac3df3421a2098123",
      "iv" : "00112233445566778899aabb",
      "aad" : "aabbccddeeff",
      "ct" : "",
      "tag" : "2a7d77fa526b8250cb296078926b5020"},
]

AES_CCM_KTV = [{
  "ref": "example 1",
  "Tlen" : 32,
  "K": "404142434445464748494a4b4c4d4e4f",
  "N": "10111213141516",
  "A": "0001020304050607",
  "P": "20212223",
  "B": "4f101112131415160000000000000004"
       "00080001020304050607000000000000"
       "20212223000000000000000000000000",
  "T": "6084341b",
  "Ctr0" : "07101112131415160000000000000000",
  "C"    : "7162015b4dac255d"},
  {
  "Tlen" : 48,
  "K" : "404142434445464748494a4b4c4d4e4f",
  "N" : "1011121314151617",
  "A" : "000102030405060708090a0b0c0d0e0f",
  "P" : "202122232425262728292a2b2c2d2e2f",
  "B" : "56101112131415161700000000000010"
        "0010000102030405060708090a0b0c0d"
        "0e0f0000000000000000000000000000"
        "202122232425262728292a2b2c2d2e2f",
  "T" : "7f479ffca464",
  "C" : "d2a1f0e051ea5f62081a7792073d593d"
        "1fc64fbfaccd"},
  {
  "Tlen" : 64,
  "K" : "404142434445464748494a4b4c4d4e4f",
  "N" : "101112131415161718191a1b",
  "A" : "000102030405060708090a0b0c0d0e0f"
        "10111213",
  "P" : "202122232425262728292a2b2c2d2e2f"
        "3031323334353637",
  "B" : "5a101112131415161718191a1b000018"
        "0014000102030405060708090a0b0c0d"
        "0e0f1011121300000000000000000000"
        "202122232425262728292a2b2c2d2e2f"
        "30313233343536370000000000000000",
  "T" : "67c99240c7d51048",
  "Ctr0" : "02101112131415161718191a1b000000",
  "C" : "e3b201a9f5b71a7a9b1ceaeccd97e70b"
        "6176aad9a4428aa5484392fbc1b09951",
 },
 {
  "Tlen" : 112,
  "K" : "404142434445464748494a4b4c4d4e4f",
  "N" : "101112131415161718191a1b1c",
  "A" : bytes(range(256)).hex() * 256,
  "P" : "202122232425262728292a2b2c2d2e2f"
        "303132333435363738393a3b3c3d3e3f",
  "Ctr0" : "01101112131415161718191a1b1c0000",
  "C" : "69915dad1e84c6376a68c2967e4dab61"
        "5ae0fd1faec44cc484828529463ccf72"
        "b4ac6bec93e8598e7f0dadbcea5b"
  },
]
