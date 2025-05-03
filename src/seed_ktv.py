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

# From RFC 4269
SEED_KTV = [
  { "key" : "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
    "pt" :  "00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F",
    "ct" :  "5E BA C6 E0 05 4E 16 68 19 AF F1 CC 6D 34 6C DB"},
  { "key" : "00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F",
    "pt" :  "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
    "ct" :  "C1 1F 22 F2 01 40 50 50 84 48 35 97 E4 37 0F 43"},
  { "key" : "47 06 48 08 51 E6 1B E8 5D 74 BF B3 FD 95 61 85",
    "pt" :  "83 A2 F8 A2 88 64 1F B9 A4 E9 A5 CC 2F 13 1C 7D",
    "ct" :  "EE 54 D1 3E BC AE 70 6D 22 6B C3 14 2C D4 0D 4A"},
  { "key" : "28 DB C3 BC 49 FF D8 7D CF A5 09 B1 1D 42 2B E7",
    "pt" :  "B4 1E 6B E2 EB A8 4A 14 8E 2E ED 84 59 3C 5E C7",
    "ct" :  "9B 9B 7B FC D1 81 3C B9 5D 0B 36 18 F4 0F 51 22"},
]


# RFC 5669
SEED_CCM_KTV = [{
  "key" : "974bee725d44fc3992267b284c3c6750",
  "iv" :  "000020e8f5eb00000000315e",
  "msg" : "f57af5fd4ae19562976ec57a5a7ad55a"
          "5af5c5e5c5fdf5c55ad57a4a7272d572"
          "62e9729566ed66e97ac54a4a5a7ad5e1"
          "5ae5fdd5fd5ac5d56ae56ad5c572d54a"
          "e54ac55a956afd6aed5a4ac562957a95"
          "16991691d572fd14e97ae962ed7a9f4a"
          "955af572e162f57a956666e17ae1f54a"
          "95f566d54a66e16e4afd6a9f7ae1c5c5"
          "5ae5d56afde916c5e94a6ec56695e14a"
          "fde1148416e94ad57ac5146ed59d1cc5",
   "aad" :"8008315ebf2e6fe020e8f5eb",
   "ct" : "486843a881df215a8574650ddabf5dbb"
          "2650f06f51252bccaeb4012899d6d71e"
          "30c64dad5ead5d8ba65ffe9d79aaf30d"
          "c9e6334490c07e7533d704114a9006ec"
          "b3b3bff59ecf585485bc0bd286ed434c"
          "fd684d19a1ad514ca5f37b71d93288c0"
          "7cf4d5e9b83db8becc8c692a7279b6a9"
          "ac62ba970fc54f46dcc926d434c0b5ad"
          "8678fbf0e7a03037924dae342ef64fa6"
          "5b8eaea260fecb477a57e3919c5dab82",
    "tag" : "b0a8274cf6a8bb6cc466"},
]

SEED_GCM_KTV = [{
    "key" : "e91e5e75da65554a48181f3846349562",
    "iv" :  "000020e8f5eb00000000315e",
    "msg":"f57af5fd4ae19562976ec57a5a7ad55a"
          "5af5c5e5c5fdf5c55ad57a4a7272d572"
          "62e9729566ed66e97ac54a4a5a7ad5e1"
          "5ae5fdd5fd5ac5d56ae56ad5c572d54a"
          "e54ac55a956afd6aed5a4ac562957a95"
          "16991691d572fd14e97ae962ed7a9f4a"
          "955af572e162f57a956666e17ae1f54a"
          "95f566d54a66e16e4afd6a9f7ae1c5c5"
          "5ae5d56afde916c5e94a6ec56695e14a"
          "fde1148416e94ad57ac5146ed59d1cc5",
   "aad" : "8008315ebf2e6fe020e8f5eb",
   "ct" : "8a5363682c6b1bbf13c0b09cf747a551"
          "2543cb2f129b8bd0e92dfadf735cda8f"
          "88c4bbf90288f5e58d20c4f1bb0d5844"
          "6ea009103ee57ba99cdeabaaa18d4a9a"
          "05ddb46e7e5290a5a2284fe50b1f6fe9"
          "ad3f1348c354181e85b24f1a552a1193"
          "cf0e13eed5ab95ae854fb4f5b0edb2d3"
          "ee5eb238c8f4bfb136b2eb6cd7876042"
          "0680ce1879100014f140a15e07e70133"
          "ed9cbb6d57b75d574acb0087eefbac99",
    "tag" : "36cd9ae602be3ee2cd8d5d9d"},
]
