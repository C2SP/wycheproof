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

# From RFC 5528
CAMELLIA_CCM_KTV = [{
   "key" :   "C0 C1 C2 C3  C4 C5 C6 C7  C8 C9 CA CB  CC CD CE CF",
   "iv" :    "00 00 00 03  02 01 00 A0  A1 A2 A3 A4  A5",
   "aad" :   "00 01 02 03  04 05 06 07",
   "msg" :   "08 09 0A 0B  0C 0D 0E 0F  10 11 12 13  14 15 16 17"
             "18 19 1A 1B  1C 1D 1E",
   "ct" :    "BA 73 71 85  E7 19 31 04  92 F3 8A 5F  12 51 DA 55"
             "FA FB C9 49  84 8A 0D",
   "tag" :   "FC AE CE 74  6B 3D B9 AD"},
  {
   "key" :   "C0 C1 C2 C3  C4 C5 C6 C7  C8 C9 CA CB  CC CD CE CF",
   "iv" :    "00 00 00 04  03 02 01 A0  A1 A2 A3 A4  A5",
   "aad" :   "00 01 02 03  04 05 06 07",
   "msg" :   "08 09 0A 0B  0C 0D 0E 0F 10  11 12 13  14 15 16 17"
             "18 19 1A 1B  1C 1D 1E 1F",
   "ct" :    "5D 25 64 BF  8E AF E1 D9 95 26 EC 01  6D 1B F0 42"
             "4C FB D2 CD  62 84 8F 33",
   "tag" :   "60 B2 29 5D  F2 42 83 E8"},
  {
   "key" :   "C0 C1 C2 C3  C4 C5 C6 C7  C8 C9 CA CB  CC CD CE CF",
   "iv" :    "00 00 00 05  04 03 02 A0  A1 A2 A3 A4  A5",
   "aad" :   "00 01 02 03  04 05 06 07",
   "msg" :   "08 09 0A 0B  0C 0D 0E 0F 10 11 12 13  14 15 16 17"
             "18 19 1A 1B  1C 1D 1E 1F 20",
   "ct" :    "81 F6 63 D6  C7 78 78 17 F9 20 36 08  B9 82 AD 15"
             "DC 2B BD 87  D7 56 F7 92 04",
   "tag" :   "F5 51 D6 68  2F 23 AA 46"},
  {
   "key" :   "C0 C1 C2 C3  C4 C5 C6 C7  C8 C9 CA CB  CC CD CE CF",
   "iv" :    "00 00 00 06  05 04 03 A0  A1 A2 A3 A4  A5",
   "aad" :   "00 01 02 03  04 05 06 07  08 09 0A 0B",
   "msg" :   "0C 0D 0E 0F  10 11 12 13  14 15 16 17"
             "18 19 1A 1B  1C 1D 1E",
   "ct" :    "CA EF 1E 82  72 11 B0 8F  7B D9 0F 08"
             "C7 72 88 C0  70 A4 A0",
   "tag" :   "8B 3A 93 3A 63  E4 97 A0"},
 {
   "key" :   "C0 C1 C2 C3  C4 C5 C6 C7  C8 C9 CA CB  CC CD CE CF",
   "iv" :    "00 00 00 07  06 05 04 A0  A1 A2 A3 A4  A5",
   "aad" :   "00 01 02 03  04 05 06 07  08 09 0A 0B",
   "msg" :   "0C 0D 0E 0F  10 11 12 13  14 15 16 17  18 19 1A 1B"
             "1C 1D 1E 1F",
   "ct" :    "2A D3 BA D9  4F C5 2E 92  BE 43 8E 82  7C 10 23 B9"
             "6A 8A 77 25",
   "tag" :   "8F A1 7B A7  F3 31 DB 09"},
 {
   "key" :   "C0 C1 C2 C3  C4 C5 C6 C7  C8 C9 CA CB  CC CD CE CF",
   "iv" :    "00 00 00 08  07 06 05 A0  A1 A2 A3 A4  A5",
   "aad" :   "00 01 02 03  04 05 06 07  08 09 0A 0B",
   "msg" :   "0C 0D 0E 0F  10 11 12 13  14 15 16 17  18 19 1A 1B"
             "1C 1D 1E 1F  20",
   "ct" :    "FE A5 48 0B  A5 3F A8 D3  C3 44 22 AA  CE 4D E6 7F"
             "FA 3B B7 3B AB",
   "tag" :   "AB 36 A1 EE  4F E0 FE 28",},
]
