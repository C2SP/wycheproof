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

# IEEE P1619
# - this also uses little endian encoding for the sequence
# - numbers.
AES_XTS_KTV = [
    {
        "key":
            "00000000000000000000000000000000"
            "00000000000000000000000000000000",
        "seq":
            0,
        "pt":
            "00000000000000000000000000000000"
            "00000000000000000000000000000000",
        "ct":
            "917cf69ebd68b2ec9b9fe9a3eadda692"
            "cd43d2f59598ed858c02c2652fbf922e"
    },
    {
        "key":
            "11111111111111111111111111111111"
            "22222222222222222222222222222222",
        "seq":
            0x3333333333,
        "pt":
            "44444444444444444444444444444444"
            "44444444444444444444444444444444",
        "ct":
            "c454185e6a16936e39334038acef838b"
            "fb186fff7480adc4289382ecd6d394f0",
    },
    {
        "key":
            "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0"
            "bfbebdbcbbbab9b8b7b6b5b4b3b2b1b0",
        "seq":
            0x123456789a,
        "pt":
            "000102030405060708090a0b0c0d0e0f10",
        "ct":
            "6c1625db4671522d3d7599601de7ca09ed"
    },
    {
        "key":
            "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0"
            "bfbebdbcbbbab9b8b7b6b5b4b3b2b1b0",
        "seq":
            0x123456789a,
        "pt":
            "000102030405060708090a0b0c0d0e0f"
            "101112131415161718191a1b1c1d1e",
        "ct":
            "d05bc090a8e04f1b3d3ecdd5baec0fd4"
            "edbf9dace45d6f6a7306e64be5dd82",
    },
    
    { "key":
      "e0e1e2e3e4e5e6e7e8e9eaebecedeeef"
      "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf",
      "seq":
          0xa987654321,
      "pt":
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f "
        "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
        "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f"
        "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f"
        "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"
        "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
        "c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf"
        "e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
        "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f"
        "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f"
        "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"
        "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
        "c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf"
        "e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
      "ct":
        "38b45812ef43a05bd957e545907e223b954ab4aaf088303ad910eadf14b42be6"
        "8b2461149d8c8ba85f992be970bc621f1b06573f63e867bf5875acafa04e42cc"
        "bd7bd3c2a0fb1fff791ec5ec36c66ae4ac1e806d81fbf709dbe29e471fad3854"
        "9c8e66f5345d7c1eb94f405d1ec785cc6f6a68f6254dd8339f9d84057e01a177"
        "41990482999516b5611a38f41bb6478e6f173f320805dd71b1932fc333cb9ee3"
        "9936beea9ad96fa10fb4112b901734ddad40bc1878995f8e11aee7d141a2f5d4"
        "8b7a4e1e7f0b2c04830e69a4fd1378411c2f287edf48c6c4e5c247a19680f7fe"
        "41cefbd49b582106e3616cbbe4dfb2344b2ae9519391f3e0fb4922254b1d6d2d"
        "19c6d4d537b3a26f3bcc51588b32f3eca0829b6a5ac72578fb814fb43cf80d64"
        "a233e3f997a3f02683342f2b33d25b492536b93becb2f5e1a8b82f5b88334272"
        "9e8ae09d16938841a21a97fb543eea3bbff59f13c1a18449e398701c1ad51648"
        "346cbc04c27bb2da3b93a1372ccae548fb53bee476f9e9c91773b1bb19828394"
        "d55d3e1a20ed69113a860b6829ffa847224604435070221b257e8dff783615d2"
        "cae4803a93aa4334ab482a0afac9c0aeda70b45a481df5dec5df8cc0f423c77a"
        "5fd46cd312021d4b438862419a791be03bb4d97c0e59578542531ba466a83baf"
        "92cefc151b5cc1611a167893819b63fb8a6b18e86de60290fa72b797b0ce59f3",
      }
]
