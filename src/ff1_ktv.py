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

FF1_KTV = [
  # From githup/capicalone/fpe, which claims the test
  # vectors are provided by NIST.
  {"key": "2b7e151628aed2a6abf7158809cf4f3c",
   "radix": 10,
   "tweak": "",
   "pt": [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
   "ct": [2, 4, 3, 3, 4, 7, 7, 4, 8, 4]
  },
  {"key": "2b7e151628aed2a6abf7158809cf4f3c",
   "radix": 10,
   "tweak": "39383736353433323130",
   "pt": [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
   "ct": [6, 1, 2, 4, 2, 0, 0, 7, 7, 3]
  },
  # sample #3
  {"key": "2b7e151628aed2a6abf7158809cf4f3c",
   "radix": 36,
   "tweak": "3737373770717273373737",
   "pt": [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18],
   "ct": [10, 9, 29, 31, 4, 0, 22, 21, 21, 9, 20, 13, 30, 5, 0, 9, 14, 30, 22]
  },
  # sample #4
  {"key": "2b7e151628aed2a6abf7158809cf4f3cef4359d8d580aa4f",
   "radix": 10,
   "tweak": "",
   "pt": [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
   "ct": [2, 8, 3, 0, 6, 6, 8, 1, 3, 2]
  },
  # sample #5
  {"key": "2b7e151628aed2a6abf7158809cf4f3cef4359d8d580aa4f",
   "radix": 10,
   "tweak": "39383736353433323130",
   "pt": [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
   "ct": [2, 4, 9, 6, 6, 5, 5, 5, 4, 9], 
  },
  # sample #6
  {"key": "2b7e151628aed2a6abf7158809cf4f3cef4359d8d580aa4f",
   "radix": 36,
   "tweak": "3737373770717273373737",
   "pt": [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18],
   "ct": [33, 11, 19, 3, 20, 31, 3, 5, 19, 27, 10, 32, 33, 31, 3, 2, 34, 28, 27]
  },
  # sample #7
  {"key": "2b7e151628aed2a6abf7158809cf4f3cef4359d8d580aa4f7f036d6f04fc6a94",
   "radix": 10,
   "tweak": "",
   "pt": [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
   "ct": [6, 6, 5, 7, 6, 6, 7, 0, 0, 9]
  },
  # sample #8
  {"key": "2b7e151628aed2a6abf7158809cf4f3cef4359d8d580aa4f7f036d6f04fc6a94",
   "radix": 10,
   "tweak": "39383736353433323130",
   "pt": [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
   "ct": [1, 0, 0, 1, 6, 2, 3, 4, 6, 3], 
  },
  # sample #9
  {"key": "2b7e151628aed2a6abf7158809cf4f3cef4359d8d580aa4f7f036d6f04fc6a94",
   "radix": 36,
   "tweak": "3737373770717273373737",
   "pt": [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18],
   "ct": [33, 28, 8, 10, 0, 10, 35, 17, 2, 10, 31, 34, 10, 21, 34, 35, 30, 32, 13]
  },
  # ---------   self generated
  {"key": "1b4b166184dc23147192dff130743d62",
   "radix": 36,
   "tweak": "01020304050607",
   "pt": [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
   "ct": [31, 12, 22, 4, 0, 3, 9, 16, 7, 7, 0]
  },

  {"key": "1b4b166184dc23147192dff130743d62",
   "radix": 64,
   "tweak": "01020304050607",
   "pt": [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
   "ct": [43, 44, 28, 49, 16, 17, 41, 30, 58, 37, 56]
  },

  {"key": "1b4b166184dc23147192dff130743d62",
   "radix": 255,
   "tweak": "01020304050607",
   "pt": [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
   "ct": [123, 9, 175, 15, 100, 152, 226, 239, 185, 20, 228]
  },

  {"key": "1b4b166184dc23147192dff130743d62",
   "radix": 256,
   "tweak": "01020304050607",
   "pt": [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
   "ct": [243, 190, 57, 94, 239, 132, 231, 58, 130, 12, 118]
  },

  {"key": "1b4b166184dc23147192dff130743d62",
   "radix": 257,
   "tweak": "01020304050607",
   "pt": [256, 255, 254, 253, 252, 251, 250],
   "ct": [84, 248, 131, 202, 233, 201, 75]  },

]

