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

import keywrap

# Format: [key, bytes to wrap, wrapped result]
test_vectors_rfc3394 = [
  ["000102030405060708090A0B0C0D0E0F",
   "00112233445566778899AABBCCDDEEFF",
   "1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5"],
  ["000102030405060708090A0B0C0D0E0F1011121314151617",
   "00112233445566778899AABBCCDDEEFF",
   "96778B25AE6CA435F92B5B97C050AED2468AB8A17AD84E5D"],
  ["000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
   "00112233445566778899AABBCCDDEEFF",
   "64E8C3F9CE0F5BA263E9777905818A2A93C8191E7D6E8AE7"],
  ["000102030405060708090A0B0C0D0E0F1011121314151617",
   "00112233445566778899AABBCCDDEEFF0001020304050607",
   "031D33264E15D33268F24EC260743EDCE1C6C7DDEE725A936BA814915C6762D2"],
  ["000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
   "00112233445566778899AABBCCDDEEFF0001020304050607",
   "A8F9BC1612C68B3FF6E6F4FBE30E71E4769C8B80A32CB8958CD5D17D6B254DA1"],
  ["000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
   "00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F",
   "28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43B"
   "FB988B9B7A02DD21"],
]

test_vectors_rfc5649 = [
  ["5840df6e29b02af1ab493b705bf16ea1ae8338f4dcc176a8",
   "c37b7e6492584340bed12207808941155068f738",
   "138bdeaa9b8fa7fc61f97742e72248ee5ae6ae5360d1ae6a5f54f373fa543b6a"],
  ["5840df6e29b02af1ab493b705bf16ea1ae8338f4dcc176a8",
   "466f7250617369",
   "afbeb0f07dfbf5419200f2ccb50bb24f"]
]

test_vectors_rfc3537 = [
  ["5840df6e 29b02af1 ab493b70 5bf16ea1 ae8338f4 dcc176a8",
   "c37b7e64 92584340 bed12207 80894115 5068f738",
   "9fa0c146 5291ea6d b55360c6 cb95123c d47b38cc e84dd804 fbcec5e3 75c3cb13"],
]

def testAesWrap():
  for k,d,res in test_vectors_rfc3394:
    w = keywrap.AesWrap(bytes.fromhex(k))
    wrapped = w.wrap(bytes.fromhex(d))
    assert bytes.fromhex(res) == wrapped
    unwrapped = w.unwrap(wrapped)
    assert bytes.fromhex(d) == unwrapped

def testAesKwp():
  for k,d,res in test_vectors_rfc5649:
    w = keywrap.AesKwp(bytes.fromhex(k))
    wrapped = w.wrap(bytes.fromhex(d))
    assert bytes.fromhex(res) == wrapped
    unwrapped = w.unwrap(wrapped)
    assert bytes.fromhex(d) == unwrapped

def testHmacWithAesWrap():
  for k,d,res in test_vectors_rfc3537:
    w = keywrap.HmacWithAesWrap(bytes.fromhex(k))
    unwrapped = w.unwrap(bytes.fromhex(res))
    assert bytes.fromhex(d) == unwrapped

if __name__ == "__main__":
  testAesWrap()
  testAesKwp()
  testHmacWithAesWrap()
