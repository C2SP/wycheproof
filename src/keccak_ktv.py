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

# Test vectors for KECCAK-nnn('a' * n) for long n.
# n = 0
# KECCAK_224 f71837502ba8e10837bdd8d365adb85591895602fc552b48b7390abd
# KECCAK_256 c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470
# KECCAK_384 2c23146a63a29acf99e73b88f8c24eaa7dc60aa771780ccc006afbfa8fe2479b2dd2b21362337441ac12b515911957ff
# KECCAK_512 0eab42de4c3ceb9235fc91acffe746b29c29a8c366b7c60e4e67c466f36a4304c00fa9caf9d87976ba469bcbe06713b435f091ef2769fb160cdab33d3670680e
# 0.009102106094360352
# n = 1000000
# KECCAK_224 19f9167be2a04c43abd0ed554788101b9c339031acc8e1468531303f
# KECCAK_256 fadae6b49f129bbb812be8407b7b2894f34aecf6dbd1f9b0f0c7e9853098fc96
# KECCAK_384 0c8324e1ebc182822c5e2a086cac07c2fe00e3bce61d01ba8ad6b71780e2dec5fb89e5ae90cb593e57bc6258fdd94e17
# KECCAK_512 5cf53f2e556be5a624425ede23d0e8b2c7814b4ba0e4e09cbbf3c2fac7056f61e048fc341262875ebc58a5183fea651447124370c1ebf4d6c89bc9a7731063bb
# 22.125170707702637
# n = 2147483647
# KECCAK_224 ecbd20f13ccec2ca90e638825d815e2823193a15476bbd9c70fa1cf8
# KECCAK_256 9932ed01cadcaffa583c7cac4586bf3aa2b82e3c28501200276d778423f471f8
# KECCAK_384 6fad5d86e01ac7cda864fb89fb5f9533516af12a2730aae663c766a910316677cf0833f9f7d8ff2316d63737fb25e74a
# KECCAK_512 d0dab1cf3b6b87a38593ebf9f9dfea85513a8e2884f2c8f126f456b0e730fbcfb423a9bd32849f077885ab9b0632402968448b872990e8255448e52883dc04ae
# 47223.33699417114
# n = 5000000000
# KECCAK_224 eb0d1cbaf604ed955fafd528c1d945f05f97ba6bfcfc57984d662913
# KECCAK_256 875ff21c135ab9eb8a57da79f0f02c3ce0913dc9faad111e6f165dfce9715c45
# KECCAK_384 529028480fc183ca7c6dc5a84270b5fe14babaf9618ce4512e27210ba1041fbdc55f6557098335eff1982cc8b078ec4f
# KECCAK_512 08e38c32234f19c7c7dfb60b9632e60f33b67eebaa9305908861657d51af9850a82ea7a0a0733ffd83b3c6ecca437ace980048307b40df4e69ed7b290df3ea0b
# 109569.42583251

