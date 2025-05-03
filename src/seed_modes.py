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

import seed
import encryption_mode
import padding

# TODO: add OIDs.
#   Things I have so far:
#   "1.2.410.200004.1.4":        id-seedCBC          RFC 4009, RFC 4269
#   RFC 4009 gives no details on the padding used for CBC. Neither does RFC 4269
# From openssl:
#   "1.2.410.200004.1.3"  SeedEcb
#   "1.2.410.200004.1.5"  SeedCfb
#   "1.2.410.200004.1.6"  SeedOfb
#   but so far I don't have another reference for comparison.
#   It is also unclear if the Cfb mode fixes the feedback.

class SeedEcb(encryption_mode.Ecb):
  block_cipher = seed.Seed
  padding_scheme = None
  oids = {128: "1.2.410.200004.1.3"}

class SeedEcbNoPadding(SeedEcb):
  padding_scheme = padding.NoPadding

class SeedEcbPkcs5(SeedEcb):
  padding_scheme = padding.Pkcs5Padding


class SeedCbcNoPadding(encryption_mode.Cbc):
  block_cipher = seed.Seed
  padding_scheme = padding.NoPadding


class SeedCbcPkcs5(encryption_mode.Cbc):
  block_cipher = seed.Seed
  padding_scheme = padding.Pkcs5Padding
  oids = {128: "1.2.410.200004.1.4"}


class SeedOfb(encryption_mode.Ofb):
  block_cipher = seed.Seed
  oids = {128: "1.2.410.200004.1.6"}


class SeedCfb128(encryption_mode.Cfb):
  block_cipher = seed.Seed
  feedback_size_in_bits = 128
  oids = {128: "1.2.410.200004.1.5"}


class SeedCtr(encryption_mode.Ctr):
  block_cipher = seed.Seed
