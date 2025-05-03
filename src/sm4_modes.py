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

import sm4
import encryption_mode
import padding

# OIDs from openssl:
# "1.2.156.10197.1.104.1": "sm4-ecb"
# "1.2.156.10197.1.104.2": "sm4-cbc"
# "1.2.156.10197.1.104.3": "sm4-ofb128
# "1.2.156.10197.1.104.4": "sm4-cfb128
# "1.2.156.10197.1.104.5": "sm4-cfb1"
# "1.2.156.10197.1.104.6": "sm4-cfb8"
# "1.2.156.10197.1.104.7": "sm4-ctr"
# TODO: Is there an RFC? Do the OIDs specify padding?

class Sm4Ecb(encryption_mode.Ecb):
  block_cipher = sm4.Sm4
  padding_scheme = None
  # OIDs for key sizes in bits. This is from openssl.
  # TODO: Does the OID specify the padding?
  oids = {128: "1.2.156.10197.1.104.1"}


class Sm4EcbNoPadding(Sm4Ecb):
  padding_scheme = padding.NoPadding


class Sm4EcbPkcs5(Sm4Ecb):
  padding_scheme = padding.Pkcs5Padding


class Sm4CbcNoPadding(encryption_mode.Cbc):
  block_cipher = sm4.Sm4
  padding_scheme = padding.NoPadding


class Sm4CbcPkcs5(encryption_mode.Cbc):
  block_cipher = sm4.Sm4
  padding_scheme = padding.Pkcs5Padding
  # OIDs for key sizes in bits. This is from openssl.
  oids = {128: "1.2.156.10197.1.104.2"}


class Sm4Cfb128(encryption_mode.Cfb):
  block_cipher = sm4.Sm4
  feedback_size_in_bits = 128
  # OIDs for key sizes in bits. This is from openssl.
  oids = {128: "1.2.156.10197.1.104.4"}


class Sm4Ofb(encryption_mode.Ofb):
  block_cipher = sm4.Sm4
  # OIDs for key sizes in bits. This is from openssl.
  oids = {128: "1.2.156.10197.1.104.3"}


class Sm4Ctr(encryption_mode.Ctr):
  block_cipher = sm4.Sm4
  # OIDs for key sizes in bits. This is from openssl.
  oids = {128: "1.2.156.10197.1.104.3"}
