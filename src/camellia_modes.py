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

import camellia
import encryption_mode
import padding

# TODO: add OIDs.
# Defined in RFC 3657 and RFC 3713.
# The mapping of OIDs to algorithms is not clear to me, because I haven't
# found a place where the paddings are clearly discussed.
# RFC 3657 refers to RFC 3370, which does not specify the padding.
# RFC 3713 specifies in Section 3 that the cbc algorithm include PKCS #7 padding
# and refers to RFC 2315.
# RFC 3657 and RFC 3713 only define CBC. Not sure what a good reference for
# the OIDs for the other modes is.
#
# CamelliaGcm
# There is no wide support for CamelliaGcm.
# Some examples are:
# RFC 6367
# RFC 8996
# draft-kato-ipsec-camellia-gcm-03 appears abandoned, contains KTVs.
# https://forum.palemoon.org/viewtopic.php?f=1&t=10827&p=75697&hilit=camellia
# https://www.sciencedirect.com/science/article/abs/pii/S0141933116300291
# There are TLS identifiers like TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384 
#
# Generally, I'm waiting for an RFC for adding this.

class CamelliaEcb(encryption_mode.Ecb):
  block_cipher = camellia.Camellia
  padding_scheme = None
  oids = {
      128: "0.3.4401.5.3.1.9.1",
      192: "0.3.4401.5.3.1.9.21",
      256: "0.3.4401.5.3.1.9.41"}

class CamelliaEcbNoPadding(CamelliaEcb):
  padding_scheme = padding.NoPadding

class CamelliaEcbPkcs5(CamelliaEcb):
  padding_scheme = padding.Pkcs5Padding


class CamelliaCbcNoPadding(encryption_mode.Cbc):
  block_cipher = camellia.Camellia
  padding_scheme = padding.NoPadding


class CamelliaCbcPkcs5(encryption_mode.Cbc):
  name = "CAMELLIA-CBC-PKCS5"
  block_cipher = camellia.Camellia
  padding_scheme = padding.Pkcs5Padding
  # OIDs for key sizes in bits.
  # Defined in RFC 3657 and RFC 3713.
  # RFC 3657 refers to RFC 3370, which does not specify the padding.
  # RFC 3713 specifies in Section 3 that the cbc algorithm include PKCS #7 padding
  # and refers to RFC 2315.
  oids = {
      128: "1.2.392.200011.61.1.1.1.2",
      192: "1.2.392.200011.61.1.1.1.3",
      256: "1.2.392.200011.61.1.1.1.4"
  }


class CamelliaOfb(encryption_mode.Ofb):
  block_cipher = camellia.Camellia
  oids = {
      128: "0.3.4401.5.3.1.9.3",
      192: "0.3.4401.5.3.1.9.23",
      256: "0.3.4401.5.3.1.9.43"}


class CamelliaCfb128(encryption_mode.Cfb):
  block_cipher = camellia.Camellia
  feedback_size_in_bits = 128
  oids = {
      128: "0.3.4401.5.3.1.9.4",
      192: "0.3.4401.5.3.1.9.24",
      256: "0.3.4401.5.3.1.9.44"}


class CamelliaCtr(encryption_mode.Ctr):
  block_cipher = camellia.Camellia
  oids = {
      128: "0.3.4401.5.3.1.9.9",
      192: "0.3.4401.5.3.1.9.29",
      256: "0.3.4401.5.3.1.9.49"}
