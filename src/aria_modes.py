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

import aria
import encryption_mode
import padding


class AriaEcb(encryption_mode.Ecb):
  block_cipher = aria.Aria
  padding_scheme = None
  # OIDs for key sizes in bits. Defined in RFC 5794.
  # TODO: It is unclear to me if the OID specifies a padding.
  oids = { 128: "1.2.410.200046.1.1.1",
           192: "1.2.410.200046.1.1.6",
           256: "1.2.410.200046.1.1.11"}

class AriaEcbNoPadding(AriaEcb):
  padding_scheme = padding.NoPadding

class AriaEcbPkcs5(AriaEcb):
  padding_scheme = padding.Pkcs5Padding


class AriaCbcNoPadding(encryption_mode.Cbc):
  block_cipher = aria.Aria
  padding_scheme = padding.NoPadding


class AriaCbcPkcs5(encryption_mode.Cbc):
  block_cipher = aria.Aria
  padding_scheme = padding.Pkcs5Padding
  # OIDs for key sizes in bits. Defined in RFC 5794.
  oids = {
      128: "1.2.410.200046.1.1.2",
      192: "1.2.410.200046.1.1.7",
      256: "1.2.410.200046.1.1.12"
  }


class AriaCfb128(encryption_mode.Cfb):
  block_cipher = aria.Aria
  feedback_size_in_bits = 128
  # OIDs for key sizes in bits. Defined in RFC 5794.
  # The feedback size is not specified by the OID.
  # Appendix B of RFC 5794, specifies that algorithms are
  # encoded as { OID PARAMS }.
  oids = { 128: "1.2.410.200046.1.1.3",
           192: "1.2.410.200046.1.1.8",
           256: "1.2.410.200046.1.1.13"}


class AriaOfb(encryption_mode.Ofb):
  block_cipher = aria.Aria
  # OIDs for key sizes in bits. Defined in RFC 5794.
  oids = { 128: "1.2.410.200046.1.1.4",
           192: "1.2.410.200046.1.1.9",
           256: "1.2.410.200046.1.1.14"}


class AriaCtr(encryption_mode.Ctr):
  block_cipher = aria.Aria
  # OIDs for key sizes in bits. Defined in RFC 5794.
  oids = { 128: "1.2.410.200046.1.1.5",
           192: "1.2.410.200046.1.1.10",
           256: "1.2.410.200046.1.1.15"}
