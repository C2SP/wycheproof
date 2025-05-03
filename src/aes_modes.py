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

import aes
import encryption_mode
import padding


class AesEcb(encryption_mode.Ecb):
  # TODO: Does the algorithm described defined by the OID include
  #   a padding? So far I haven"t found an RFC describing the OID.
  #   For CBC the situation is described in RFC 8018. Here the padding is
  #   implied by the OID.
  # OIDs for key sizes in bits
  block_cipher = aes.AES
  oids = {
      128: "2.16.840.1.101.3.4.1.1",
      192: "2.16.840.1.101.3.4.1.21",
      256: "2.16.840.1.101.3.4.1.41"
  }
  padding_scheme = None

class AesEcbNoPadding(AesEcb):
  padding_scheme = padding.NoPadding

class AesEcbPkcs5(AesEcb):
  padding_scheme = padding.Pkcs5Padding


class AesCbcNoPadding(encryption_mode.Cbc):
  block_cipher = aes.AES
  padding_scheme = padding.NoPadding


class AesCbcPkcs5(encryption_mode.Cbc):
  block_cipher = aes.AES
  padding_scheme = padding.Pkcs5Padding
  # OIDs for key sizes in bits
  # Defined in RFC 3565 and RFC 8018 Section B.2.5
  oids = {
      128: "2.16.840.1.101.3.4.1.2",
      192: "2.16.840.1.101.3.4.1.22",
      256: "2.16.840.1.101.3.4.1.42"
  }


class AesOfb(encryption_mode.Ofb):
  block_cipher = aes.AES
  # OIDs for key sizes in bits
  # TODO: references?
  oids = {
      128: "2.16.840.1.101.3.4.1.3",
      192: "2.16.840.1.101.3.4.1.23",
      256: "2.16.840.1.101.3.4.1.43"
  }


class AesCfb128(encryption_mode.Cfb):
  block_cipher = aes.AES
  feedback_size_in_bits = 128
  # OIDs for key sizes in bits
  # TODO: references?
  # TODO: Is the feedback size specified?
  oids = {
      128: "2.16.840.1.101.3.4.1.4",
      192: "2.16.840.1.101.3.4.1.24",
      256: "2.16.840.1.101.3.4.1.44"
  }


class AesCtr(encryption_mode.Ctr):
  block_cipher = aes.AES
  # TODO: Other ciphers (Camellia, Aria) have
  #   OIDs for CTR mode. Does AES have such OIDs? I can't find any.
  #   In particular, trying to encrypt a PEM with aes-128-ctr throws an
  #   error claiming that the cipher has no OID.
