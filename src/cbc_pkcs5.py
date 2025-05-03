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

import encryption_mode
import padding

# TODO: There may be some incentive to implement other variants:
#   The following OIDs describe some CBC variants. I still need to check that
#   they refer to CBC with PKCS5 padding.
#
#  "1.2.156.10197.1.104.2" :    sm4-cbc
#
#  "1.2.392.200011.61.1.1.1.2": id-camellia128-cbc  RFC 3657, RFC 3713
#  "1.2.392.200011.61.1.1.1.3": id-camellia192-cbc
#  "1.2.392.200011.61.1.1.1.4": id-camellia256-cbc
#  RFC 3657 refers to RFC 3370, which does not specify the padding.
#  RFC 3713 specifies in Section 3 that the cbc algorithm include PKCS #7 padding
#  and refers to RFC 2315.
#
#  "1.2.410.200004.1.4":        id-seedCBC          RFC 4009, RFC 4269
#  RFC 4009 gives no details on the padding used for CBC. Neither does RFC 4269
#
#  "1.2.410.200046.1.1.2":      id-aria128-cbc OID
#  "1.2.410.200046.1.1.7":      id-aria192-cbc OID
#  "1.2.410.200046.1.1.12":     id-aria256-cbc OID  RFC 5794
#  RFC 5794 does not define the encryption modes and does not give any references.
#
#  "1.2.840.113533.7.66.10":    cast5-cbc
#  "1.2.840.113549.3.2":        rc2-cbc             RFC 2630, RFC 2633, RFC 3370, RFC 5911
#  "1.2.840.113549.3.7":        des-ede3-cbc        RFC 2630, RFC 2633, RFC 3370, RFC 5911, RFC8018
#  "1.2.840.113549.3.8":        rc5-cbc
#  "1.3.14.3.2.7":              desCBC              RFC 2898, RFC 8018"
#  "1.3.6.1.4.1.188.7.1.1.2":   idea-cbc
#  RFC 8018 defines the padding. It also extends PKCS #5 padding to 128-bit block ciphers
#  (i.e. tha padding is bytes([t])* t for t = 16 - len(m)%16.)


class CbcPkcs5(encryption_mode.Cbc):
  padding_scheme = padding.Pkcs5Padding
