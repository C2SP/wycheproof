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
import cbc_pkcs5

class CamelliaCbcPkcs5(cbc_pkcs5.CbcPkcs5):
  name = "CAMELLIA-CBC-PKCS5"
  block_cipher = camellia.Camellia
  # OIDs for key sizes in bits.
  # Defined in RFC 3657 and RFC 3713.
  # RFC 3657 refers to RFC 3370, which does not specify the padding.
  # RFC 3713 specifies in Section 3 that the cbc algorithm include PKCS #7 padding
  # and refers to RFC 2315.
  oids = {
    128: "1.2.392.200011.61.1.1.1.2",
    192: "1.2.392.200011.61.1.1.1.3",
    256: "1.2.392.200011.61.1.1.1.4"}
