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

import ccm
import camellia

# Defined in RFC 5528
# See also RFC 5529
class CamelliaCcm(ccm.Ccm):
  name = "CAMELLIA-CCM"
  block_cipher = camellia.Camellia
  # OIDs for key sizes in bits
  oids = {
    128: "0.3.4401.5.3.1.9.7",
    192: "0.3.4401.5.3.1.9.27",
    256: "0.3.4401.5.3.1.9.47"}
