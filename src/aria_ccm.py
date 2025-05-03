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
import aria

class AriaCcm(ccm.Ccm):
  name = "ARIA-CCM"
  block_cipher = aria.Aria

  # OIDs depending on key size in bits (RFC 5794)
  oids = {
    128: "1.2.410.200046.1.1.37",
    192: "1.2.410.200046.1.1.38",
    256: "1.2.410.200046.1.1.39"}
