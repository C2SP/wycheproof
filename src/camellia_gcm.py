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

import gcm
import camellia

# Possibly added to some SSL implementations.
# TODO: Find a good reference.
class CamelliaGcm(gcm.Gcm):
  name = "CAMELLIA-GCM"
  block_cipher = camellia.Camellia
  # OIDs for key sizes in bits
  oids = {
    128: "0.3.4401.5.3.1.9.6",
    192: "0.3.4401.5.3.1.9.26",
    256: "0.3.4401.5.3.1.9.46"}
