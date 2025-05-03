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
import cmac
import util


class SeedCmac(cmac.Cmac):
  """Probably defined in RFC 4269.
  
  The may appears to call it SeedMac
     id-seedMAC OBJECT IDENTIFIER ::= { algorithm seedMAC(7) }
  """
  name = "SEED-CMAC"
  block_cipher = seed.Seed

  def __init__(self, key: bytes, macsize: int = 16):
    super().__init__(seed.Seed(key), macsize)
