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

# Format of the test vectors:
# (private key A hex,
#  public key A hex,
#  private key B hex,
#  public key B, hex,
#  shared secret hex)
TESTVECTORS_X25519 = [
    ("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
     "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
     "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
     "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
     "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")
]

TESTVECTORS_X448 = [("9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28d"
                     "d9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b",
                     "9b08f7cc31b7e3e67d22d5aea121074a273bd2b83de09c63faa73d2c"
                     "22c5d9bbc836647241d953d40c5b12da88120d53177f80e532c41fa0",
                     "1c306a7ac2a0e2e0990b294470cba339e6453772b075811d8fad0d1d"
                     "6927c120bb5ee8972b0d3e21374c9c921b09d1b0366f10b65173992d",
                     "3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b430"
                     "27d8b972fc3e34fb4232a13ca706dcb57aec3dae07bdc1c67bf33609",
                     "07fff4181ac6cc95ec1c16a94a0f74d12da232ce40a77552281d282b"
                     "b60c0b56fd2464c335543936521c24403085d59a449a5037514a879d")
                   ]
