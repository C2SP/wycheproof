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

import ec_groups
import ec_key
import ecdsa
import hlib

def test():
  msg = "ce0677bb30baa8cf067c88db9811f4333d131bf8bcf12fe7065d211dce971008"
  sig = ("90f27b8b488db00b00606796d2987f6a5f59ae62ea05effe84fef5b8b0e54998"
          "4a691139ad57a3f0b906637673aa2f63d1f55cb1a69199d4009eea23ceaddc9301")
  pub = ("04e32df42865e97135acfb65f3bae71bdc86f4d49150ad6a440b6f15878109880a"
           "0a2b2667f7e725ceea70c673093bf67663e0312623c8e091b13cf2c0f11ef652")
  compressed = "0x02e32df42865e97135acfb65f3bae71bdc86f4d49150ad6a440b6f15878109880a"

  group = ec_groups.secp256k1
  m = bytes.fromhex(msg)
  rsv = bytes.fromhex(sig)
  pk = bytes.fromhex(pub)
  r = int.from_bytes(rsv[:32], "big")
  s = int.from_bytes(rsv[32:64], "big")
  v = rsv[64]
  px = int.from_bytes(pk[1:33], "big")
  py = int.from_bytes(pk[33:65], "big")
  pubkey = ec_key.EcPublicKey(group, (px, py))
  ver = ecdsa.EcdsaVerifier(pubkey)
  
  print(ver.verify_hash(r, s, m))
  print(ver.verify_hash(r, s, hlib.hash("KECCAK-256", m)))


if __name__ == "__main__":
  test()
