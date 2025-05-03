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

from ec_groups import curveP256 as secp256r1
from ec_key import EcPrivateKey
import asn_parse

def reduce(java_bytes):
  assert all(-256 <= x < 256 for x in java_bytes)
  return [x % 256 for x in java_bytes]

def bytes2int(java_bytes):
  return int.from_bytes(reduce(java_bytes), "big", signed=True)

ELLIPTIC_CURVE_PUBLIC_KEY = [
            8, 1, 18, 69, 10, 33, 0, -95, 97, 40, -89, 50, 10, -123, 115, 48, -51, 42, -29, -43,
            -114, 110, 69, -35, -7, 74, 10, -128, -105, 114, 101, -26, 22, 26, 4, -28, 62, -105,
            -55, 18, 32, 122, -85, 18, -59, 10, 100, 30, 79, 87, 41, -104, -4, 37, -16, 16, -36,
            127, 120, -10, 50, -80, 80, 103, 24, -35, 64, 73, -125, 98, 56, -109, -51]
           
ELLIPTIC_CURVE_PRIVATE_KEY = [
            48, 65, 2, 1, 0, 48, 19, 6, 7, 42, -122, 72, -50, 61, 2, 1, 6, 8, 42, -122, 72, -50, 61,
            3, 1, 7, 4, 39, 48, 37, 2, 1, 1, 4, 32, 44, 0, 13, -6, -86, -99, -65, 107, 76, 120, -51,
            124, -44, -43, -48, -118, -100, 92, 89, 96, 62, 48, -86, 73, -75, -90, -23, 56, -34, -6,
            3, -36]
RAW_PRIVATE_KEY = [44, 0, 13, -6, -86, -99, -65, 107, 76, 120, -51,
            124, -44, -43, -48, -118, -100, 92, 89, 96, 62, 48, -86, 73, -75, -90, -23, 56, -34, -6,
            3, -36]
def convert():
  priv = bytes(reduce(ELLIPTIC_CURVE_PRIVATE_KEY))
  try:
    priv_asn = asn_parse.parse(priv)
    print(priv_asn)
  except Exception as ex:
    print(ex)
    return
  priv_os = priv_asn[-1]
  print(priv_os)
  print(len(priv_os.val))
  print(priv_os.val.hex())
  pp = asn_parse.parse(priv_os.val)
  print(pp)
  s2 = bytes2int(pp[1].val)
  print(s2.bit_length())
  print('correct private key:', s2)
  sbytes = s2.to_bytes(32,"big")
  jb = [x - 256 if x >= 128 else x for x in sbytes]
  print(jb)  
  priv = EcPrivateKey(secp256r1, s2)


  print(priv.public().encode_hex())
  print(bytes(reduce(ELLIPTIC_CURVE_PUBLIC_KEY)).hex()) 


if __name__ == "__main__":
  convert()
