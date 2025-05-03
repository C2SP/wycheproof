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

import hashlib
import hmac
import util
import os

# TODO: It is unclear if HKDF will be extended to SHA-3.
#   SHA-3 contains its own pseudorandom streams.
#   NIST assigns OIDs for HMAC with SHA-3 here:
#   https://csrc.nist.rip/groups/ST/crypto_apps_infra/csor/algorithms.html#Hash
#   Some OIDs are proposed here:
#   https://tools.ietf.org/html/draft-housley-hkdf-oids-01
#   This also lists "commonly" used hash functions as SHA-256, SHA-384 and
#   SHA-512.
SUPPORTED_HASHES = ["SHA-1", "SHA-256", "SHA-384", "SHA-512"]

@util.type_check
def hkdf(md, ikm: bytes, salt: bytes, info: bytes, size: int,
         check_size:bool = True) -> bytes:
  '''HKDF as defined in RFC 5869 and expanded in RFC 6234.

  Args:
     md: the hash function (e.g. hashlib.sha256)
     ikm: the input key material
     salt: the salt bytes
     info: additional info used to derive the bytes
     size: the size in bytes of the pseudorandom stream generated.
     check_size: if False the the size check for the output is
       skipped. This allows to generated outputs that are longer
       than allowed.
  '''
  if check_size and size > 255 * md().digest_size:
    raise ValueError("size too big")
  if len(salt) == 0:
    salt = bytes(md().digest_size)
  h = hmac.new(salt, digestmod=md)
  h.update(ikm)
  prk = h.digest()
  T = bytes()
  Tn = T
  ctr = 1
  while len(T) < size:
    h = hmac.new(prk, digestmod=md)
    h.update(Tn)
    h.update(info)
    h.update(bytes([ctr % 256]))
    Tn = h.digest()
    T += Tn
    ctr += 1
  return T[:size]

# Format: [hash, ikm_hex, salt_hex, info_hex, size, okm_hex, reference]
TEST_VECTORS = [
  [
    "SHA-1", "0b0b0b0b0b0b0b0b0b0b0b", "000102030405060708090a0b0c",
    "f0f1f2f3f4f5f6f7f8f9", 42,
    "085a01ea1b10f36933068b56efa5ad81a4f14b822f5b091568"
    "a9cdd4f155fda2c22e422478d305f3f896",
    ""
  ],
  [
    "SHA-256", "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
    "000102030405060708090a0b0c", "f0f1f2f3f4f5f6f7f8f9", 42,
    "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5d"
    "b02d56ecc4c5bf34007208d5b887185865",
    "RFC 5869, Test case 1"
  ],
  [
    "SHA-512", "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
    "000102030405060708090a0b0c", "f0f1f2f3f4f5f6f7f8f9", 42,
    "832390086cda71fb47625bb5ceb168e4c8e26a1a16ed34d9fc"
    "7fe92c1481579338da362cb8d9f925d7cb",
    ""
  ],
  [
    "SHA-512", "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
    "", "", 42,
    "f5fa02b18298a72a8c23898a8703472c6eb179dc204c03425c"
    "970e3b164bf90fff22d04836d0e2343bac",
    ""
  ],
  [ "SHA-256",
    bytes(range(0x50)).hex(),
    bytes(range(0x60, 0xb0)).hex(),
    bytes(range(0xb0, 256)).hex(),
    82,
    "b11e398dc80327a1c8e7f78c596a4934"
    "4f012eda2d4efad8a050cc4c19afa97c"
    "59045a99cac7827271cb41c65e590e09"
    "da3275600c2f09b8367793a9aca3db71"
    "cc30c58179ec3e87c14c01d5c1f3434f"
    "1d87",
    "RFC 5869, test case 2"
  ],
  ["SHA-256",
   bytes([0x0b]*22).hex(),
   "", "", 42,
   "8da4e775a563c18f715f802a063c5a31"
   "b8a11f5c5ee1879ec3454e5f3c738d2d"
   "9d201395faa4b61a96c8",
   "RFC 5869, test case 3"
  ],
  ["SHA-1",
   "0b0b0b0b0b0b0b0b0b0b0b",
   "000102030405060708090a0b0c",
   "f0f1f2f3f4f5f6f7f8f9",
   42,
   "085a01ea1b10f36933068b56efa5ad81"
   "a4f14b822f5b091568a9cdd4f155fda2"
   "c22e422478d305f3f896",
   "RFC 5869, test case 4"
  ],
  ["SHA-1",
    bytes(range(0x50)).hex(),
    bytes(range(0x60, 0xb0)).hex(),
    bytes(range(0xb0, 256)).hex(),
    82,
   "0bd770a74d1160f7c9f12cd5912a06eb"
   "ff6adcae899d92191fe4305673ba2ffe"
   "8fa3f1a4e5ad79f3f334b3b202b2173c"
   "486ea37ce3d397ed034c7f9dfeb15c5e"
   "927336d0441f4c4300e2cff0d0900b52"
   "d3b4",
   "RFC 5869, test case 5"
  ],
  ["SHA-1",
   bytes([0x0b] * 22).hex(),"", "", 42,
   "0ac1af7002b3d761d1e55298da9d0506"
   "b9ae52057220a306e07b6b87e8df21d0"
   "ea00033de03984d34918",
   "RFC 5869, test case 6",
  ],
  ["SHA-1",
   bytes([0x0b] * 22).hex(), bytes(20).hex(), "", 42,
   "0ac1af7002b3d761d1e55298da9d0506"
   "b9ae52057220a306e07b6b87e8df21d0"
   "ea00033de03984d34918",
   "RFC 5869, test case 6 but with HashLen zero octets",
  ],

  ["SHA-1",
   bytes([0x0c] * 22).hex(),
   "",
   "",
   42,
   "2c91117204d745f3500d636a62f64f0a"
   "b3bae548aa53d423b0d1f27ebba6f5e5"
   "673a081d70cce7acfc48",
   "RFC 5869, test case 7"
  ]
]


def hkdf_for_hash(md: str):

  def wrapper(ikm: bytes,
              salt: bytes,
              info: bytes,
              size: int,
              check_size: bool = True) -> bytes:
    return hkdf(hash_func, ikm, salt, info, size, check_size)

  if md == "SHA-1":
    hash_func = hashlib.sha1
  elif md == "SHA-256":
    hash_func = hashlib.sha256
  elif md == "SHA-384":
    hash_func = hashlib.sha384
  elif md == "SHA-512":
    hash_func = hashlib.sha512
  return wrapper


hkdf_sha1 = hkdf_for_hash("SHA-1")
hkdf_sha256 = hkdf_for_hash("SHA-256")
hkdf_sha512 = hkdf_for_hash("SHA-512")


def test():
  print([len(x) for x in TEST_VECTORS])
  for md, ikm, salt, info, size, okm, ref in TEST_VECTORS:
    h = hkdf_for_hash(md)
    okm2 = h(bytes.fromhex(ikm), bytes.fromhex(salt), bytes.fromhex(info), size)
    assert okm2.hex() == okm


def test_collision():
  '''HKDF has a maximal output size. Otherwise collisions are possible.'''
  ikm = os.urandom(16)
  salt = os.urandom(8)
  output1 = hkdf(hashlib.sha256, ikm, salt, info = bytes(), size = 257 * 32,
                 check_size=False)
  info2 = output1[255 * 32 : 256 * 32]
  output2 = hkdf(hashlib.sha256, ikm, salt, info = info2, size = 32)
  print(output2.hex())
  print(output1[256 * 32:].hex())
  assert output2 == output1[256 * 32:]

if __name__ == "__main__":
  test()
  test_collision()
