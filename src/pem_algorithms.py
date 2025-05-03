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

import aes_modes
import aes_ccm
import aes_gcm
import aria_modes
import aria_ccm
import aria_gcm
import camellia_modes
import camellia_ccm
import camellia_gcm
import seed_modes
import sm4_modes
import oid
import ccm
import gcm
from typing import Optional

# TODO: Rename and extend the use of algorithms to more cases.
#   The algorithms below are used for PBES in the PEM encoding; the general
#   structure is defined in RFC 8018 (i.e. password based encryption).
#   Hence not necessarily limited to PEM encryption.
#
#   Another issue here is that the term algorithm is overused:
#   test_vector uses a class algorithm for algorithms without parameters
#   This class here uses the term algorithm for algorithms with parameters.
#   E.g. to avoid confusion the base classes could be named
#   AlgorithmWithoutParameter, AlgorithmWithParameter or ParameterizedAlgorithm
class PemAlgorithm:
  def __init__(self,
               name: str,
               cipher,
               key_size_in_bits: Optional[int],
               iv_size_in_bytes: Optional[int],
               oid: Optional[str]):
    self.name = name
    self.cipher = cipher
    self._key_size_in_bits = key_size_in_bits
    self._oid = oid
    self._iv_size_in_bytes = iv_size_in_bytes

  def oid(self) -> Optional[str]:
    return self._oid

  def key_size(self) -> int:
    return self._key_size_in_bits

  def iv_size(self) -> int:
    return self._iv_size_in_bytes


# Encryption modes are tuples (format, class), where the (name%key_size_in_bits)
# is the name of the encryption mode
# TODO: This table is not complete.
# TODO: Which encryption modes use no padding, which ones use
#    pkcs5 padding?
# TODO: Does the old PKC5 format indeed use ECB with no padding
#    while the PKCS8 format uses ECB with PKCS5 padding.
# TODO: PKCS5 does not allow ECB, but PKCS8 does. Is this correct?
# TODO: Is SEED supported?
# TODO: Does PKCS8 support CTR modes? openssl throws an error because
#   the ciphers do not have OIDs. Not sure if this is an openssl bug.
# TODO: PKCS 5 with openssl allows GCM and CCM.
#   Is this documented somewhere? What are the parameters?
#   PKCS 8 does not support these encryption modes.
ENCRYPTION_MODES_PKCS5 = [
  ("AES-{key_size}-CBC", aes_modes.AesCbcNoPadding),
  ("AES-{key_size}-OFB", aes_modes.AesOfb),
  ("AES-{key_size}-CFB", aes_modes.AesCfb128),
  ("AES-{key_size}-CTR", aes_modes.AesCtr),
  ("id-aes{key_size}-CCM", aes_ccm.AesCcm),
  ("id-aes{key_size}-GCM", aes_gcm.AesGcm),
  ("CAMELLIA-{key_size}-CBC", camellia_modes.CamelliaCbcNoPadding),
  ("CAMELLIA-{key_size}-CFB", camellia_modes.CamelliaCfb128),
  ("CAMELLIA-{key_size}-CTR", camellia_modes.CamelliaCtr),
  ("CAMELLIA-{key_size}-OFB", camellia_modes.CamelliaOfb),
  ("CAMELLIA-{key_size}-CCM", camellia_ccm.CamelliaCcm),
  ("CAMELLIA-{key_size}-GCM", camellia_gcm.CamelliaGcm),
  ("ARIA-{key_size}-CBC", aria_modes.AriaCbcNoPadding),
  ("ARIA-{key_size}-CFB", aria_modes.AriaCfb128),
  ("ARIA-{key_size}-CTR", aria_modes.AriaCtr),
  ("ARIA-{key_size}-OFB", aria_modes.AriaOfb),
  ("ARIA-{key_size}-CCM", aria_ccm.AriaCcm),
  ("ARIA-{key_size}-GCM", aria_gcm.AriaGcm),  
  ("SEED-{key_size}-CBC", seed_modes.SeedCbcNoPadding),
  ("SEED-{key_size}-CFB", seed_modes.SeedCfb128),
  ("SEED-{key_size}-CTR", seed_modes.SeedCtr),
  ("SEED-{key_size}-OFB", seed_modes.SeedOfb),
  ("SM4-CBC", sm4_modes.Sm4CbcNoPadding),
  ("SM4-CFB", sm4_modes.Sm4Cfb128),
  ("SM4-CTR", sm4_modes.Sm4Ctr),
  ("SM4-OFB", sm4_modes.Sm4Ofb),
]

ENCRYPTION_MODES_PKCS8 = [
    ("AES-{key_size}-ECB", aes_modes.AesEcbPkcs5),
    ("AES-{key_size}-CBC", aes_modes.AesCbcPkcs5),
    ("AES-{key_size}-CFB", aes_modes.AesCfb128),
    ("AES-{key_size}-OFB", aes_modes.AesOfb),
    ("CAMELLIA-{key_size}-ECB", camellia_modes.CamelliaEcbPkcs5),
    ("CAMELLIA-{key_size}-CBC", camellia_modes.CamelliaCbcPkcs5),
    ("CAMELLIA-{key_size}-CFB", camellia_modes.CamelliaCfb128),
    ("CAMELLIA-{key_size}-OFB", camellia_modes.CamelliaOfb),
    ("ARIA-{key_size}-ECB", aria_modes.AriaEcbPkcs5),
    ("ARIA-{key_size}-CBC", aria_modes.AriaCbcPkcs5),
    ("ARIA-{key_size}-CFB", aria_modes.AriaCfb128),
    ("ARIA-{key_size}-OFB", aria_modes.AriaOfb),
    ("SEED-{key_size}-CBC", seed_modes.SeedCbcPkcs5),
    # TODO: I don't have any reliable ref for OIDs for the following
    #   modes yet.
    ("SEED-{key_size}-ECB", seed_modes.SeedEcbPkcs5),
    ("SEED-{key_size}-CFB", seed_modes.SeedCfb128),
    ("SEED-{key_size}-OFB", seed_modes.SeedOfb),
    ("SM4-ECB", sm4_modes.Sm4EcbPkcs5),
    ("SM4-CBC", sm4_modes.Sm4CbcPkcs5),
    ("SM4-CFB", sm4_modes.Sm4Cfb128),
    ("SM$-OFB", sm4_modes.Sm4Ofb),
]

def iv_size(cipher, key_size_in_bits):
  if issubclass(cipher, ccm.Ccm):
    return 12
  elif issubclass(cipher, gcm.Gcm):
    return 12
  else:
    return cipher(bytes(key_size_in_bits // 8)).iv_size
  
def get_algorithms(encryption_modes):
  """Returns a list of algorithms"""
  algorithms = []
  for template, cipher in encryption_modes:
    if hasattr(cipher, "oids"):
      for key_size, oid_str in cipher.oids.items():
        assert key_size >= 64  # Tries to ensure that key sizes are in bits.
        name = template.format(key_size = key_size)
        # TODO: This should be static
        iv_size_in_bytes = iv_size(cipher, key_size)
        alg = PemAlgorithm(name, cipher, key_size, iv_size_in_bytes, oid_str)
        algorithms.append(alg)
    else:
      # If there are no OIDs defined, then generate a list of algorithms
      # from the key sizes
      for key_size_in_bytes in cipher.block_cipher.key_sizes_in_bytes:
        key_size = 8 * key_size_in_bytes
        iv_size_in_bytes = iv_size(cipher, key_size)
        name = template.format(key_size = key_size)
        alg = PemAlgorithm(name, cipher, key_size, iv_size_in_bytes, None)
        algorithms.append(alg)
  return algorithms

# PEMs using PKCS 5 encoding define algorithms by name.
PEM_ALGORITHMS_PKCS5 = get_algorithms(ENCRYPTION_MODES_PKCS5)
ALGORITHM_TABLE_PKCS5 = {alg.name : alg for alg in PEM_ALGORITHMS_PKCS5}

# PEMs using PKCS 8 encoding identify algorithms by OID.
PEM_ALGORITHMS_PKCS8 = get_algorithms(ENCRYPTION_MODES_PKCS8)
OID_TABLE_PKCS8 = {alg.oid() : alg for alg in PEM_ALGORITHMS_PKCS8 if alg.oid()}


def get_algorithm(alg_oid: oid.Oid):
  alg = str(alg_oid)
  if alg in OID_TABLE_PKCS8:
    return OID_TABLE_PKCS8[alg]
  else:
    return None
