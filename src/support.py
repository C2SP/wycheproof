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
import hkdf
import hmac_algorithms
import json
import collections


class Library:

  def __init__(self, name: str, **args):
    self.name = name
    self.args = args

  def __call__(self, **moreargs):
    return Library(self.name, **self.args, **moreargs)

  def __repr__(self):
    args = [repr(self.name)]
    args += list(f"{k}={repr(v)}" for k, v in self.args.items())
    args = ", ".join(args)
    return f"Library({args})"


BC = Library("BouncyCastle")

# https://github.com/google/conscrypt/blob/master/CAPABILITIES.md
CC = Library("Conscrypt")

JDK = Library("Jdk")

BSSL = Library("BoringSSL")

JS = Library("JavaScript")

EC_CURVES = [group.name for group in ec_groups.all_curves]
JWK_CURVES = [group.name for group in ec_groups.jwk_curves]


def inverted(kvpairs):
  res = collections.defaultdict(list)
  if isinstance(kvpairs, dict):
    kvpairs = kvpairs.kvpairs()
  for lib, values in kvpairs:
    # Skip unrealeased entries.
    if not getattr(lib, "released", True):
      continue
    if isinstance(values, str):
      values = [values]
    assert isinstance(values, list)
    for val in values:
      res[val].append(lib)
  return res


CURVES = inverted([
    (BC, EC_CURVES),
    (CC, ["secp224r1", "secp256r1", "secp384r1", "secp521r1"]),
    (BSSL, ["secp224r1", "secp256r1", "secp384r1", "secp521r1"]),
    # TODO: remove duplicates.
    (JDK(
        since="8",
        before="16",
        ref="https://bugs.openjdk.org/browse/JDK-8252601"), [
            "secp256r1", "secp384r1", "secp521r1", "secp112r1", "secp112r2",
            "secp128r1", "secp128r2", "secp160k1", "secp160r1", "secp160r2",
            "secp192k1", "secp192r1", "secp224k1", "secp224r1", "secp256k1",
            "sect113r1", "sect113r2", "sect131r1", "sect131r2", "sect163k1",
            "sect163r1", "sect163r2", "sect193r1", "sect193r2", "sect233k1",
            "sect233r1", "sect239k1", "sect283k1", "sect283r1", "sect409k1",
            "sect409r1", "sect571k1", "sect571r1", "c2tnb191v1", "c2tnb191v2",
            "c2tnb191v3", "c2tnb239v1", "c2tnb239v2", "c2tnb239v3",
            "c2tnb359v1", "c2tnb431r1", "prime192v2", "prime192v3",
            "prime239v2", "prime239v3", "brainpoolP256r1", "brainpoolP320r1",
            "brainpoolP384r1", "brainpoolP512r1"
        ]),
    (JDK(since="16"), ["secp256r1", "secp384r1", "secp521r1"]),
    (JS, JWK_CURVES),
])

# No known implementation: MORUS, ASCON
CIPHER = inverted([
    (BC, [
        "AES", "ARC4", "BLOWFISH", "CAST5", "CAST6", "DES", "DESEDE",
        "GOST3412-2015", "Grain128", "Grainv1", "HC128", "HC256", "IDEA",
        "NOEKEON", "RC2", "RC5", "RC5-64", "RC6", "SALSA20", "SHACAL-2",
        "SKIPJACK", "SM2", "Serpent", "TEA", "Threefish", "Twofish", "XSALSA20",
        "XTEA", "ZUC-128", "ZUC-256"
    ]),
    (BC(since="1.30"), "CAMELLIA"),
    (BC(since="1.36"), "SEED"),
    (BC(since="1.55"), "SM4"),
    (BC(since="1.57"), "ARIA"),
    (BC(since="1.63"), "CHACHA20"),
    (CC, ["AES", "CHACHA20", "ARC4", "DESEDE"]),
    (JDK, ["AES"]),
    (JDK(since="11"), "CHACHA20"),
    (JDK(released=False, ref="JDK-8256529"), "XCHACHA20"),
    (JDK(released=False, ref="JDK-6537039"), "CAMELLIA"),
])

CIPHER_MODES = inverted([
    (BC(since="1.56"), ["CCM"]),
    (BC, ["ECB", "CTR", "CBC", "EAX", "GCM", "GCM-SIV"]),
    (JDK, ["ECB", "CTR", "CBC", "CCM", "GCM"]),
    (CC, ["ECB", "CTR", "CBC", "GCM", "GCM-SIV"]),
    (BSSL, ["ECB", "CTR", "CBC", "GCM", "GCM-SIV"]),
])

KEYWRAP = inverted([
    (BC, ["KW", "KWP"]),  # for Camellia and seed since 1.54
    (JDK, ["KW", "KWP"]),
    (BSSL, ["KW", "KWP"]),
    (CC, []),
])

SIGNATURE = {
    "DSA": [BC, JDK, JS],
    "ECDSA": [BC, CC, JDK, BSSL, JS],
    "RSA-PKCS1": [BC, JDK],
    "RSASSA-PSS": [BC, CC, JDK],
    "ED25519": [BC, JDK],
    "ED448": [JDK],
    "ECNR": [BC],
}

MESSAGE_DIGEST = inverted([
    (CC, ["MD5", "SHA-1", "SHA-256", "SHA-384", "SHA-512"]),
    (BSSL, ["SHA-1", "SHA-256", "SHA-384", "SHA-512"]),
    (JDK, [
        "MD2", "MD5", "SHA-1", "SHA-224", "SHA-256", "SHA-384", "SHA-512",
        "SHA-512/224", "SHA-512/256", "SHA3-224", "SHA3-256", "SHA3-384",
        "SHA3-512"
    ]),
    (BC, [
        "BLAKE2B-160", "BLAKE2B-256", "BLAKE2B-384", "BLAKE2B-512",
        "BLAKE2S-128", "BLAKE2S-160", "BLAKE2S-224", "BLAKE2S-256",
        "DSTU7564-256", "DSTU7564-384", "DSTU7564-512", "GOST3411",
        "GOST3411-2012-256", "GOST3411-2012-512", "HARAKA-256", "HARAKA-512",
        "KECCAK-224", "KECCAK-256", "KECCAK-288", "KECCAK-384", "KECCAK-512",
        "MD2", "MD4", "MD5", "RIPEMD128", "RIPEMD160", "RIPEMD256", "RIPEMD320",
        "SHA-1", "SHA-224", "SHA-256", "SHA-384", "SHA-512", "SHA-512/224",
        "SHA-512/256", "SHA3-224", "SHA3-256", "SHA3-384", "SHA3-512", "SM3",
        "Skein-1024-1024", "Skein-1024-384", "Skein-1024-512", "Skein-256-128",
        "Skein-256-160", "Skein-256-224", "Skein-256-256", "Skein-512-128",
        "Skein-512-160", "Skein-512-224", "Skein-512-256", "Skein-512-384",
        "Skein-512-512", "TIGER", "WHIRLPOOL"
    ]),
])

HMAC_MD = inverted([
    (CC, ["MD5", "SHA-1", "SHA-256", "SHA-384", "SHA-512"]),
    (BSSL, ["SHA-1", "SHA-256", "SHA-384", "SHA-512"]),
    (JDK, ["MD5", "SHA-1", "SHA-256", "SHA-384", "SHA-512"]),
    (BC, ["MD5", "SHA-1", "SHA-256", "SHA-384", "SHA-512"]),
])

SIGNATURE_MD = inverted([
    (CC, ["SHA-1", "SHA-256", "SHA-384", "SHA-512"]),  # Also MD5withRSA
    (BSSL, ["SHA-1", "SHA-256", "SHA-384", "SHA-512"]),
    (JDK, [
        "MD2", "MD5", "SHA-1", "SHA-256", "SHA-384", "SHA-512", "SHA-512/224",
        "SHA-512/256", "SHA3-224", "SHA3-256", "SHA3-384", "SHA3-512"
    ]),  # Also Md2 and Md5 and truncated SHA-512 only with RSA
    (BC, ["MD5", "SHA-1", "SHA-256", "SHA-384", "SHA-512"]),
    (BC(since="1.69"), ["SHAKE128", "SHAKE256"]),
    (BC(since="1.55"), [""SHA3-224", "SHA3-256", "SHA3-384", "SHA3-512""]),
    (BC(since="1.54"), ["Blake2b"]),
])

MAC = inverted([
    (BC, ["HMAC", "CMAC"]),
    (CC, ["HMAC"]),
    (JDK, ["HMAC"]),
    (BSSL, ["HMAC"]),
])

KEY_EXCHANGE = inverted([
    (BC, ["DH", "ECDH", "ECCDH", "ECDHC", "X25519", "X448"]),
    (JDK, ["DH", "ECDH", "X25519", "X448"]),
    (CC, ["ECDH", "X25519"]),
    (BSSL, ["ECDH", "X25519"]),
])

PK_ENCRYPT = inverted([
    (BSSL, ["RSA-PKCS1", "RSA-OAEP"]),
    (BC, ["RSA-PKCS1", "RSA-OAEP"]),
    (CC, ["RSA-PKCS1", "RSA-OAEP"]),
    (JDK, ["RSA-PKCS1", "RSA-OAEP"]),
])

if __name__ == "__main__":
  for cap in [CURVES, CIPHER, SIGNATURE]:
    for c, l in cap.items():
      print(c, [lib.name for lib in l])
