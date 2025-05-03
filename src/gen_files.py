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
import gen_ccm
import gen_gcm
import gen_cmac
import gen_gmac
import gen_xts
import gen_kw
import gen_kwp
import gen_morus
import gen_ascon
import gen_sip_hash
import gen_cbc_pkcs5
import gen_eddsa
import hmac_algorithms
import json

EC_CURVES = [group.name for group in ec_groups.all_curves]
JWK_CURVES = [group.name for group in ec_groups.jwk_curves]

generators = []
def generator(func):
  generators.append(func)

TYPE = "test.json"
AMD_SEV_FILES = {
    f"ecdh_secp256r1_amd_sev_{TYPE}": {
        "status": "alpha",
        "generator": "gen_ecdh.py",
        "encoding": "amd_sev",
        "curve": "secp256r1",
    },
    f"ecdh_secp384r1_amd_sev_{TYPE}": {
        "status": "alpha",
        "generator": "gen_ecdh.py",
        "encoding": "amd_sev",
        "curve": "secp384r1",
    },
    f"ecdsa_secp256r1_sha256_amd_sev_{TYPE}": {
        "status": "internal",
        "generator": "gen_ecdsa.py",
        "curve": "secp256r1",
        "encoding": "amd_sev",
        "sha": "SHA-256",
    },
    f"ecdsa_secp256r1_sha384_amd_sev_{TYPE}": {
        "status": "internal",
        "generator": "gen_ecdsa.py",
        "curve": "secp256r1",
        "encoding": "amd_sev",
        "sha": "SHA-384",
    },
    f"ecdsa_secp384r1_sha384_amd_sev_{TYPE}": {
        "status": "internal",
        "generator": "gen_ecdsa.py",
        "curve": "secp384r1",
        "encoding": "amd_sev",
        "sha": "SHA-384",
    },
    f"ecdsa_secp256k1_sha256_amd_sev_{TYPE}": {
        "status": "alpha",
        "generator": "gen_ecdsa.py",
        "curve": "secp256k1",
        "encoding": "amd_sev",
        "sha": "SHA-256",
    },
}

MISC_FILES = {
    f"ecdsa_secp256k1_sha256_bitcoin_{TYPE}": {
        "status": "release",
        "generator": "gen_ecdsa.py",
        "curve": "secp256k1",
        "encoding": "bitcoin",
        "sha": "SHA-256",
    },
    f"ecdsa_secp256r1_webcrypto_{TYPE}": {
        "status": "release",
        "curve": "secp256r1",
        "generator": "gen_ecdsa.py",
        "encoding": "webcrypto",
        "sha": "SHA-256",
    },
    f"ecdsa_secp384r1_webcrypto_{TYPE}": {
        "status": "release",
        "curve": "secp384r1",
        "generator": "gen_ecdsa.py",
        "encoding": "webcrypto",
        "sha": "SHA-384",
    },
    f"ecdsa_secp521r1_webcrypto_{TYPE}": {
        "status": "release",
        "curve": "secp521r1",
        "generator": "gen_ecdsa.py",
        "encoding": "webcrypto",
        "sha": "SHA-512",
    },
    f"ecnr_{TYPE}": {
        "status": "alpha",
        "generator": "gen_ecnr.py",
    },
    f"primality_{TYPE}": {
        "status": "release",
        "generator": "gen_primetest.py",
    },
    f"rsa_oaep_misc_{TYPE}": {
        "status": "release",
        "generator": "gen_rsa_oaep.py",
        "mode": "misc",
    },
    f"rsa_pss_misc_{TYPE}": {
        "status": "release",
        "generator": "gen_rsa_pss_misc.py",
        "message": "123400",
    },
    f"rsa_sig_gen_misc_{TYPE}": {
        "status": "release",
        "generator": "gen_rsa_signature.py",
        "size": 0,
        "sha": "",
        "op": "sign",
    },
    f"rsa_sig_gen_misc_three_primes_{TYPE}": {
        "status": "release",
        "generator": "gen_rsa_signature.py",
        "size": 0,
        "sha": "",
        "op": "sign",
        "three_primes": True
    },
    f"rsa_pss_2048_sha256_mgf1_32_params_{TYPE}": {
        "status": "release",
        "generator": "gen_rsa_pss.py",
        "size": 2048,
        "sha": "SHA-256",
        "mgf": "MGF1",
        "mgf_sha": "SHA-256",
        "slen": 32,
        "specify_pkcs1algorithm": True
    },
    f"rsa_pss_misc_params_{TYPE}": {
        "status": "release",
        "generator": "gen_rsa_pss_misc.py",
        "message": "123400",
        "specify_pkcs1algorithm": True
    },
    f"rsa_three_prime_private_key_pem_2048_{TYPE}": {
        "status": "alpha",
        "generator": "gen_rsa_priv_key.py",
        "size": 2048,
        "encoding": "pem",
        "three_primes": True
    },
    f"rsa_three_prime_private_key_pem_3072_{TYPE}": {
        "status": "alpha",
        "generator": "gen_rsa_priv_key.py",
        "size": 3072,
        "encoding": "pem",
        "three_primes": True
    },
    f"rsa_three_prime_private_key_pkcs8_2048_{TYPE}": {
        "status": "alpha",
        "generator": "gen_rsa_priv_key.py",
        "size": 2048,
        "encoding": "asn",
        "three_primes": True
    },
    f"rsa_three_prime_private_key_pkcs8_3072_{TYPE}": {
        "status": "alpha",
        "generator": "gen_rsa_priv_key.py",
        "size": 3072,
        "encoding": "asn",
        "three_primes": True
    },
    f"vmac_128_{TYPE}": {
        "status": "release",
        "generator": "gen_vmac.py",
        "tag_sizes": [128]
    },
    f"vmac_64_{TYPE}": {
        "status": "release",
        "generator": "gen_vmac.py",
        "tag_sizes": [64]
    },
    f"xchacha20_poly1305_{TYPE}": {
        "status": "release",
        "generator": "gen_xchacha_poly1305.py"
    },
    f"ec_prime_order_curves_{TYPE}": {
        "status": "release",
        "generator": "gen_eccurves.py"
    }
}


DISABLED = {
    "rsa_{TYPE}": {
        "status": "disabled",
        "generator": "gen_rsa.py",
        "size": 0,
        "encoding": "asn",
    },
}
def hash_id(md: str):
  """Converts a hash name into an identifier that can be used in file names"""
  names = {
      "SHA-1": "sha1",
      "SHA-224": "sha224",
      "SHA-256": "sha256",
      "SHA-384": "sha384",
      "SHA-512": "sha512",
      "SHA-512/224": "sha512_224",
      "SHA-512/256": "sha512_256"
  }
  if md in names:
    return names[md]
  else:
    return md.lower().replace("-", "_")

@generator
def hmac_files():
  for sha in hmac_algorithms.HASHES:
    sha_id = hash_id(sha)
    filename = f"hmac_{sha_id}_{TYPE}"
    params = {"status": "release", "generator": "gen_hmac.py", "sha": sha}
    yield filename, params


@generator
def hkdf_files():
  for sha in hkdf.SUPPORTED_HASHES:
    sha_id = hash_id(sha)
    filename = f"hkdf_{sha_id}_{TYPE}"
    params = {"status": "release", "generator": "gen_hkdf.py", "sha": sha}
    yield filename, params

@generator
def misc_enc():
  # file_prefix, generator, status
  files = [
      ("aead_aes_siv_cmac", "gen_aes_siv_aead.py", "release"),
      ("aegis128L", "gen_aegis128L.py", "release"),
      ("aegis128", "gen_aegis128.py", "release"),
      ("aegis256", "gen_aegis256.py", "release"),
      ("aes_eax", "gen_aes_eax.py", "release"),
      ("aes_gcm_siv", "gen_aes_gcm_siv.py", "release"),
      ("aes_siv_cmac", "gen_aes_siv.py", "release"),
      ("chacha20_poly1305", "gen_chacha_poly1305.py", "release"),
  ]
  for prefix, generator, status in files:
    filename = f"{prefix}_{TYPE}"
    params = params = {"status": status, "generator" : generator}
    yield filename, params

@generator
def aead_files():
  files = [("gen_morus.py", gen_morus.ALGORITHMS, "internal"),
           ("gen_ascon.py", gen_ascon.ALGORITHMS, "internal"),
          ]
  for generator, algorithms, status in files:
    for alg in algorithms:
      filename = f"{alg.lower()}_{TYPE}"
      params = {"status": status, "generator" : generator, "algorithm": alg}
      yield filename, params

@generator
def alg_files():
  for package in [
      gen_ccm, gen_gcm, gen_xts, gen_cbc_pkcs5, gen_kw, gen_kwp, gen_cmac,
      gen_gmac, gen_sip_hash, gen_eddsa
  ]:
    algorithms = getattr(package, "ALGORITHMS")
    for alg in algorithms:
      name = alg.lower().replace("-", "_")
      filename = f"{name}_{TYPE}"
      status = "release"
      generator = f"{package.__name__}.py"
      params = {"status": status, "algorithm": alg, "generator": generator}
      yield filename, params


@generator
def ff1_files():
  algorithm = "AES-FF1"
  generator = "gen_fpe.py"
  status = "release"
  for radix in [10, 16, 26, 32, 36, 45, 62, 64, 85, 255, 256, 65535, 65536]:
    filename = f"aes_ff1_radix{radix}_{TYPE}"
    params = {"status": status,
            "generator" : generator,
            "algorithm" : algorithm,
            "radix": radix,
            "format" : "digits"}
    yield filename, params
  for alphabet in [
      "0123456789",
      "0123456789ABCDEF",
      "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
      "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567",
      "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ",
      "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:",
      "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
      "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-_",
  ]:
    filename = f"aes_ff1_base{len(alphabet)}_{TYPE}"
    params = {
        "status": status,
        "generator": generator,
        "algorithm" : algorithm,
        "radix": len(alphabet),
        "alphabet": alphabet,
        "format" : "str",
    }
    yield filename, params
  yield f"aes_ff1_base85_{TYPE}", {
    "status" : status,
    "generator" : generator,
    "algorithm" : algorithm,
    "radix" : 85,
    "format" : "str"
  }

@generator
def ec_priv_key_files():
  for curve_name in EC_CURVES:
    for encoding in ["pem", "asn"]:
      name = f"ec_priv_key_{curve_name}_{encoding}_{TYPE}"
      params = {
          "status": "internal",
          "generator": "gen_ec_priv_key.py",
          "curve": curve_name,
          "encoding": encoding
      }
      yield name, params

@generator
def xdh_priv_key_files():
  for curve in ["curve25519", "curve448"]:
    for encoding in ["asn", "pem"]:
      filename = f"ec_priv_key_{curve}_{encoding}_{TYPE}"
      params = {
          "status": "internal",
          "generator": "gen_xdh_priv_key.py",
          "curve": curve,
          "encoding": encoding
      }
      yield filename, params

@generator
def ec_key_files():
  curves = ["secp256r1", "secp256k1", "secp384r1", "secp521r1"]
  for curve in curves:
    for encoding in ["asn", "pem"]:
      if encoding == "asn":
        filename = f"eckey_{curve}_{TYPE}"
      else:
        filename = f"eckey_{curve}_{encoding}_{TYPE}"
      params = {
          "status": "internal",
          "generator": "gen_eckey.py",
          "curve": curve,
          "encoding": encoding
      }
      yield filename, params


@generator
def ecdsa_files():
  hashes_for_curve = {
      # secp160k1, sep160r1, secp160r2 have an order n with bitlength 161.
      "secp160k1": ("SHA-256",),
      "secp160r1": ("SHA-256",),
      "secp160r2": ("SHA-256",),
      "secp192k1": ("SHA-256",),
      "secp192r1": ("SHA-256",),
      "secp224k1":
          ("SHA-224", "SHA3-224", "SHA-256", "SHA3-256", "SHA-512", "SHA3-512"),
      "secp224r1":
          ("SHA-224", "SHA3-224", "SHA-256", "SHA3-256", "SHA-512", "SHA3-512"),
      "secp256r1": ("SHA-256", "SHA3-256", "SHA-512", "SHA3-512", "SHAKE128"),
      "secp256k1": ("SHA-256", "SHA3-256", "SHA-512", "SHA3-512", "SHAKE128"),
      "secp384r1": ("SHA-384", "SHA3-384", "SHA-512", "SHA3-512"),
      "secp521r1": ("SHA-512", "SHA3-512", "SHAKE256"),
      "brainpoolP224r1": ("SHA-224", "SHA3-224"),
      "brainpoolP256r1": ("SHA-256", "SHA3-256"),
      "brainpoolP320r1": ("SHA-384", "SHA3-384"),
      "brainpoolP384r1": ("SHA-384", "SHA3-384"),
      "brainpoolP512r1": ("SHA-512", "SHA3-512"),
      "sect163k1": ("SHA-256",),
      "sect163r1": ("SHA-256",),
      "sect163r2": ("SHA-256",),
      "sect233k1": ("SHA-224", "SHA-256"),
      "sect233r1": ("SHA-224", "SHA-256"),
      "sect283k1": ("SHA-256", "SHA-384"),
      "sect283r1": ("SHA-256", "SHA-384"),
      "sect409k1": ("SHA-384", "SHA-512"),
      "sect409r1": ("SHA-384", "SHA-512"),
      "sect571k1": ("SHA-512",),
      "sect571r1": ("SHA-512",),
      "c2tnb191v1": ("SHA-256",),
      "c2tnb191v2": ("SHA-256",),
      "c2tnb191v3": ("SHA-256",),
      "c2tnb239v1": ("SHA-256",),
      "c2tnb239v2": ("SHA-256",),
      "c2tnb239v3": ("SHA-256",),
      "c2tnb359v1": ("SHA-384",),
      "c2tnb431r1": ("SHA-512",),
  }
  for encoding in ["asn", "p1363"]:
    for curve, hashes in hashes_for_curve.items():
      for sha in hashes:
        sha_id = hash_id(sha)
        if encoding == "asn":
          filename = f"ecdsa_{curve}_{sha_id}_{TYPE}"
        else:
          filename = f"ecdsa_{curve}_{sha_id}_{encoding}_{TYPE}"
        status = "release"
        params = {
            "status": status,
            "generator": "gen_ecdsa.py",
            "curve": curve,
            "encoding": encoding,
            "sha": sha
        }
        if encoding == "asn":
          params["asnparsing"] = "der"
        yield filename, params


@generator
def ecdh_files():
  for encoding in ["asn", "pem", "ecpoint", "webcrypto"]:
    if encoding == "webcrypto":
      curves = JWK_CURVES
    else:
      curves = EC_CURVES
    for curve_name in curves:
      if encoding == "asn":
        name = f"ecdh_{curve_name}_{TYPE}"
      else:
        name = f"ecdh_{curve_name}_{encoding}_{TYPE}"
      params = {
          "status": "release",
          "generator": "gen_ecdh.py",
          "curve": curve_name,
          "encoding": encoding
      }
      yield name, params

@generator
def dsa_files():
  for sizep, sizeq, sha in [
      (2048, 224, "SHA-224"),
      (2048, 224, "SHA-256"),
      (2048, 256, "SHA-256"),
      (3072, 256, "SHA-256"),
  ]:
    sha_id = hash_id(sha)
    for encoding in ["asn", "p1363"]:
      if encoding == "asn":
        filename = f"dsa_{sizep}_{sizeq}_{sha_id}_{TYPE}"
      else:
        filename = f"dsa_{sizep}_{sizeq}_{sha_id}_{encoding}_{TYPE}"
      params = {
          "status": "release",
          "generator": "gen_dsa.py",
          "asnparsing": "der",
          "sizep": sizep,
          "sizeq": sizeq,
          "sha": sha,
          "encoding": encoding
      }
      yield filename, params


@generator
def rsa_pkcs1_files():
  for keysize in [2048, 3072, 4096]:
    filename = f"rsa_pkcs1_{keysize}_{TYPE}"
    params = {
        "status": "release",
        "generator": "gen_rsaes_pkcs1.py",
        "size": keysize
    }
    yield filename, params

@generator
def rsa_pub_key_files():
  for keysize in [2048, 3072, 4096]:
    for encoding in ["pem", "asn"]:
      filename = f"rsa_pub_key_{keysize}_{encoding}_{TYPE}"
      params = {
          "status": "alpha",
          "generator": "gen_rsa_pub_key.py",
          "size": keysize,
          "encoding": encoding
      }
      yield filename, params


@generator
def rsa_signature_files():
  for keysize, sha in [(2048, "SHA-224"), (2048, "SHA-256"), (2048, "SHA-384"),
                       (2048, "SHA3-224"), (2048, "SHA3-256"),
                       (2048, "SHA3-384"), (2048, "SHA3-512"),
                       (2048, "SHA-512/224"), (2048, "SHA-512/256"),
                       (2048, "SHA-512"), (3072, "SHA-256"), (3072, "SHA-384"),
                       (3072, "SHA3-256"), (3072, "SHA3-384"),
                       (3072, "SHA3-512"), (3072, "SHA-512/256"),
                       (3072, "SHA-512"), (4096, "SHA-256"), (4096, "SHA-384"),
                       (4096, "SHA-512/256"), (4096, "SHA-512"),
                       (8192, "SHA-256"), (8192, "SHA-384"), (8192, "SHA-512")]:
    sha_id = hash_id(sha)
    filename = f"rsa_signature_{keysize}_{sha_id}_{TYPE}"
    params = {
        "status": "release",
        "generator": "gen_rsa_signature.py",
        "op": "verify",
        "size": keysize,
        "sha": sha
    }
    yield filename, params


@generator
def rsa_oaep_files():
  combinations = [(2048, "SHA-1", "MGF1", "SHA-1"),
                  (2048, "SHA-224", "MGF1", "SHA-1"),
                  (2048, "SHA-224", "MGF1", "SHA-224"),
                  (2048, "SHA-256", "MGF1", "SHA-1"),
                  (2048, "SHA-256", "MGF1", "SHA-256"),
                  (2048, "SHA-384", "MGF1", "SHA-1"),
                  (2048, "SHA-384", "MGF1", "SHA-384"),
                  (2048, "SHA-512", "MGF1", "SHA-1"),
                  (2048, "SHA-512", "MGF1", "SHA-512"),
                  (3072, "SHA-256", "MGF1", "SHA-1"),
                  (3072, "SHA-256", "MGF1", "SHA-256"),
                  (3072, "SHA-512", "MGF1", "SHA-1"),
                  (3072, "SHA-512", "MGF1", "SHA-512"),
                  (4096, "SHA-256", "MGF1", "SHA-1"),
                  (4096, "SHA-256", "MGF1", "SHA-256"),
                  (4096, "SHA-512", "MGF1", "SHA-1"),
                  (4096, "SHA-512", "MGF1", "SHA-512")]
  for keysize, sha, mgf, mgf_sha in combinations:
    sha_id = hash_id(sha)
    mgf_id = mgf.lower() + hash_id(mgf_sha)
    filename = f"rsa_oaep_{keysize}_{sha_id}_{mgf_id}_{TYPE}"
    params = {
        "status": "release",
        "generator": "gen_rsa_oaep.py",
        "size": keysize,
        "sha": sha,
        "mgf": mgf,
        "mgf_sha": mgf_sha
    }
    yield filename, params
  for keysize, sha, mgf, mgf_sha in [
      (2048, "SHA-1", "MGF1", "SHA-1"),
      (3072, "SHA-224", "MGF1", "SHA-224"),
      (4096, "SHA-256", "MGF1", "SHA-256"),
  ]:
    sha_id = hash_id(sha)
    mgf_id = mgf.lower() + hash_id(mgf_sha)
    filename = f"rsa_three_primes_oaep_{keysize}_{sha_id}_{mgf_id}_{TYPE}"
    params = {
        "status": "internal",
        "generator": "gen_rsa_oaep.py",
        "size": keysize,
        "sha": sha,
        "mgf": mgf,
        "mgf_sha": mgf_sha,
        "three_primes": True
    }
    yield filename, params


@generator
def rsa_pss_files():
  for size, sha, mgf, mgf_sha, slen in [
      (2048, "SHA-1", "MGF1", "SHA-1", 20),
      (2048, "SHA-256", "MGF1", "SHA-256", 0),
      (2048, "SHA-256", "MGF1", "SHA-256", 32),
      (2048, "SHA-256", "MGF1", "SHA-1", 20),
      (2048, "SHA-512/224", "MGF1", "SHA-512/224", 28),
      (2048, "SHA-512/256", "MGF1", "SHA-512/256", 32),
      (3072, "SHA-256", "MGF1", "SHA-256", 32),
      (4096, "SHA-256", "MGF1", "SHA-256", 32),
      (4096, "SHA-512", "MGF1", "SHA-512", 32),
      (4096, "SHA-512", "MGF1", "SHA-512", 64),
  ]:
    sha_id = hash_id(sha)
    if sha == mgf_sha:
      mgf_id = mgf.lower()
    else:
      mgf_id = mgf.lower() + hash_id(mgf_sha)
    filename = f"rsa_pss_{size}_{sha_id}_{mgf_id}_{slen}_{TYPE}"
    params = {
        "status": "release",
        "generator": "gen_rsa_pss.py",
        "size": size,
        "sha": sha,
        "mgf": mgf,
        "mgf_sha": mgf_sha,
        "slen": slen
    }
    yield filename, params
  for size, shake in [(2048, "SHAKE128"), (2048, "SHAKE256"),
                      (3072, "SHAKE128"), (3072, "SHAKE256"),
                      (4096, "SHAKE256")]:
    shake_id = hash_id(shake)
    filename = f"rsa_pss_{size}_{shake_id}_{TYPE}"
    params = {
        "status": "alpha",
        "generator": "gen_rsa_pss.py",
        "size": size,
        "mgf": shake
    }
    yield filename, params


@generator
def rsa_private_key_files():
  for keysize in [2048, 3072, 4096]:
    for encoding, name in [("pem", "pem"), ("asn", "pkcs8")]:
      filename = f"rsa_private_key_{name}_{keysize}_{TYPE}"
      params = {
          "status": "alpha",
          "generator": "gen_rsa_priv_key.py",
          "size": keysize,
          "encoding": encoding
      }
      yield filename, params


@generator
def xdh_files():
  for alg in ["x25519", "x448"]:
    for encoding in ["raw", "asn", "pem", "jwk"]:
      if encoding == "raw":
        filename = f"{alg}_{TYPE}"
      else:
        filename = f"{alg}_{encoding}_{TYPE}"
      params = {
          "status": "release",
          "generator": "gen_xdh.py",
          "encoding": encoding,
          "algorithm": alg
      }
      yield filename, params


@generator
def ckm_rsa_aes_files():
  for size, sha, mgf in [
      (2048, "SHA-1", "MGF1"),
      (2048, "SHA-256", "MGF1"),
      (2048, "SHA-512", "MGF1"),
      (3072, "SHA-1", "MGF1"),
      (3072, "SHA-256", "MGF1"),
      (3072, "SHA-512", "MGF1"),
      (4096, "SHA-1", "MGF1"),
      (4096, "SHA-256", "MGF1"),
      (4096, "SHA-512", "MGF1"),
  ]:
    sha_id = hash_id(sha)
    mgf_id = mgf.lower()
    filename = f"ckm_rsa_aes_key_wrap_{size}_{mgf_id}_{sha_id}_{TYPE}"
    params = {
        "status": "alpha",
        "generator": "gen_ckm_rsa_aes_key_wrap.py",
        "size": size,
        "sha": sha,
        "mgf": mgf,
        "mgf_sha": sha
    }
    yield filename, params


def get_all_files():
  files = {}
  default = {
  }
  for g in generators:
    for name, params in g():
      for k, v in default.items():
        if k not in params:
          params[k] = v
      files[name] = params
  for d in [AMD_SEV_FILES, MISC_FILES]:
    for name, params in d.items():
      files[name] = params
  return files

def new_files():
  f = open("gen_files.json")
  files1 = json.load(f)
  files2 = get_all_files()
  new_files = {}
  for x in sorted(files2):
    if x not in files1:
      new_files[x] = files2[x]
  return new_files

def compare():
  def dict_str(d):
    return str({x: d[x] for x in sorted(d)})

  f = open("gen_files.json")
  files1 = json.load(f)
  files2 = get_all_files()
  for x in files2:
    if x not in files1:
      print("new file", x)
  for x in files1:
    if x not in files2:
      print("missing file", x)
  for x in files1:
    if x in files2:
      a = dict_str(files1[x])
      b = dict_str(files2[x])
      if a != b:
        print(x)
        print(a)
        print(b)
  print("number of test vector files:", len(files2))


if __name__ == "__main__":
  compare()
  print("----- new files ------")
  print(json.dumps(new_files(), indent=2))
