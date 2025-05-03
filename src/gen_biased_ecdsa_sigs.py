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

import argparse
import biased_ecdsa
import ec_groups
import ec_key
import ecdsa
import util
import json
import os
import lcg
from typing import Optional, Union


def randomint(a, b):
  bits = (b - a).bit_length() + 64
  t = os.urandom((bits + 7) // 8)
  return int.from_bytes(t, 'little') % (b - a) + a

def dump(name, samples):
  f = open(name, "w")
  f.write(json.dumps(samples, indent=2))
  f.close()
  print("Generated", name)

def gen_signatures(signer, md, cnt):
  signatures = []
  for i in range(cnt):
    msg = i.to_bytes(4, "big")
    digest = util.hash(md, msg)

    r,s = signer.sign(md, msg)
    sig = {
      "r": r,
      "s": s,
      "digest": digest.hex(),
    }
    signatures.append(sig)
  return signatures

def gen_biased_signatures(
    curve: str = "secp256r1",
    md: str = "SHA-256",
    *,
    bias: int = 0,
    mul_k_upper: int = None,
    mul_k_lower: int = None,
    allow_offset: bool = False,
    sample_name: str = None,
    mask: int = None,
    cnt: int = 50):
  if sample_name is None:
    sample_name = "SAMPLE_" + curve.upper() + "_" + str(bias)
  group = ec_groups.named_curve(curve)
  s = randomint(1, group.n)
  msb = bias
  if mul_k_lower is None:
    mul_k_lower = 1
  if mul_k_upper is None:
    mul_k = mul_k_lower
  else:
    mul_k = randomint(mul_k_lower, mul_k_upper)
  if allow_offset:
    offset = randomint(1, group.n - 2**msb)
  else:
    offset = 0
  sample = {
     "name": sample_name,
     "curve": curve,
     "n": group.n,
     "priv": s,
     "msb": msb,
     "offset": offset,
     "mul_k": mul_k,
  }
  if mask is not None:
    sample["mask"] = mask
  priv = ec_key.EcPrivateKey(group, s)
  min_k = offset
  max_k = group.n // 2**msb + offset
  biased_signer = biased_ecdsa.BiasedEcdsaSigner(priv, min_k=min_k,
      max_k = max_k, mul_k = mul_k, mask=mask)
  sigs = gen_signatures(biased_signer, md, cnt)
  sample["signatures"] = sigs
  return sample


def gen_biased_u2f_signatures(
    curve_name: str = "secp256r1",
    md: str = "SHA-256",
    sample_name: str = None,
    cnt: int = 50,
    mode = biased_ecdsa.U2fMode.ALL_BYTES):
  if sample_name is None:
    sample_name = "SAMPLE_U2F_" + curve_name.upper()
  repeated_bytes = 4
  group = ec_groups.named_curve(curve_name)
  s = randomint(1, group.n)
  sample = {
     "name": sample_name,
     "curve": curve_name,
     "n": group.n,
     "priv": s,
     "repeated_bytes": repeated_bytes,
  }
  priv = ec_key.EcPrivateKey(group, s)
  biased_signer = biased_ecdsa.U2fEcdsaSigner(priv,
      repeated_bytes=repeated_bytes,
      mode = mode)
  sigs = gen_signatures(biased_signer, md, cnt)
  sample["signatures"] = sigs
  return sample

def gen_biased_java_util_random_signatures(
    curve_name: str = "secp256r1",
    md: str = "SHA-256",
    sample_name: str = None,
    cnt: int = 50,
    normalize: bool = False):
  if sample_name is None:
    sample_name = "SAMPLE_JAVA_UTIL_RANDOM_" + curve_name.upper()
  group = ec_groups.named_curve(curve_name)
  s = randomint(1, group.n)
  sample = {
     "name": sample_name,
     "lcg_name" : "java",
     "curve": curve_name,
     "n": group.n,
     "priv": s,
     "normalized": normalize
  }
  priv = ec_key.EcPrivateKey(group, s)
  biased_signer = biased_ecdsa.JavaUtilRandomEcdsaSigner(priv, normalize=normalize)
  sigs = gen_signatures(biased_signer, md, cnt)
  sample["signatures"] = sigs
  return sample


def gen_biased_lcg_signatures(
    curve_name: str = "secp256r1",
    md: str = "SHA-256",
    sample_name: str = None,
    cnt: Optional[int] = None,
    lcg_name: str = None,
    normalize: bool = False):
  rng = lcg.named_lcg(lcg_name)
  if cnt is None:
    cnt = 50
  if sample_name is None:
    sample_name = f"SAMPLE_{lcg_name}_{curve_name}".upper()
  group = ec_groups.named_curve(curve_name)
  s = randomint(1, group.n)
  sample = {
     "name": sample_name,
     "lcg_name": lcg_name,
     "curve": curve_name,
     "n": group.n,
     "priv": s,
     "a": rng.a,
     "b": rng.b,
     "mod": rng.mod,
     "truncate": rng.shift,
     "normalize": normalize,
  }
  priv = ec_key.EcPrivateKey(group, s)
  biased_signer = biased_ecdsa.LcgEcdsaSigner(priv, rng, normalize=normalize)
  sigs = gen_signatures(biased_signer, md, cnt)
  sample["signatures"] = sigs
  return sample

def gen_biased_mwc_signatures(
    curve_name: str = "secp256r1",
    md: str = "SHA-256",
    sample_name: str = None,
    cnt: int = 50,
    *,
    a: int,
    b: int):
  if sample_name is None:
    sample_name = "SAMPLE_MWC_" + curve_name.upper()
  group = ec_groups.named_curve(curve_name)
  s = randomint(1, group.n)
  sample = {
     "name": sample_name,
     "curve": curve_name,
     "n": group.n,
     "priv": s,
     "a": a,
     "b": b,
  }
  priv = ec_key.EcPrivateKey(group, s)
  biased_signer = biased_ecdsa.MwcEcdsaSigner(priv,a=a,b=b)
  sigs = gen_signatures(biased_signer, md, cnt)
  sample["signatures"] = sigs
  return sample

def gen_biased_hidden_subset_sum_signatures(
    curve_name: str = "secp256r1",
    md: str = "SHA-256",
    sample_name: str = None,
    cnt: int = 50,
    set_size: int = 40,
    normalize: bool = False):
  if sample_name is None:
    sample_name = f"SAMPLE_SUBSETSUM_{set_size}_{curve_name}".upper()
  group = ec_groups.named_curve(curve_name)
  s = randomint(1, group.n)
  sample = {
     "name": sample_name,
     "curve": curve_name,
     "n": group.n,
     "priv": s,
     "set_size": set_size,
     "normalize": normalize,
  }
  priv = ec_key.EcPrivateKey(group, s)
  biased_signer = biased_ecdsa.HiddenSubsetSumSigner(priv, set_size=set_size, normalize=normalize)
  sigs = gen_signatures(biased_signer, md, cnt)
  sample["signatures"] = sigs
  return sample


def gen_biased():
  samples = []
  for curve, bits in [("secp256r1", 256)]:
    curve_name = curve.upper()
    for bias in [8, 16, 24, 32, 40, 48, 64, 96, 128]:
      samples.append(gen_biased_signatures(curve=curve, bias=bias))
      samples.append(gen_biased_signatures(
          sample_name = f"SAMPLE_{curve_name}_WITH_OFFSET_{bias}",
          curve=curve,
          bias=bias,
          allow_offset=True))
      samples.append(gen_biased_signatures(
          sample_name = f"SAMPLE_{curve_name}_LSB_{bias}",
          curve=curve,
          bias=bias,
          mul_k_lower=2**bias))
      samples.append(gen_biased_signatures(
          sample_name = f"SAMPLE_{curve_name}_GENERALIZED_{bias}",
          curve=curve,
          bias=bias,
          mul_k_lower=0,
          mul_k_upper=2**bits))
    for bias in [16, 32, 64]:
      for lsb in [bits//2 - bias, (bits - bias)//2, bits//2]:
        mask = 2**bits - 2**(lsb + bias) + 2**(lsb) - 1
        samples.append(gen_biased_signatures(
            sample_name=f"SAMPLE_{curve_name}_zeros_{lsb}_{lsb+bias}",
            curve=curve,
            mask=mask))
  dump("../../keyhunt/biased_ecdsa_samples.json", samples)

#
# curve = "secp256r1", bias = 32
#    md: str = "SHA-256",
#    bias: int = 32,
#    mul_k_upper: int = None,
#    mul_k_lower: int = None,
#    allow_offset: bool = False,
#    cnt: int = 20):

def gen_u2f():
  samples= []
  samples.append(gen_biased_u2f_signatures("secp224r1"))
  samples.append(gen_biased_u2f_signatures("secp256r1"))
  samples.append(gen_biased_u2f_signatures("brainpoolP256r1"))
  samples.append(gen_biased_u2f_signatures("secp384r1"))
  samples.append(gen_biased_u2f_signatures("secp256r1",
      mode=biased_ecdsa.U2fMode.MOST_SIGNIFICANT_WORD,
      sample_name="SAMPLE_U2F_MOST_SIGNIFICANT_WORD"))
  samples.append(gen_biased_u2f_signatures("brainpoolP256r1",
      mode=biased_ecdsa.U2fMode.MOST_SIGNIFICANT_WORD,
      sample_name="SAMPLE_U2F_MOST_SIGNIFICANT_WORD"))
  samples.append(gen_biased_u2f_signatures("secp256r1",
      mode=biased_ecdsa.U2fMode.LEAST_SIGNIFICANT_WORD,
      sample_name="SAMPLE_U2F_LEAST_SIGNIFICANT_WORD"))
  samples.append(gen_biased_u2f_signatures("brainpoolP256r1",
      mode=biased_ecdsa.U2fMode.LEAST_SIGNIFICANT_WORD,
      sample_name="SAMPLE_U2F_LEAST_SIGNIFICANT_WORD"))
  dump("../../keyhunt/biased_u2f_samples.json", samples)


LCG_LIST = [
    ("Glibc",
        [("secp256r1", 20),
         ("brainpoolP256r1", None),
         ("secp384r1", None),
         ("secp521r1", None)]),
    ("NumericalRecipesLCG",
        [("secp256r1", 19),
         ("brainpoolP256r1",None),
         ("secp384r1", None),
         ("secp521r1", None)]),
    ("TurboPascal",
        [("secp256r1", None),
         ("brainpoolP256r1", None),
         ("secp384r1", None),
         ("secp521r1", None)]),
    ("PosixRand48",
        [("secp256r1", 15),
         ("brainpoolP256r1", None),
         ("secp384r1", None),
         ("secp521r1", None)]),
    ("Posix",
        [("secp256r1", 23),
         ("brainpoolP256r1", None),
         ("secp384r1", None),
         ("secp521r1", None)]),
    ("MMIX",
        [("secp256r1", 12),
         ("brainpoolP256r1", None),
         ("secp384r1", None),
         ("secp521r1", None)]),
    ("Gmp32_16",
        [("secp256r1", None),
         ("secp256k1", None),
         ("secp384r1", None),
         ("secp521r1", None)]),
    ("Gmp40_20",
        [("secp256r1", None),
         ("secp256k1", None),
         ("secp384r1", None),
         ("secp521r1", None)]),
    ("Gmp56_28",
        [("secp256r1", None),
         ("secp256k1", None),
         ("secp384r1", None),
         ("secp521r1", None)]),
    ("Gmp64_32",
        [("secp256r1", 26),
         ("secp256k1", None),
         ("secp384r1", 33),
         ("secp521r1", 42)]),
    ("Gmp100_50",
        [("secp256r1", None),
         ("secp256k1", None),
         ("secp384r1", None),
         ("secp521r1", None)]),
    ("Gmp128_64",
        [("secp256r1", 22),
         ("secp256k1", None),
         ("secp384r1", 23),
         ("secp521r1", 26)]),
    ("Gmp196_98",
        [("secp256r1", None),
         ("secp256k1", None),
         ("secp384r1", None),
         ("secp521r1", None)]),
    ("Gmp200_100",
        [("secp256r1", 37),
         ("secp256k1", None),
         ("secp384r1", 23),
         ("secp521r1", 23)]),
    ("Gmp256_128",
        [("secp256r1", None),
         ("secp256k1", None),
         ("secp384r1", 27),
         ("secp521r1", 23)]),
]

def gen_lcg(sample_size: Optional[int]):
  samples = []
  for lcg_name, curves in LCG_LIST:
    for curve, sigs in curves:
      normalize = (curve == "secp256k1")
      curve_name = curve.upper()
      samples.append(gen_biased_lcg_signatures(
          curve_name=curve,
          sample_name=f"SAMPLE_{curve_name.upper()}_{lcg_name.upper()}",
          lcg_name=lcg_name,
          normalize=normalize,
          cnt=sample_size))
  dump("../../keyhunt/biased_lcg_ecdsa_samples.json", samples)

def gen_mwc():
  samples = []
  for curve in ["secp256r1", "brainpoolP256r1", "secp384r1",
                "secp521r1"]:
    curve_name = curve.upper()
    for a, b in [
        (2**16 - 352, 2**16),
        (2**32 - 178, 2**32),
        (2**64 - 742, 2**64),
        (2**128 - 10480, 2**128),
    ]:
      txt = f"MWC_{(b - 1).bit_length()}"
      samples.append(gen_biased_mwc_signatures(
          curve_name=curve,
          sample_name=f"SAMPLE_{curve_name.upper()}_{txt}",
          a=a,
          b=b))
  dump("../../keyhunt/biased_mwc_ecdsa_samples.json", samples)

def gen_java_util_random():
  samples = []
  for curve, normalize  in [
      ("secp256r1", False),
      ("secp224r1", False),
      ("brainpoolP256r1", False),
      ("secp384r1", False),
      ("secp256k1", True)]:
    curve_name = curve.upper()
    name = f"SAMPLE_JAVA_UTIL_RANDOM_{curve_name}"
    samples.append(gen_biased_java_util_random_signatures(
          curve_name=curve,
          normalize=normalize,
          sample_name=name))
  dump("../../keyhunt/biased_java_util_random_ecdsa_samples.json", samples)

def gen_hidden_subset_sum():
  samples = []
  for curve, set_size, cnt in [
      ("secp256r1", 20, 50),
      ("secp256r1", 32, 120),
      ("secp521r1", 20, 50),
      ("secp521r1", 32, 120)]:
    samples.append(gen_biased_hidden_subset_sum_signatures(
        curve_name = curve,
        md = "SHA-256",
        cnt = cnt,
        set_size = set_size,
        normalize = False))
  dump("../../keyhunt/biased_hidden_subset_sum_samples.json", samples)

def gen_paranoid():
  samples = []
  for lcg_name, curves in LCG_LIST:
    for curve, cnt in curves:
      if cnt is None:
        continue
      curve_name = curve.upper()
      samples.append(gen_biased_lcg_signatures(
          curve_name=curve,
          sample_name=f"SAMPLE_{curve_name.upper()}_{lcg_name.upper()}",
          lcg_name=lcg_name))

  for curve, a, b, cnt in [
        ("secp256r1", 2**16 - 352, 2**16, 39),
        ("secp256r1", 2**32 - 178, 2**32, 23),
        ("secp256r1", 2**64 - 742, 2**64, 15),
    ]:
    curve_name = curve.upper()
    txt = f"MWC_{(b - 1).bit_length()}"
    samples.append(gen_biased_mwc_signatures(
        curve_name=curve,
        sample_name=f"SAMPLE_{curve_name.upper()}_{txt}",
        a=a,
        b=b, cnt=cnt))
  samples.append(gen_biased_u2f_signatures("secp256r1", cnt=23))
  samples.append(gen_biased_u2f_signatures("secp256r1",
      mode=biased_ecdsa.U2fMode.MOST_SIGNIFICANT_WORD,
      sample_name="SAMPLE_U2F_MOST_SIGNIFICANT_WORD", cnt = 23))
  samples.append(gen_biased_u2f_signatures("secp256r1",
      mode=biased_ecdsa.U2fMode.LEAST_SIGNIFICANT_WORD,
      sample_name="SAMPLE_U2F_LEAST_SIGNIFICANT_WORD", cnt=41))

  for curve, bias, cnt in [
    ("secp256r1", 16, 18),
    ("secp256r1", 32, 10),
    ("secp256r1", 64, 6)]:
    samples.append(gen_biased_signatures(curve=curve, bias=bias, cnt=cnt))

  for curve, bias, cnt in [
    ("secp256r1", 16, 18),
    ("secp256r1", 32, 10),
    ("secp256r1", 64, 6)]:
    curve_name = curve.upper()
    samples.append(gen_biased_signatures(
        sample_name = f"SAMPLE_{curve_name}_WITH_OFFSET_{bias}",
        curve=curve,
        bias=bias,
        cnt = cnt,
        allow_offset=True))
  for curve, bias, cnt in [
    # ("secp256r1", 16, 18),
    # ("secp256r1", 32, 10),
    # ("secp256r1", 64, 6)
    ]:
    curve_name = curve.upper()
    samples.append(gen_biased_signatures(
        sample_name = f"SAMPLE_{curve_name}_LSB_{bias}",
        curve=curve,
        cnt=cnt,
        bias=bias,
        mul_k_lower=2**bias))

  for curve, bits, bias, cnt in [
    # ("secp256r1", 256, 16),
    ("secp256r1", 256, 32, 18),
    # ("secp256r1", 256, 64)
    ]:
    curve_name = curve.upper()
    samples.append(gen_biased_signatures(
        sample_name = f"SAMPLE_{curve_name}_GENERALIZED_{bias}",
        curve=curve,
        bias=bias,
        cnt=cnt,
        mul_k_lower=0,
        mul_k_upper=2**bits))

  for curve, bias, lsb, cnt in [
        ("secp256r1", 32, 128, 18),
    ]:
    curve_name = curve.upper()
    mask = 2**bits - 2**(lsb + bias) + 2**(lsb) - 1
    samples.append(gen_biased_signatures(
        sample_name=f"SAMPLE_{curve_name}_zeros_{lsb}_{lsb+bias}",
        curve=curve,
        mask=mask))
  dump("../../keyhunt/biased_paranoid_samples.json", samples)

def gen_new():
  samples = []
  for lcg_name, curves in LCG_LIST:
    if lcg_name.upper()[:] != "GMP":
      continue
    for curve, cnt in curves:
      if cnt is None:
        continue
      curve_name = curve.upper()
      samples.append(gen_biased_lcg_signatures(
          curve_name=curve,
          sample_name=f"SAMPLE_{curve_name.upper()}_{lcg_name.upper()}",
          lcg_name=lcg_name))
  dump("../../keyhunt/biased_new_samples.json", samples)

def main():
  parser = argparse.ArgumentParser()
  parser.add_argument("--sample",
                      type=str,
                      default="lcg")
  parser.add_argument("--size",
                      type=int)
  args = parser.parse_args()
  sample = args.sample.lower()
  sample_size = getattr(args, "size", None)
  if sample == "all":
    gen_lcg(sample_size)
    gen_java_util_random()
    gen_mwc()
    gen_paranoid()
    gen_biased()
    gen_u2f()
    gen_hidden_subset_sum()
    gen_new()
  elif sample == "lcg":
    gen_lcg(sample_size)
  elif sample == "java":
    gen_java_util_random()
  elif sample == "mwc":
    gen_mwc()
  elif sample == "paranoid":
    gen_paranoid()
  elif sample == "biased":
    gen_biased()
  elif sample == "u2f":
    gen_u2f()
  elif sample == "hidden_subset_sum":
    gen_hidden_subset_sum()
  elif sample == "new":
    gen_new()
  else:
    raise ValueError("Unknown sample:" + sample)


if __name__ == "__main__":
  main()
