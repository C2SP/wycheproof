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

from asn import *
import asn
import asn_parser
import base64
import asn_fuzzing
import io
import tarfile
import ec_key
import ec_groups
import pem_util
import prand


# TODO: Add more structural fuzzing.
#   So far the fuzzing just includes general ASN fuzzing.
#   The fuzzer does not understand EcPrivate key structures defined in RFCs.
#   Hence it cannot generate additional test vectors. These have to be added
#   by hand:
#     - There is an optional parameter for the ECParameters.
#       This parameter is redundant and hence can lead to confusion.
#     - include multiple public keys
#     - include false parameters
# Type hints

# KeyInfo is a dictionary describing a key.
# It"s fields are:
#   asn_struct: The ASN structure of the key.
#     This field is used for fuzzing.
#   pem: the PEM encoded key
#   private_s: the private key as integer.
KeyInfo = dict

def pem(struct):
  return pem_util.private_key_pem(encode(struct))

def der_to_pem(der):
  return pem_util.private_key_pem(der)

KEY_1 = {
    "pem":
        b"-----BEGIN PRIVATE KEY-----\n"
        b"MIGEAgEAMBAGByqGSM49AgEGBSuBBAAKBG0wawIBAQQgMAlRnq4Z5FZ1TFlCxNPb\n"
        b"tiRrtCQmX7IBNJTvvhwPF06hRANCAAQN5OK6Cmde3HJLoWlpGoHzERNAIlh6D6RM\n"
        b"IvDwT2xsw8oWN9G9JIgYkemHkJW81qt6I1mlmDX7yi2sEjv92lPT\n"
        b"-----END PRIVATE KEY-----\n",
    "asn_struct": [
        0,
        [Oid("2a8648ce3d0201"), Oid("2b8104000a")],
        OctetStringFromStruct([
            1,
            OctetString("3009519eae19e456754c5942c4d3dbb6"
                        "246bb424265fb2013494efbe1c0f174e"),
            Explicit(
                1,
                BitString(
                    bytes.fromhex("040de4e2ba0a675edc724ba169691a81"
                                  "f311134022587a0fa44c22f0f04f6c6c"
                                  "c3ca1637d1bd24881891e9879095bcd6"
                                  "ab7a2359a59835fbca2dac123bfdda53d3")),
                CONTEXT_SPECIFIC, True)
        ]),
    ],
    "private_s":
        int(
            "3009519eae19e456754c5942c4d3dbb6"
            "246bb424265fb2013494efbe1c0f174e", 16)
}

KEY_2 = {
    "pem":
        b"-----BEGIN PRIVATE KEY-----\n"
        b"MIGEAgEAMBAGByqGSM49AgEGBSuBBAAKBG0wawIBAQQgGDKdcnasePgHLwXpZWB/\n"
        b"3igbhI+K+RclaHeSDJGB+ZyhRANCAASQNYy6m48AAW7zqN1TK+COpgpBPQyJuX5e\n"
        b"pPbdge0K4Dg4djx7s/yjtrYgdw1deZrPRdAxr+C7y/hO0m+XY5P9\n"
        b"-----END PRIVATE KEY-----\n",
    "asn_struct": [
        0,
        [Oid("2a8648ce3d0201"), Oid("2b8104000a")],
        OctetStringFromStruct([
            1,
            OctetString("18329d7276ac78f8072f05e965607fde"
                        "281b848f8af917256877920c9181f99c"),
            Explicit(
                1,
                BitString(
                    bytes.fromhex("0490358cba9b8f00016ef3a8dd532be0"
                                  "8ea60a413d0c89b97e5ea4f6dd81ed0a"
                                  "e03838763c7bb3fca3b6b620770d5d79"
                                  "9acf45d031afe0bbcbf84ed26f976393fd")),
                CONTEXT_SPECIFIC, True)
        ]),
    ],
    "private_s":
        int(
            "18329d7276ac78f8072f05e965607fde"
            "281b848f8af917256877920c9181f99c", 16),
}

def extract(tar, name: str) -> str:
  f = tar.extractfile(name)
  txt = f.read()
  f.close()
  assert isinstance(txt, bytes)
  return txt.decode("ascii")


def fuzz_pem(key: KeyInfo,
             filename: str = None,
             check: bool = False,
             keyname_prefix: str = "EcPrivateKey",
             more_comments: dict = None):
  """Takes an EC key and generates modified keys.
  
  Args:
    key: the key, key["asn_struct"] must be defined.
    filename: the filename for the tar file
    check: True, if the tar file is read back and logged.
    keyname_prefix: the prefix for the key names in the tar file.
 """

  def add_file(tar, name: str, content):
    if isinstance(content, str):
      content = content.encode("ascii")
    if tar is None:
      return
    s = io.BytesIO(content)
    tarinfo = tarfile.TarInfo(key_name)
    tarinfo.size = len(content)
    tar.addfile(tarinfo, s)

  loglines = []

  def log(txt):
    if isinstance(txt, str):
      pass
    elif isinstance(txt, bytes):
      txt = txt.decode("ascii")
    else:
      txt = str(txt)
    loglines.append(txt)

  if filename is None:
    tar = None
  else:
    try:
      tar = tarfile.open(filename, "w")
    except Exception:
      print("cannot open", filename)
      tar = None
  struct = key["asn_struct"]
  der_key = encode(struct)
  keymat_key = encode(struct[2])
  unmodified = []
  cnt = 0
  keys = {}
  for txt, der in asn_fuzzing.generate(struct):
    key_name = keyname_prefix + str(cnt)
    # keep the count for now.
    cnt += 1
    if der in keys:
      log(f"{key_name} is identical to {keys[der]}")
      continue
    keys[der] = key_name
    # Check if this is just some BER
    log(key_name)
    log(txt)
    try:
      if der == der_key:
        log("Unmodified PEM")
        unmodified.append(cnt-1)
      else:
        struct = asn_parser.parse(der)
        if not isinstance(struct, list):
          log("The key has the wrong type")
        elif len(struct) < 3:
          log("The key material is missing")
        elif not isinstance(struct[2], AsnElement):
          log("The key material has an incorrect type")
        else:
          keymat = asn_parser.parse(struct[2].val)
          der2 = encode(struct)
          if der2 == der_key:
            log("Same key, but with alternative BER encoding")
            unmodified.append(cnt - 1)
          else:
            log("The key was modified, but has valid ASN encoding.")
    except asn.AsnError as ex:
      log("The key is invalid: " + str(ex))
    except Exception as ex:
      print(struct)
      raise ex
    pem = der_to_pem(der)
    log(pem)
    add_file(tar, key_name, pem)
  log(f"unmodified:{unmodified}")
  logs = "\n".join(loglines)
  if tar is None:
    print(logs)
  else:
    add_file(tar, "keys.txt", logs)
    tar.close()


def test():
  for key in [KEY_1, KEY_2]:
    parsed = key["asn_struct"]
    key_pem1 = key["pem"].decode("ascii")
    key_pem2 = pem(parsed)
    s = key["private_s"]
    priv = ec_key.EcPrivateKey(group=ec_groups.named_curve("secp256k1"), s=s)
    der = priv.encode(include_public=True)
    key_pem3 = pem(der)
    print(key_pem1)
    print(key_pem3)
    assert key_pem1 == key_pem2 == key_pem3


def gen_keys_hsm():
  key = KEY_1
  accepted = [
      0, 1, 16, 37, 42, 52, 53, 54, 87, 88, 90, 93, 94, 95, 131, 145, 146, 147,
      194, 195, 196, 243, 244, 245, 258, 261, 263, 265, 268, 269, 277, 282, 283,
      284, 299, 320, 325, 335, 336, 349, 352, 367, 369, 370, 372, 374, 375, 376,
      390, 394, 396, 399, 400, 408, 414, 415, 460, 461, 479, 481, 484, 485, 493
  ]
  keyname_prefix = "EcPrivateKey"
  more_comments = {}
  for i in accepted:
    more_comments[keyname_prefix + str(i)] = ("Accepted by HSM",)
  fuzz_pem(key, "../testvectors/EcPrivKeyForFuzzing.tar", True, keyname_prefix,
           more_comments)


def fuzz_eckey(filename: str,
               group: ec_groups.EcGroup,
               s: int,
               keyname_prefix: str = "EcPrivateKey",
               include_public: bool = True):
  p = ec_key.EcPrivateKey(group, s)
  key = {
      "asn_struct": p.asn_struct(include_public=True),
      "pem": pem(p.encode(include_public=True)),
      "private_s": s
  }
  fuzz_pem(key, filename, False, keyname_prefix)


def gen_keys():
  for group in ec_groups.predefined_curves:
    s = prand.randrange(1, group.n, seed=b"12j3lkau", label=group.name)
    fuzz_eckey(f"../testvectors/ec_priv_keys_{group.name}.tar", group, s)


if __name__ == "__main__":
  test()
  fuzz_eckey(None, ec_groups.named_curve("secp256r1"), 3**256 % 2**256)
  gen_keys()
