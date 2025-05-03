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

import gen_test_vectors
import json
import tar_util
import base64

CURVES = [
    "secp192r1",  #  X9_62_prime192v1
    "secp256r1",  #  X9_62_prime256v1
    "sect163k1",
    "sect163r2",
    "sect233k1",
    "sect233r1",
    "sect283k1",
    "sect283r1",
    "sect409k1",
    "sect409r1",
    "sect571k1",
    "sect571r1",
    "secp224r1",
    "secp384r1",
    "secp521r1",
    "FRP256v1",
    "secp192k1",
    "secp256k1",
    "brainpoolP160r1",
    "brainpoolP192r1",
    "brainpoolP224r1",
    "brainpoolP256r1",
    "brainpoolP320r1",
    "brainpoolP384r1",
    "brainpoolP512r1",
    "curve25519",
    "curve448",
]

class Namespace:
  pass


def get_files():
  files = {}
  for curve_name in CURVES:
    for encoding in ["pem", "asn"]:
      name = f"ec_priv_key_{curve_name}_{encoding}_test.json"
      if curve_name in ["curve25519", "curve448"]:
        generator = "gen_xdh_priv_key.py"
      else:
        generator = "gen_ec_priv_key.py"
      files[name] = {
          "status": "internal",
          "generator": generator,
          "curve": curve_name,
          "encoding": encoding
      }
  return files

def generate_keys():
  """Generates test vectors for the curves suppprted by Cavium HSM.
  
  For each of the curves three files are generated:
    (1) A JSON file with PEM encoded keys.
    (2) A JSON file with ASN encoded keys. The ASN is the same as the
        base64 encoded content in a PEM encoding. Some libraries (e.g.
        the Java providers) are easier to test with ASN encodings.
    (3) A tar file with the PEM encoded keys.
  The JSON encoded files will most likely be added to Wycheproof, when
  the are stable. The tar files can always be generated from the JSON files
  when necessary.
  """
  # The director where the test vectors are written to.
  test_vector_dir = "../testvectors/cavium/"
  files = get_files()
  # Dumps the list of files. Test vectors can be generated from
  # such list of files.
  fp = open(test_vector_dir + "cavium_files.json", 'w')
  json.dump(files, fp, indent=2)
  fp.close()
  # Test vector generation in Wycheproof is normally done from the command line.
  # The code uses a namespace returned by argparse. The variable ns simply
  # copies the result of argparse.
  ns = Namespace()
  ns.version = "internal"
  ns.age = 0
  ns.dir = test_vector_dir
  ns.poolsize = 12
  ns.silent = False
  ns.gen = ""
  ns.contains = ""
  gen_test_vectors.gen_test_vectors(ns, files)
  # Generate a tar files for the pem encoded keys
  for filename in files:
    if filename.endswith("_pem_test.json"):
      input_name = test_vector_dir + filename
      output_name = test_vector_dir + filename[:-10] + ".tar"
      tar_util.json_to_tar(input_name, output_name, "EcPrivKey", "encodedKey")


if __name__ == "__main__":
  # test_xdh()
  generate_keys()
