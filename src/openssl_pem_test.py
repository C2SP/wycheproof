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

import asn_parser
import base64
import shlex
import pem_util
import subprocess
from typing import Optional

def run_process(cmd:str, inp:Optional[bytes]=None) -> bytes:
  print(cmd)
  args = shlex.split(cmd)
  res = subprocess.run(args,
                       input=inp,
                       capture_output=True)
  return res.stdout

class KeyGenerator:
  priv_label = None
  pub_label = None

  def priv_header(self):
    return f"-----BEGIN {self.priv_label}-----"

  def priv_footer(self):
    return f"-----END {self.priv_label}-----"

  def pub_header(self):
    return f"-----BEGIN {self.pub_label}-----"

  def pub_footer(self):
    return f"-----END {self.pub_label}-----"

# Generating keys with openssl genpkey
# sample command line:
# openssl genpkey -algorithm ed25519 -outform PEM -out ed25519_priv.pem
# openssl pkey -in ed25519_priv.pem -outform PEM -pubout -out ed25519_pub.pem
class GenPkeyGenerator(KeyGenerator):
  priv_label = "PRIVATE KEY"
  pub_label = "PUBLIC KEY"
  algorithm = None

  def __init__(self):
    pass

  def parameters(self) -> str:
    return ""

  def priv_key(self) -> bytes:
    if self.algorithm is None:
      raise ValueError("Unknown algorithm")
    params = self.parameters()
    return run_process(f"openssl genpkey -algorithm {self.algorithm} {params}")

  def pub_key(self, privkey: bytes) -> bytes:
    return run_process(f"openssl pkey -pubout", inp=privkey)

class Ed25519KeyGenerator(GenPkeyGenerator):
  algorithm = "ed25519"

class X25519KeyGenerator(GenPkeyGenerator):
  algorithm = "X25519"

class RsaKeyGenerator(GenPkeyGenerator):
  algorithm = "RSA"

  def __init__(self, key_size_in_bits):
    self.key_size_in_bits = key_size_in_bits

  def parameters(self):
    return f"-pkeyopt rsa_keygen_bits:{self.key_size_in_bits}"


class EcKeyGenerator(GenPkeyGenerator):
  algorithm = "EC"
  def __init__(self, curve: str):
    self.curve = curve

  def parameters(self):
    return f"-pkeyopt ec_paramgen_curve:{self.curve}"

# Alternative RSA key generation
# command line:
# openssl genrsa -out rsa_priv_2048.pem 2048
# openssl rsa -in rsa_priv_2048.pem -outform PEM -pubout -out rsa_pub_2048.pem
class AltRsaKeyGenerator(KeyGenerator):
  # RSAPrivateKey, RFC 8017, Section A.1.2
  priv_label = "RSA PRIVATE KEY"
  pub_label = "PUBLIC KEY"

  def __init__(self, key_size_in_bits: int):
    self.key_size = key_size_in_bits

  def priv_key(self) -> bytes:
    return run_process(f"openssl genrsa {self.key_size}")

  def pub_key(self, privkey: bytes) -> bytes:
    return run_process(f"openssl rsa -pubout", inp=privkey)

# EC keys:
# command line:
# openssl ecparam -name secp256k1 -genkey -noout -out secp256k1_priv.pem
# openssl ec -in secp256k1_priv.pem -outform PEM -pubout -out secp256k1_pub.pem
class AltEcKeyGenerator(KeyGenerator):
  # Contains an ECPrivateKey defined in section 3 of RFC 5915
  priv_label = "EC PRIVATE KEY"
  pub_label = "PUBLIC KEY"

  def __init__(self, curve: str):
    self.curve = curve

  def priv_key(self) -> bytes:
    return run_process(f"openssl ecparam -name {self.curve} -noout -genkey")

  def pub_key(self, privkey: bytes) -> bytes:
    return run_process(f"openssl ec -pubout", inp=privkey)

def parse_pem(pem: bytes, header:str, footer:str):
  header = header.encode("ascii")
  footer = footer.encode("ascii")
  pos_header = pem.find(header)
  pos_footer = pem.find(footer)
  if pos_header < 0:
    raise ValueError("could not find header")
  if pos_footer < pos_header + len(header):
    raise ValueError("could not find footer")
  b64 = pem[pos_header + len(header): pos_footer]
  b = base64.b64decode(b64)
  return asn_parser.parse(b)


def test_generators():
  for kg in [
     RsaKeyGenerator(2048),
     AltRsaKeyGenerator(2048),
     # NOTE(bleichen): openssl does not seem to use consistent curve names.
     EcKeyGenerator("P-256"),
     AltEcKeyGenerator("secp256r1"),
     Ed25519KeyGenerator(),
     X25519KeyGenerator()]:
    print()
    print(f"===== {type(kg).__name__} =====")
    priv = kg.priv_key()
    pub = kg.pub_key(priv)
    print(priv.decode("ascii"))
    print(pub.decode("ascii"))
    print('---ASN---')
    priv_asn = parse_pem(priv, kg.priv_header(), kg.priv_footer())
    pub_asn = parse_pem(pub, kg.pub_header(), kg.pub_footer())
    print(priv_asn)
    print(pub_asn)

# generated with openssl gendsa dsa_params.pem
# The format is [0, p, q, g, y, x]
dsa1 = """-----BEGIN DSA PRIVATE KEY-----
MIIDVgIBAAKCAQEA1YweeI5bStdCJY4ITDAptg3M12ZLw2h+VNtmiSuWDk+tFd6G
Yg0ZzpcFO56fezY7NdolCUdVTok2FdD2c7pcFpUKE24rwKzeVmYkF7Q9Unzt77HT
DmaARPumTWwsarMimszKj2vXh61w0bH2CwHMYjMjUKVfIcHFFTUggg6p/7GIeB9O
/0EYjvP56c9+aHLOwyNEjLN2u281Hbyyzh1jUdTmp9Oh+A5AgePMDmcJDzzjhw7T
5+LEZ81HSFLhBjVXfcJN4UeOOdmG8mw+zaDvSVEJPWgIz5DSAm5Q82YO3d1dO9Qb
jK1X0dY5c/XSc/m0ve3egxSC5/QZ5PfvzZG/EwIhALH42rNJVD/Hw/8qXdnqfngN
EirmNO7BeWzqzO++n9NvAoIBAQCLG1ZDN59avF7Fh06DAs26+Ji8hIMmAF3AUopk
UYjascJLAn9c72CvCIc0Gnc11h2WzI3Q6vNp2wj9Y66T9KdqJNfcBgbX9bBRsd4e
PyEGh+GX0k9VnWXKpe2kzIfqnJlzT46xavXyAGuK3mFibBkLpp1Q4NbHV8iwTNhu
60uV0kK5Adh44pGvfupPH45vtb8kGlXqPLhva6WrCmqYvXs9j5+S7NjxuGn4ukV8
G1HxzX0OAjyKYVz69YLtQ17ZNmcjcPzdVPjBDzbhdTOxE1gFrpVV8w0hiaobEJLV
ueAA/BLojtn05eFP9AcvUtfbNUuHwHf8sI/1P6aOAOck0HbcAoIBACCb/ApP3ZC7
7EwcAPRjncej4sYjSvC+NVVxvy6sRUfaRNQVeb+1uogxAuIrSGK5At8OY7t7/Mqr
O5zCzi615B3jAlNbRpK8RF7VETRzmKkuKolooQD2Wc7BtGk/lJEqVGxmzDLQc1Rh
EPs85nLVzqoyJ2r4zuzVpO0Oh3MhfITAcxtSBeiX3eiSvrrSGluAj1Z+wm9Ea9h3
30G7kESB0jcvUV/rkR3tI1OCAbYcOQ2uKhEG87i5YDEFJHn2fU4trW7cJjEErV6I
b+m6os/L8d3gA68duiMBYY2prNZPlrGU7q6vImimQItN5CkcNi8ufkcg8+NMMdFB
+gd9191HiQ8CIEkvk/2P/zlOk4oG4InUMRGFQCV7X19iiSd3oSpFH2p8
-----END DSA PRIVATE KEY-----
"""

# generated with openssl genpkey -param_file dsa_params.pem
# The format is [0, [dsa-oid, [p, q, g]], OctetString(x)]
dsa2 = """
-----BEGIN PRIVATE KEY-----
MIICZQIBADCCAjoGByqGSM44BAEwggItAoIBAQDVjB54jltK10IljghMMCm2DczX
ZkvDaH5U22aJK5YOT60V3oZiDRnOlwU7np97Njs12iUJR1VOiTYV0PZzulwWlQoT
bivArN5WZiQXtD1SfO3vsdMOZoBE+6ZNbCxqsyKazMqPa9eHrXDRsfYLAcxiMyNQ
pV8hwcUVNSCCDqn/sYh4H07/QRiO8/npz35ocs7DI0SMs3a7bzUdvLLOHWNR1Oan
06H4DkCB48wOZwkPPOOHDtPn4sRnzUdIUuEGNVd9wk3hR4452YbybD7NoO9JUQk9
aAjPkNICblDzZg7d3V071BuMrVfR1jlz9dJz+bS97d6DFILn9Bnk9+/Nkb8TAiEA
sfjas0lUP8fD/ypd2ep+eA0SKuY07sF5bOrM776f028CggEBAIsbVkM3n1q8XsWH
ToMCzbr4mLyEgyYAXcBSimRRiNqxwksCf1zvYK8IhzQadzXWHZbMjdDq82nbCP1j
rpP0p2ok19wGBtf1sFGx3h4/IQaH4ZfST1WdZcql7aTMh+qcmXNPjrFq9fIAa4re
YWJsGQumnVDg1sdXyLBM2G7rS5XSQrkB2Hjika9+6k8fjm+1vyQaVeo8uG9rpasK
api9ez2Pn5Ls2PG4afi6RXwbUfHNfQ4CPIphXPr1gu1DXtk2ZyNw/N1U+MEPNuF1
M7ETWAWulVXzDSGJqhsQktW54AD8EuiO2fTl4U/0By9S19s1S4fAd/ywj/U/po4A
5yTQdtwEIgIgXWCmkaN9pyVW0rB6LHKq4F57201jfTcSzjCZthqgC20=
-----END PRIVATE KEY-----
"""


def test_dsa():
  print("-----test_dsa-----")
  for pem in [dsa1, dsa2]:
    label, b64, header_info, checksum = pem_util.parse(pem)
    asn = base64.b64decode(b64)
    struct = asn_parse.parse(asn)
    print(struct)


if __name__ == "__main__":
  test_generators()
  test_dsa()
