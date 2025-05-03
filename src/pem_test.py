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
import pem
import pem_pkcs5
import pem_samples
import pem_util
import json

def make_key(e, p, q):
  """Returns an RSA key from e, p and q.
  
  The function is used as a sanity check in the tests below.
  If recomputing the CRT values matches with the decrypted values
  then one can assume that deryption was likely correct.
  """
  n = p * q
  dp = pow(e, -1, p - 1)
  dq = pow(e, -1, q - 1)
  d = pow(e, -1, (p - 1) * (q - 1))
  qinvp = pow(q, -1, p)
  return [0, n, e, d, p, q, dp, dq, qinvp]


def test(log=True):
  pem_key = pem_samples.SAMPLE
  id_aes128_ECB = pem.get_oid('2.16.840.1.101.3.4.1.1')
  hmac_md = "SHA-256"

  pw = b'abcd'
  salt = bytes.fromhex('541d00ddff1b641a')
  rsa = pem.pem_pkcs8_decrypt(pem_key, pw, log=False)
  rsa2 = make_key(rsa[2], rsa[4], rsa[5])
  assert rsa == rsa2
  enc = pem.pem_pkcs8_encrypt(
      rsa, pw, salt=salt, c=2048,
      alg_oid = id_aes128_ECB,
      hmac_md = hmac_md)

  if log:
    for i, n in enumerate(['version', 'n', 'e', 'd', 'p', 'q', 'dp', 'dq',
                           'crt']):
      print(n, '=', hex(rsa[i]))
    print(enc)
    print(pem_key)
  assert enc == pem_key

def test_pkcs8(log=False):
  print("test_pkcs8")
  pw = b'abcd'
  for cipher, sample in pem_samples.SAMPLES_PKCS8:
    try:
      params = pem.pem_pkcs8_decrypt_raw(sample, pw, log=log)
      rsa, salt, c, alg_oid, iv, hmac_md = params
      rsa2 = make_key(rsa[2], rsa[4], rsa[5])
      if rsa != rsa2:
        for i, n in enumerate(
            ['version', 'n', 'e', 'd', 'p', 'q', 'dp', 'dq', 'crt']):
          print(n, '=', hex(rsa[i]))
        assert False
      pem2 = pem.pem_pkcs8_encrypt(rsa2, pw, salt, c, alg_oid, iv, hmac_md)
      if pem2 == sample:
        print(cipher, "ok")
      else:
        # One reason for differences to happen are defaults.
        # E.g. this happens when HMAC-SHA1 is used for the PRF.
        for i in range(min(len(sample), len(pem2))):
          if sample[i] != pem2[i]:
            txt = 'first diff at position %d' % i
            break
        else:
          txt = 'truncated'
        diffs = sum(x != y for x, y in zip(sample, pem2))
        print(cipher, "distinct ct", len(sample), len(pem2), txt)
    except Exception as ex:
      print(cipher, "throws", ex)
  print("--done--")

def test_pkcs5():
  # TODO: PKCS5 decryption is not complete because of lack of
  #   documentation.
  print("test_pkcs5")
  pw = b'abcd'
  for cipher, sample in pem_samples.SAMPLES_PKCS5:
    try:
      pem_pkcs5.pem_pkcs5_decrypt(sample, pw, log=False)
      print(cipher, "ok")
    except Exception as ex:
      print(cipher, "throws", ex)


def test_formats(samples):
  for txt, pem in samples:
    try:
      label, b64, d, checksum = pem_util.parse(pem)
      print()
      print(label)
      for k, v in d.items():
        print(k, ':', v)
      asn = base64.b64decode(b64.encode('ascii'))
      asn_struct = asn_parser.parse(encoding)
      if isinstance(asn_struct, list):
        for v in asn_struct:
          print(v)
      else:
        print(asn_struct)
    except Exception as ex:
      print(ex)

class MyEncoder(json.JSONEncoder):
  def default(self, val):
    if isinstance(val, bytes):
      return val.hex()
    try:
      return json.JSONEncoder.default(self, val)
    except Exception:
      return repr(val)

def pprint(struct):
  print(json.dumps(struct, indent=2, cls=MyEncoder))

def test_formats2(samples):
  print('-----TEST FORMATS2 -------')
  for txt, pem in samples:
    try:
      label, b64, d, checksum = pem_util.parse(pem)
      struct = pem_util.parse_to_struct(pem)
      print(label)
      pprint(struct.native)
    except Exception as ex:
      print(label, ex)

def all_tests():
  test()
  test_pkcs8()
  # test_pkcs5()
  test_formats(pem_samples.FORMAT_SAMPLES)
  test_formats(pem_samples.MISC_SAMPLES)
  test_formats2(pem_samples.FORMAT_SAMPLES)
  test_formats2(pem_samples.CERTIFICATE_SAMPLES)

if __name__ == '__main__':
  test_formats2(pem_samples.CERTIFICATE_SAMPLES)

