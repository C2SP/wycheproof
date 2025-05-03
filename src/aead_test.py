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

from google3.experimental.users.bleichen.wycheproof.py3.hazmat import test_util

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305, AESCCM, AESGCM


def test_aead(get_cipher, filename):
  """get_cipher(key, group) must either return a crypter or None, if

     the parameters are not implemented.
  """

  def fail(tc, msg):
    nonlocal errors
    errors += 1
    print(msg, tc)

  test = test_util.get_test_vectors(filename)
  algorithm = test["algorithm"]
  print()
  print("path:", filename)
  expected = "aead_test_schema.json"
  if test["schema"] != expected:
    print("schema expected:%s actual:%s" % (expected, test["schema"]))
    return 1
  print("number of tests:", test["numberOfTests"])
  cnt = 0
  errors = 0
  for g in test["testGroups"]:
    for t in g["tests"]:
      key = bytes.fromhex(t["key"])
      try:
        crypter = get_cipher(key, g)
      except Exception:
        continue
      cnt += 1
      msg = bytes.fromhex(t["msg"])
      aad = bytes.fromhex(t["aad"])
      ct = bytes.fromhex(t["ct"] + t["tag"])
      iv = bytes.fromhex(t["iv"])
      result = t["result"]
      # Test encryption
      try:
        ct2 = crypter.encrypt(iv, msg, aad)
        if result == "invalid":
          if ct == ct2:
            fail(t, "Encrypted invalid test case")
        elif result == "valid":
          if ct != ct2:
            fail(t, "Incorrect encryption")
      except Exception as e:
        if result == "valid":
          fail(t, "Encryption failed " + str(e))
      # Test decryption
      try:
        msg2 = crypter.decrypt(iv, ct, aad)
        if result == "invalid":
          fail(t, "Decrypted invalid test case")
        else:
          if msg != msg2:
            fail(t, "Incorrect decryption")
      except Exception as e:
        if result == "valid":
          fail(t, "Decryption failed " + str(e))
  print("Tests done:", cnt)
  print("Errors:", errors)
  print()
  return errors == 0


def get_chacha20(key: bytes, group):
  """ChaChaPoly1305 fixes tag size and iv size.

     Hence there is no choice here.
  """
  return ChaCha20Poly1305(key)


def get_gcm(key: bytes, group):
  """Only tags of size 128 are supported.

  Other would need to be skipped.
     Most test vectors use 128-bit tag sizes. So this is not an issue.
  """
  if group["tagSize"] != 128:
    raise ValueError("unsupported tag size")
  return AESGCM(key)


def get_ccm(key: bytes, group):
  """Invalid tag sizes are rejected during initialization."""
  return AESCCM(key, group["tagSize"] // 8)


if __name__ == "__main__":
  test_aead(get_chacha20, "chacha20_poly1305_test.json")
  test_aead(get_gcm, "aes_gcm_test.json")
  test_aead(get_ccm, "aes_ccm_test.json")
