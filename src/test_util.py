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

"""Test util for cryptography.hazmat"""

__author__ = "bleichen@google.com (Daniel Bleichenbacher)"

import json
import re
import tarfile
from typing import Optional

from google3.pyglib import resources
from cryptography.hazmat.primitives import hashes

TEST_VECTOR_PATH = "google3/third_party/wycheproof/testvectors/"
TAR_PATH = "google3/experimental/users/bleichen/wycheproof/py3/hazmat/"

def get_test_vectors(fname: str,
                     path: Optional[str] = None):
  if path is None:
    path = TEST_VECTOR_PATH
  txt = resources.GetResource(path + fname)
  return json.loads(txt)


def get_all_test_vectors(pattern: str,
                         schema: Optional[str] = None,
                         path: Optional[str] = None):
  if path is None:
    path = TEST_VECTOR_PATH
  regex = re.compile(pattern)
  for root, dirs, files in resources.WalkResources(path):
    if root != path:
      # skip
      continue
    for name in files:
      if regex.match(name):
        try:
          test = get_test_vectors(name, path=path)
          if schema is None or test["schema"] == schema:
            yield name, test
        except Exception as e:
          print("Could not load %s. Reason: %s" % (name, e))

def extract(tar, name: str) -> bytes:
  f = tar.extractfile(name)
  txt = f.read()
  f.close()
  return txt

def extract_from_tar(pattern: str,
                     filename: str,
                     path: Optional[str] = None):
  """Returns the content of all members matching pattern in a tar file.
  
  Args:
    pattern: a regex pattern
    filename: the name of a tar file
  Yields:
    tuples (name:str, content: bytes)
  """
  if path is None:
    path = TAR_PATH
  file_obj = resources.GetResourceAsFile(path + filename)
  tar = tarfile.open(fileobj=file_obj)
  regex = re.compile(pattern)
  for member in tar:
    if regex.match(member.name):
      pem = extract(tar, member.name)
      yield member.name, pem


def get_hash(md):
  try:
    if md == "MD5":
      return hashes.MD5()
    elif md == "SHA-1":
      return hashes.SHA1()
    elif md == "SHA-224":
      return hashes.SHA224()
    elif md == "SHA-256":
      return hashes.SHA256()
    elif md == "SHA-384":
      return hashes.SHA384()
    elif md == "SHA-512":
      return hashes.SHA512()
    elif md == "SHA3-224":
      return hashes.SHA3_224()
    elif md == "SHA3-256":
      return hashes.SHA3_256()
    elif md == "SHA3-384":
      return hashes.SHA3_384()
    elif md == "SHA3-512":
      return hashes.SHA3_512()
    # Added in version 2.5, but it is always possible that
    # the backend does not support the hash.
    elif md == "SHA-512/224":
      return hashes.SHA512_224()
    elif md == "SHA-512/256":
      return hashes.SHA512_256()
  except AttributeError:
    raise ValueError("Unsupported hash:" + md)
  raise ValueError("unknown hash " + md)
