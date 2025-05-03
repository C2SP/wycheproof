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


class Vector:

  def __init__(self, alg: str, sha: str, P: bytes, S: bytes, c: int, dkLen: int, DK: str, src: str):
    """Constructs a test vector

    Args:
      P: the password
      S: the salt
      c: the iteration count
      dkLen: the length of the derived key
      DK: the derived key in hexadecimal representation
    """
    self.alg = alg
    self.sha = sha
    self.P = P
    self.S = S
    self.c = c
    self.dkLen = dkLen
    self.DK = DK
    self.src = src

PBKDF_TEST_VECTORS = [
# Test vectors from https://www.ietf.org/rfc/rfc6070.txt
    Vector(
        alg="PBKDF2",
        sha="SHA-1",
        P=b"password",
        S=b"salt",
        c=1,
        dkLen=20,
        DK="""0c 60 c8 0f 96 1f 0e 71
            f3 a9 b5 24 af 60 12 06
            2f e0 37 a6""",
        src = "RFC 6070"),
    Vector(
        alg="PBKDF2",
        sha="SHA-1",
        P=b"password",
        S=b"salt",
        c=2,
        dkLen=20,
        DK="""ea 6c 01 4d c7 2d 6f 8c
            cd 1e d9 2a ce 1d 41 f0
            d8 de 89 57""",
        src = "RFC 6070"),
    Vector(
        alg="PBKDF2",
        sha="SHA-1",
        P=b"password",
        S=b"salt",
        c=4096,
        dkLen=20,
        DK="""4b 00 79 01 b7 65 48 9a
            be ad 49 d9 26 f7 21 d0
            65 a4 29 c1""",
        src = "RFC 6070"),
    Vector(
        alg="PBKDF2",
        sha="SHA-1",
        P=b"password",
        S=b"salt",
        c=16777216,
        dkLen=20,
        DK="""ee fe 3d 61 cd 4d a4 e4
            e9 94 5b 3d 6b a2 15 8c
            26 34 e9 84""",
        src = "RFC 6070"),
    Vector(
        alg="PBKDF2",
        sha="SHA-1",
        P=b"passwordPASSWORDpassword",
        S=b"saltSALTsaltSALTsaltSALTsaltSALTsalt",
        c=4096,
        dkLen=25,
        DK="""3d 2e ec 4f e4 1c 84 9b
            80 c8 d8 36 62 c0 e4 4a
            8b 29 1a 96 4c f2 f0 70
            38""",
        src = "RFC 6070"),
    Vector(
        alg="PBKDF2",
        sha="SHA-1",
        P=b"pass\0word",
        S=b"sa\0lt",
        c=4096,
        dkLen=16,
        DK="""56 fa 6a a7 55 48 09 9d
            cc 37 d7 f0 34 25 e0 c3""",
        src = "RFC 6070"),
    Vector(
        alg="PBKDF2",
        sha="SHA-256",
        P=b"passwd",
        S=b"salt",
        c=1,
        dkLen=64,
        DK = """
   55 ac 04 6e 56 e3 08 9f ec 16 91 c2 25 44 b6 05
   f9 41 85 21 6d de 04 65 e6 8b 9d 57 c2 0d ac bc
   49 ca 9c cc f1 79 b6 45 99 16 64 b3 9d 77 ef 31
   7c 71 b8 45 b1 e3 0b d5 09 11 20 41 d3 a1 97 83""",
        src = "RFC 7914"),
    Vector(
        alg="PBKDF2",
        sha="SHA-256",
        P=b"Password",
        S=b"NaCl",
        c=80000,
        dkLen=64,
        DK = """
   4d dc d8 f6 0b 98 be 21 83 0c ee 5e f2 27 01 f9
   64 1a 44 18 d0 4c 04 14 ae ff 08 87 6b 34 ab 56
   a1 d4 25 a1 22 58 33 54 9a db 84 1b 51 c9 b3 17
   6a 27 2b de bb a1 d0 78 47 8f 62 b3 97 f3 3c 8d""",
        src = "RFC 7914"),
]

def all_test_vectors():
  return PBKDF_TEST_VECTORS

def test_vectors(alg: str,
                 sha: str):
  for t in all_test_vectors():
    if t.alg == alg and t.sha == sha:
      yield t
