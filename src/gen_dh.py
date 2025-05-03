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


import pseudoprimes

class DhParams:
  def __init__(self, name, p, g, q=None):
    self.name = name
    self.p = p
    self.q = q
    self.g = g
    assert g%p not in (0, 1, p-1)
    if q is None:
      ph = (p-1)//2
      if pseudoprimes.is_probable_prime(ph):
        w = pow(g, ph, p)
        if w == 1:
          self.q = ph
        else:
          assert w+1 == p
          self.q = p-1
    else:
      assert pow(g, q, p) == 1
  def usesSafePrimes(self):
    return pseudoprimes.is_probable_prime((self.p - 1)//2)


ike1536 = DhParams(
  name = "ike1536",
  p = int("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74"
        + "020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f1437"
        + "4fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7ed"
        + "ee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf05"
        + "98da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb"
        + "9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff", 16),
  g = 2)
ike2048 = DhParams(
  name = "ike2048",
  p = int("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74"
       + "020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f1437"
       + "4fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7ed"
       + "ee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf05"
       + "98da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb"
       + "9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3b"
       + "e39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf695581718"
       + "3995497cea956ae515d2261898fa051015728e5a8aacaa68ffffffffffffffff", 16),
  g = 2)

openjdk1024 = DhParams(
  name = "openjdk1024",
  p = int("fd7f53811d75122952df4a9c2eece4e7f611b7523cef4400c31e3f80b6512669"
        + "455d402251fb593d8d58fabfc5f5ba30f6cb9b556cd7813b801d346ff26660b7"
        + "6b9950a5a49f9fe8047b1022c24fbba9d7feb7c61bf83b57e7c6a8a6150f04fb"
        + "83f6d3c51ec3023554135a169132f675f3ae2b61d72aeff22203199dd14801c7", 16),
  q = int("9760508f15230bccb292b982a2eb840bf0581cf5", 16),
  g = int("f7e1a085d69b3ddecbbcab5c36b857b97994afbbfa3aea82f9574c0b3d078267"
        + "5159578ebad4594fe67107108180b449167123e84c281613b7cf09328cc8a6e1"
        + "3c167a8b547c8d28e0a3ae1e2bb3a675916ea37f0bfa213562f1fb627a01243b"
        + "cca4f1bea8519089a883dfe15ae59f06928b665e807b552564014c3bfecf492a", 16))

rfc5114group22 = DhParams(
  name = "rfc5114group22",
  p = int("B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C6"
        + "9A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C0"
        + "13ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD70"
        + "98488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0"
        + "A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708"
        + "DF1FB2BC2E4A4371", 16),
  g = int("A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507F"
        + "D6406CFF14266D31266FEA1E5C41564B777E690F5504F213"
        + "160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1"
        + "909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28A"
        + "D662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24"
        + "855E6EEB22B3B2E5", 16),
   q = int("F518AA8781A8DF278ABA4E7D64B7CB9D49462353", 16))

# TODO: Needs a parser
if __name__ == "__main__":
  for p in (ike1536, ike2048, openjdk1024, rfc5114group22):
    print(p.name)
    print("uses safe primes", p.usesSafePrimes())
    if p.q and p.g:
       print("g**q mod p", pow(p.g, p.q, p.p))


