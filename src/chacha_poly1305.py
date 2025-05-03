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

import poly1305
import chacha
import util

class Chacha20Poly1305:
  '''Implements tha AEAD interface.'''
  tagsize = 16

  @util.type_check
  def __init__(self, key: bytes):
    self.key = key

  def poly_key(self, nonce: bytes) -> bytes:
    return chacha.chacha20_block(self.key, nonce, 0)[:32]

  def tag(self, nonce: bytes, aad: bytes, ct: bytes)-> bytes:
    poly_key = self.poly_key(nonce)
    poly_inp = aad + bytes(-len(aad) % 16)
    poly_inp += ct + bytes(-len(ct) % 16)
    poly_inp += poly1305.int_to_bytes(len(aad), 8) 
    poly_inp += poly1305.int_to_bytes(len(ct), 8)
    return poly1305.poly1305(poly_key, poly_inp)

  @util.type_check
  def encrypt(self, iv: bytes, aad: bytes, msg: bytes):
    ct = chacha.chacha20_encrypt(self.key, 1, iv, msg)
    return ct, self.tag(iv, aad, ct)

  @util.type_check
  def decrypt(self, iv: bytes, aad: bytes, ct: bytes, tag: bytes)-> bytes:
    t = self.tag(iv, aad, ct)
    if t != tag:
      raise Exception("tag mismatch")
    return chacha.chacha20_decrypt(self.key, 1, iv, ct)  

class Test(object):
    def __init__(self, **args):
        for k,v in args.items():
            self.__setattr__(k,v)

testVectors = [
  Test(key = "808182838485868788898a8b8c8d8e8f"
             "909192939495969798999a9b9c9d9e9f",
       nonce = '070000004041424344454647',
       pt =  b"Ladies and Gentlemen of the clas"
             b"s of '99: If I could offer you o"
             b"nly one tip for the future, suns"
             b"creen would be it.",
       aad = "50515253c0c1c2c3c4c5c6c7",

       ct =  "d31a8d34648e60db7b86afbc53ef7ec2"
             "a4aded51296e08fea9e2b5a736ee62d6"
             "3dbea45e8ca9671282fafb69da92728b"
             "1a71de0a9e060b2905d6a5b67ecd3b36"
             "92ddbd7f2d778b8c9803aee328091b58"
             "fab324e4fad675945585808b4831d7bc"
             "3ff4def08e4b7a9de576d26586cec64b"
             "6116",
       tag = "1ae10b594f09e26a7e902ecbd0600691")
]


def test():
  errors = 0
  for t in testVectors:
    key = bytes.fromhex(t.key)
    nonce = bytes.fromhex(t.nonce)
    pt = t.pt
    aad = bytes.fromhex(t.aad)
    aead = Chacha20Poly1305(key)
    c,tag = aead.encrypt(nonce, aad, pt)
    if c.hex() != t.ct or tag.hex() != t.tag:
      print('========================')
      print('pt', pt)
      print('expected ct', t.ct)
      print('computed ct', c.hex())
      print('expected tag', t.tag)
      print('computed tag', tag.hex())
      errors += 1
    m = aead.decrypt(nonce, aad, c, tag)
    if m != pt:
      print('====== Incorrect decryption')
      print('pt', pt)
      print('decrypted', m.hex())
      print('ct', c.hex())
      print('tag', t.hex())
      errors += 1
  assert errors == 0

if __name__ == "__main__":
    import doctest
    doctest.testmod()
    test()

