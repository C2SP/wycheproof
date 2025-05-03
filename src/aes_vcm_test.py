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

import aes_vcm

test_vectors = [
{
  "key": "1b328053ccb0fd115fd0f6dc7b92d8fe",
  "counter": "ebb0e9e7f32e212af142f5fc",
  "aad": "",
  "pt": "",
  "ct": "",
  "tag": "a6b6032cad4e744e2349a473cbe5cfca",
},
{
  "key": "bd27c26ef204d201e366452b3e1ebabb",
  "counter": "ae4d3d565c1ee44221ea9803",
  "aad": "",
  "pt": "bca10b7f1e4802ee8326c9b4af696a",
  "ct": "8eb88d82f4b573cb0826641749fd76",
  "tag": "8ffd030383ce91896813888dd0b4ff7f",
},
]
more_vectors = [
{
  "key": "e8db8aac20e5183709c6bfb6795c2cf1",
  "counter": "29b3f004b68ac1510381e918",
  "aad": "",
  "pt": "7ff8b91a755358463650df8cf7fc6fad",
  "ct": "540d2214aaf841ccc2ef0cf4d1c31829",
  "tag": "2618b57bdb5c0442b7ea7aba5af1cd68",
},
{
  "key": "74121dd5e367856fcc046162d136935f",
  "counter": "accbc0b7a1e7deb814d112e8",
  "aad": "",
  "pt": "3bea77cfce6e351be890abfafaa6fbfaf7",
  "ct": "13da8e9f937c7d4b4f16cd36d1eaeeaac6",
  "tag": "32fe7e9adf6b39fde4484c1da193bc90",
},
{
  "key": "6158469db6acd24123c2b1ba4b87063d",
  "counter": "ef57d394149c7f3f0bcdf2f9",
  "aad": "",
  "pt": "e171dc803436efbcd872ed93b2ee1ff561fe0824690db4f2839c4a980f1999",
  "ct": "0fe9e79f777e0a94a4bc66dc356d4cbd270ef04d651fb9a8ec5b38cc26c7dc",
  "tag": "3fc8fcb79f107f9bf0b42818455efece",
},
{
  "key": "7e6ba32e910ecabeb80ee18afc952255",
  "counter": "6add636543692e93307c384c",
  "aad": "",
  "pt": "0617ca4f8497131edb57b123d13f6666ed91b93b063040956cf4bcbb2df723f4",
  "ct": "11dbb28c0e23ca5b4e7874b10b5ebd98961badb40f8b36511f823067237190d0",
  "tag": "7b341d3f3a151a49b0a40c891cf75ac0",
},
{
  "key": "3a1ee0af399a5e798884d1dc3accedb5",
  "counter": "81b0125c51b151db7663323b",
  "aad": "",
  "pt": "eedc6414cb2c2c8f0d1cd3ef1aeb02a7deccd0373bf80845bb6e3c9fdb4a8f54a1",
  "ct": "2e9400ae849b69f8a786427da73b851330fe9fa15989d06668ef42882cdcc0c56d",
  "tag": "bfc54b595a0a4758dcf42e688ca7297c",
},
{
  "key": "dbcaded4024fa8207f822743238c6417",
  "counter": "3432c691de0a1856d8b4159b",
  "aad": "",
  "pt": "dc2c273acd4891481dcba25a3aa447f7c5e95c171e8e5be085d56e59d7165973dbb8e9779d7b48f08d6af01e6ab6cda6417889af6c3b89dc53152daeef777b6f8898c5166c39d028ee2b968110d2f98c20bf3e94ae82175ddd0f5b13451e3f",
  "ct": "0899908b9539808c17ce8f65b37369b7ae2e61e81e286b36577ede94c2bb635bfe57ffd6e8bf695d45680b9263ba722159a51887ddee00ff049b31b375d28d3c23778e03be23665219030a55b72921048649bd7b7086f5a658f006d29da1f8",
  "tag": "e0f9c759b6bdeff24869e93da1a46974",
},
{
  "key": "d1089cf2b68ceb09ee8ba692569b11d2",
  "counter": "913e3ed5794bbad8ced32703",
  "aad": "",
  "pt": "4da4acb451648505e2a11176ebd4f1a3fab2e7ae8395344e6114eb254514cdc9c267268510a70ed5f4c64821f497e4c12d6882dda9ef0916cd7309a4c081c5d936d00f88260b76a49cdc98894f9d3edfe1743c61952d6a6ffd9129cb05beddba",
  "ct": "d778d803297a78f1325e76fbdc1185972974c86552b319d4737ae63481aa9654aac9726fe6c30ee0135370fc69dae3831eeff3149c050ca045e45cf7a77b9880448f25ec923009dcc7359e6d66fe131295a314d98e98a1ec9db2af7bec06c25d",
  "tag": "79d07232f860393a5d30d8919026102f",
},
{
  "key": "9c31dc29382846998c6138d00b91f216",
  "counter": "762390c170c629f97f3cabe0",
  "aad": "",
  "pt": "7e8ca8d8ae7ca69888fc9eab73f901fe8593fa40a337dcbbde62d4323e054c5e430ec8b8b5a0670f3cc329a99890206ea15ca200e7a44f493cf62d0d3a1440d64339e2f4f113fc5200771364fdcf88698b647709fd1c1e5fdcec35c71f63a8261d",
  "ct": "e553fd64f0b97d2b72ddc756227728f358caa3129eba44c54ffc1357a8252d704c766e7d0ed4cf3d54aa8bb84ffeca315c8b92377eda0e00ceaf9d9228c7d3a5f620fb66322ac99a1019ee6d96e97355ebdd893e047e6668e1fe0bec65299817cb",
  "tag": "d6e0fde3c36ba00c24061da0edfd8ac0",
},
{
  "key": "01ce2c5c114a605e56bbfb45b0bd3565",
  "counter": "fb02b9cde66d555b20a716ac",
  "aad": "",
  "pt": "7280c054ecebc9d10606fbccda4bc139be11deb00a9631d1ad68b22c899132f97db4188852bd4e3a52a68ee46de40f85479153fb4a3d75449ab3045cbdd0b68219e6f77b4c3e816a79f4546c1eb6e20faed233e0f6fce47f7f7ad081682bce71321cd796c3ca33d76babd844febba3",
  "ct": "bc96254b2fcbc672256453e607d05687447e04ae9d552fba8e6d522910320317dbe3319f1b9ff0bb7bc9edfb2b21244cd289766fe1dc9325e703b8db1470e5b5c367b48fe6218c1cc8b66b8bb4564793c69cf456e358acc00339bb0bdeb16b4977bc12aafb1e810ed28ae6c03ccd71",
  "tag": "a78d07201908ff777efe68ad1bdfd25c",
},
{
  "key": "e3e5fcd5df5fc231fdd8d89332519c0f",
  "counter": "a53608b777a231534a734ce7",
  "aad": "",
  "pt": "6280f99e96fbdb7012620a583454f59fc9f2e4762965f64b1201e08fd03e68195ba727ab968c77c053b34d956b22234c5e9abf7a89d4c588ac4aa2f6cb7f80cf95fb62d93ec96b4c1cf54cc50a2d71215486decf691534fac3d45a4e7d7806d18f493410662994d02009794c87afd21a",
  "ct": "bcc66458cdf9547658199bfb170304749cb87077431cabce6b0f8acf3a14ff4740315a1c6af53aa04fae843dfb8233289dd00a7be277fa7ff6f33ee9cf16e866cd2ef19c1e54710c4034237af59a09307d6309a30cbcead313879949766d8b4457d9a98f655e008a68bc55bcdcf7d2fb",
  "tag": "6d636eb645ca082919700c9b9e90d759",
},
{
  "key": "7cbe6383b49a49e16a2b72811bde4f22",
  "counter": "be1d00bdb085c8bcb3c6b9ac",
  "aad": "",
  "pt": "f2b08a12a9fd5b303bb01b3ee4d657d0b97c847a910789875fb4e9e95c9388cfb8b4a8a1a271da6f0e52402bc2c31261f2909ad2cf16981e0d2146e49585f77928887dec8e40319659532c4a2149214f4e1a1a0ea01d24a305579ec57ef76ca8bff6ba0095f1456d3c34bac4b053418fbc",
  "ct": "67560e39ee6e9ec38dec77707a94300cb568ec0ed944fce57250cec5d1c96df21c167ee479230ac5167e015d01de36ab3edb468006fbef1fb8d0817454094ffb2a1bf8fc74030587eb5e7b70ede309c5692d245229f2bd7b14ff889a3b2e63cda9750431be07ae45d64bcfd4e1322796f8",
  "tag": "a3d7b94adee2613a11e822e268ad3ebd",
}
]

#   def get_tag(self, A:bytes, C:bytes, nonce:bytes) -> bytes:
#    L = int2bytes(len(A)*8, 8) + int2bytes(len(C)*8, 8)
#    padA = bytes(-len(A) % 16)
#    padC = bytes(-len(C) % 16)
#    S = A + padA + C + padC + L
#    tag = self.mac.mac(S, nonce)
#    return tag


def test1():
  """check test vectors"""
  print("test1")
  errors = 0
  for t in test_vectors:
    key = bytes.fromhex(t["key"])
    aad = bytes.fromhex(t["aad"])
    nonce = bytes.fromhex(t["counter"])
    pt = bytes.fromhex(t["pt"])
    ct = bytes.fromhex(t["ct"])
    tag = bytes.fromhex(t["tag"])
    A = aes_vcm.AesVcm(key, tagsize = len(tag))
    c2,t2 = A.encrypt(nonce, aad, pt)
    if c2 != ct or tag != t2:
      print(t)
      print("c2", c2.hex())
      print("ct", ct.hex())
      print("t2", t2.hex())
      print("tg", tag.hex())
      print("diff", aes_vcm.xor(pt, ct).hex())
      errors += 1
      if c2 != ct:
        for w in [bytes([0,0,0,0]),
                  bytes([0,0,0,1]),
                  bytes([1,0,0,0])]:
          for n in [w + nonce,
                    nonce + w,
                    w + nonce[::-1],
                    nonce[::-1] + w]:
            print(n.hex(), A.encrypt_block(n).hex())
      s = set()
      for n in [nonce,
                bytes([1,0,0,0]) + nonce]:
        for padlen in [1, 8, 16, 32]:
          padA = bytes(len(aad) % padlen)
          padC = bytes(len(ct) % padlen)
          for la, lc in [
            (aes_vcm.int2bytes(len(aad)*8 , 8), aes_vcm.int2bytes(len(ct)*8, 8)),
          ]:
             for L in [la + lc,
                       la[::-1], lc[::-1]]:
               S = aad + padA + ct + padC + L
               for pl in [1, 128]:
                 S = S + bytes(-len(S)%pl)
                 tag = A.mac.mac(S, n)
                 if tag in s:
                   continue
                 s.add(tag)
                 print(tag.hex(), n.hex(), S.hex())

      
    try:
      p = A.decrypt(nonce, aad, ct, tag)
      if p != pt:
        errors += 1
    except Exception:
      errors += 1
  assert errors == 0


if __name__ == "__main__":
  test1()


