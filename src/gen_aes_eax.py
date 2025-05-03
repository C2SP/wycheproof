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

import aead_test_vector
import aes_eax
import producer
import test_vector
import util
import flag

# known test vectors
FLAG_CTR_WRAP = flag.Flag(
    label="CounterWrap",
    bug_type=flag.BugType.EDGE_CASE,
    description="AES-EAX reduces the counter value modulo 2^128. "
    "This test vector was constructed for testing "
    "the wrapping of the counter value. ")

FLAG_EPRINT = flag.Flag(
    label="Ktv",
    bug_type=flag.BugType.BASIC,
    description="Known test vector from eprint.iacr.org/2003/069")

TEST_VECTORS = [
    [
        "eprint.iacr.org/2003/069",
        "",
        "233952dee4d5ed5f9b9c6d6ff80ff478",
        "62ec67f9c3a4a407fcb2a8c49031a8b3",
        "6bfb914fd07eae6b",
        "e037830e8389f27b025a2d6527e79d01",
        [FLAG_EPRINT],
    ],
    [
        "eprint.iacr.org/2003/069",
        "f7fb",
        "91945d3f4dcbee0bf45ef52255f095a4",
        "becaf043b0a23d843194ba972c66debd",
        "fa3bfd4806eb53fa",
        "19dd5c4c9331049d0bdab0277408f67967e5",
        [FLAG_EPRINT],
    ],
    [
        "eprint.iacr.org/2003/069",
        "1a47cb4933",
        "01f74ad64077f2e704c0f60ada3dd523",
        "70c3db4f0d26368400a10ed05d2bff5e",
        "234a3463c1264ac6",
        "d851d5bae03a59f238a23e39199dc9266626c40f80",
        [FLAG_EPRINT],
    ],
    [
        "eprint.iacr.org/2003/069",
        "481c9e39b1",
        "d07cf6cbb7f313bdde66b727afd3c5e8",
        "8408dfff3c1a2b1292dc199e46b7d617",
        "33cce2eabff5a79d",
        "632a9d131ad4c168a4225d8e1ff755939974a7bede",
        [FLAG_EPRINT],
    ],
    [
        "eprint.iacr.org/2003/069",
        "40d0c07da5e4",
        "35b6d0580005bbc12b0587124557d2c2",
        "fdb6b06676eedc5c61d74276e1f8e816",
        "aeb96eaebe2970e9",
        "071dfe16c675cb0677e536f73afe6a14b74ee49844dd",
        [FLAG_EPRINT],
    ],
    [
        "eprint.iacr.org/2003/069",
        "4de3b35c3fc039245bd1fb7d",
        "bd8e6e11475e60b268784c38c62feb22",
        "6eac5c93072d8e8513f750935e46da1b",
        "d4482d1ca78dce0f",
        "835bb4f15d743e350e728414abb8644fd6ccb86947c5e10590210a4f",
        [FLAG_EPRINT],
    ],
    [
        "eprint.iacr.org/2003/069",
        "8b0a79306c9ce7ed99dae4f87f8dd61636",
        "7c77d6e813bed5ac98baa417477a2e7d",
        "1a8c98dcd73d38393b2bf1569deefc19",
        "65d2017990d62528",
        "02083e3979da014812f59f11d52630da30137327d10649b0aa6e1c181db617d7"
        "f2",
        [FLAG_EPRINT],
    ],
    [
        "eprint.iacr.org/2003/069",
        "1bda122bce8a8dbaf1877d962b8592dd2d56",
        "5fff20cafab119ca2fc73549e20f5b0d",
        "dde59b97d722156d4d9aff2bc7559826",
        "54b9f04e6a09189a",
        "2ec47b2c4954a489afc7ba4897edcdae8cc33b60450599bd02c96382902aef7f"
        "832a",
        [FLAG_EPRINT],
    ],
    [
        "eprint.iacr.org/2003/069",
        "6cf36720872b8513f6eab1a8a44438d5ef11",
        "a4a4782bcffd3ec5e7ef6d8c34a56123",
        "b781fcf2f75fa5a8de97a9ca48e522ec",
        "899a175897561d7e",
        "0de18fd0fdd91e7af19f1d8ee8733938b1e8e7f6d2231618102fdb7fe55ff199"
        "1700",
        [FLAG_EPRINT],
    ],
    [
        "eprint.iacr.org/2003/069",
        "ca40d7446e545ffaed3bd12a740a659ffbbb3ceab7",
        "8395fcf1e95bebd697bd010bc766aac3",
        "22e7add93cfc6393c57ec0b3c17d6b44",
        "126735fcc320d25a",
        "cb8920f87a6c75cff39627b56e3ed197c552d295a7cfc46afc253b4652b1af37"
        "95b124ab6e",
        [FLAG_EPRINT],
    ],
    # Some test vectors for counter overflow:
    [
        "Initial counter value == 2^128-1",
        "0000000000000000000000000000000011111111111111111111111111111111",
        "000102030405060708090a0b0c0d0e0f",
        "3c8cc2970a008f75cc5beae2847258c2",
        "",
        "3c441f32ce07822364d7a2990e50bb13d7b02a26969e4a937e5e9073b0d9c968"
        "db90bdb3da3d00afd0fc6a83551da95e",
        [FLAG_CTR_WRAP],
    ],
    [
        "counter value overflows at 64-bit boundary",
        "0000000000000000000000000000000011111111111111111111111111111111",
        "000102030405060708090a0b0c0d0e0f",
        "aef03d00598494e9fb03cd7d8b590866",
        "",
        "d19ac59849026a91aa1b9aec29b11a202a4d739fd86c28e3ae3d588ea21d70c6"
        "c30f6cd9202074ed6e2a2a360eac8c47",
        [FLAG_CTR_WRAP],
    ],
    [
        "no counter overflow, but the 64 most significant bits are set.",
        "0000000000000000000000000000000011111111111111111111111111111111",
        "000102030405060708090a0b0c0d0e0f",
        "55d12511c696a80d0514d1ffba49cada",
        "",
        "2108558ac4b2c2d5cc66cea51d6210e046177a67631cd2dd8f09469733acb517"
        "fc355e87a267be3ae3e44c0bf3f99b2b",
        [FLAG_CTR_WRAP],
    ],
    [
        "counter value overflows at 32-bit boundary",
        "0000000000000000000000000000000011111111111111111111111111111111",
        "000102030405060708090a0b0c0d0e0f",
        "79422ddd91c4eee2deaef1f968305304",
        "",
        "4d2c1524ca4baa4eefcce6b91b227ee83abaff8105dcafa2ab191f5df2575035"
        "e2c865ce2d7abdac024c6f991a848390",
        [FLAG_CTR_WRAP],
    ],
    [
        "bits 32-64 and 96-128 of counter are set",
        "0000000000000000000000000000000011111111111111111111111111111111",
        "000102030405060708090a0b0c0d0e0f",
        "0af5aa7a7676e28306306bcd9bf2003a",
        "",
        "8eb01e62185d782eb9287a341a6862ac5257d6f9adc99ee0a24d9c22b3e9b38a"
        "39c339bc8a74c75e2c65c6119544d61e",
        [FLAG_CTR_WRAP],
    ],
    [
        "lower bits of initial counter are 2^63-1",
        "0000000000000000000000000000000011111111111111111111111111111111",
        "000102030405060708090a0b0c0d0e0f",
        "af5a03ae7edd73471bdcdfac5e194a60",
        "",
        "94c5d2aca6dbbce8c24513a25e095c0e54a942860d327a222a815cc713b163b4"
        "f50b30304e45c9d411e8df4508a98612",
        [FLAG_CTR_WRAP],
    ],
    [
        "counter overflow",
        "0000000000000000000000000000000011111111111111111111111111111111"
        "2222222222222222222222222222222233333333333333333333333333333333",
        "000102030405060708090a0b0c0d0e0f",
        "b37087680f0edd5a52228b8c7aaea664",
        "",
        "3bb6173e3772d4b62eef37f9ef0781f360b6c74be3bf6b371067bc1b090d9d66"
        "22a1fbec6ac471b3349cd4277a101d40890fbf27dfdcd0b4e3781f9806daabb6"
        "a0498745e59999ddc32d5b140241124e",
        [FLAG_CTR_WRAP],
    ],
    [
        "lower 64 bits of initial counter are 2^63-4",
        "0000000000000000000000000000000011111111111111111111111111111111"
        "2222222222222222222222222222222233333333333333333333333333333333"
        "44444444444444444444444444444444",
        "000102030405060708090a0b0c0d0e0f",
        "4f802da62a384555a19bc2b382eb25af",
        "",
        "e9b0bb8857818ce3201c3690d21daa7f264fb8ee93cc7a4674ea2fc32bf182fb"
        "2a7e8ad51507ad4f31cefc2356fe7936a7f6e19f95e88fdbf17620916d3a6f3d"
        "01fc17d358672f777fd4099246e436e167910be744b8315ae0eb6124590c5d8b",
        [FLAG_CTR_WRAP],
    ],
]

class AesEaxTestGenerator(aead_test_vector.AeadTestGenerator):
  aead = aes_eax.AesEax

  def __init__(self, args):
    super().__init__("AES-EAX", args)
    if getattr(args, "key_sizes", None):
      self.key_sizes = [x // 8 for x in args.key_sizes]
    else:
      self.key_sizes = (16, 24, 32)

  def generate_ktv(self):
    for comment, msg, key, nonce, aad, ct, flags in TEST_VECTORS:
      c = ct[:-32]
      t = ct[-32:]
      key, nonce, aad, msg, c, t = map(bytes.fromhex,
                                       (key, nonce, aad, msg, c, t))
      self.add_vector(key, nonce, aad, msg, c, t, comment=comment, flags=flags)

  def generate_prand(self):
    pseudorandom = flag.Flag(
        label="Pseudorandom",
        bug_type=flag.BugType.FUNCTIONALITY,
        description="The test vector contains pseudorandomly generated inputs. "
        "The goal of the test vector is to check the correctness of the "
        "implementation for various sizes of the input parameters.")
    key_sizes = self.key_sizes
    self.generate_pseudorandom(
        cnt=1,
        key_sizes=key_sizes,
        iv_sizes=[12],
        aad_sizes=[0],
        msg_sizes=[0, 1, 8, 16, 24, 31, 63, 64, 66],
        comment="",
        flags=[pseudorandom])
    self.generate_pseudorandom(
        1, key_sizes, [16], [0], (0, 1, 15, 22), flags=[pseudorandom])
    self.generate_pseudorandom(
        1, key_sizes, [16], [8, 15, 16, 24], [16], flags=[pseudorandom])
    self.generate_pseudorandom(
        1,
        key_sizes, [20, 32], [0], [16],
        "large IV size",
        flags=[pseudorandom])
    self.generate_pseudorandom(
        1,
        key_sizes, [16], [0], [127, 128, 129, 255, 256, 257, 511, 512, 513],
        "longer message size",
        flags=[pseudorandom])
    self.generate_pseudorandom(
        1,
        key_sizes, [16],
        [63, 64, 65, 127, 128, 129, 255, 256, 257, 511, 512, 513], [16],
        "longer aad size",
        flags=[pseudorandom])

  def generate_largeiv(self):
    cve_2017_18330 = flag.Cve("CVE-2017-18330", "Overflow with large IVs")
    self.generate_pseudorandom(
        1,
        self.key_sizes, [64, 128, 257], [0], [16],
        "very large IV size",
        flags=[cve_2017_18330])

  def generate_smalliv(self):
    smalliv = flag.Flag(
        label="SmallIv",
        bug_type=flag.BugType.WEAK_PARAMS,
        description="""AES-EAX allows arbitrary sizes for the nonce.
           This test vector uses an IV smaller than 12 bytes.""")
    self.generate_pseudorandom(
        1,
        self.key_sizes, [4, 8], [0], [16],
        "small IV size",
        flags=[smalliv],
        valid="valid")
    self.generate_pseudorandom(
        1,
        self.key_sizes, [0], [0], [0, 16],
        "IV size = 0",
        flags=[smalliv],
        valid="valid")

  def generate_modified(self):
    for keysize in self.key_sizes:
      key = bytes(range(keysize))
      nonce = bytes(range(80, 96))
      aad = bytes()
      message = bytes(range(32, 48))
      self.generate_modified_tag(key, nonce, aad, message)

  def generate_all(self):
    self.generate_ktv()
    self.generate_prand()
    self.generate_smalliv()
    self.generate_largeiv()
    self.generate_modified()


def test():
  errors = 0
  for comment, msg, key, nonce, aad, ct, flags in TEST_VECTORS:
    m = bytes.fromhex(msg)
    k = bytes.fromhex(key)
    n = bytes.fromhex(nonce)
    a = bytes.fromhex(aad)
    A = aes_eax.AesEax(k)
    c, t  = A.encrypt(n, a, m)
    d = A.decrypt(n, a, c, t)
    assert d != False
    assert d == m

    ct2 = (c + t).hex()
    if ct != ct2:
      print("unexpected ciphertext for")
      print(msg, key, nonce, aad)
      print(ct)
      print(ct2)
      errors += 1
  print("%d errors" % errors)
  assert not errors


class AesEaxProducer(producer.Producer):

  def parser(self):
    res = self.default_parser()
    res.add_argument(
        "--key_sizes",
        type=int,
        choices=[128, 192, 256],
        nargs="+",
        help="a list of key sizes in bits")
    return res

  def generate_test_vectors(self, namespace):
    tv = AesEaxTestGenerator(namespace)
    tv.generate_all()
    return tv.test


# DEPRECATED: Use AesEaxProducer.produce() instead
def main(namespace):
  AesEaxProducer().produce(namespace)


if __name__ == "__main__":
  AesEaxProducer().produce_with_args()
