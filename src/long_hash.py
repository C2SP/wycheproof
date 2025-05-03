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

import hashlib

# TODO: Generate some JSON file with test vectors.
#   So far we don't have a suitable representation for large test inputs.
#   The test vector generated below might be too simple for good test
#   coverage (i.e. the test vectors are repetitions of the same input).
def long_hash(hash_name, message, reps, hexoutput=False):
  '''Computes util.hash(hash_name, message * reps)'''
  if hash_name == "MD5":
    md = hashlib.md5()
  elif hash_name == "SHA-1":
    md = hashlib.sha1()
  elif hash_name == "SHA-224":
    md = hashlib.sha224()
  elif hash_name == "SHA-256":
    md = hashlib.sha256()
  elif hash_name == "SHA-384":
    md = hashlib.sha384()
  elif hash_name == "SHA-512":
    md = hashlib.sha512()
  # Requires python 3.6
  elif hash_name == "SHA3-224":
    md = hashlib.sha3_224()
  elif hash_name == "SHA3-256":
    md = hashlib.sha3_256()
  elif hash_name == "SHA3-384":
    md = hashlib.sha3_384()
  elif hash_name == "SHA3-512":
    md = hashlib.sha3_512()
  else:
    print("Old style hash name:" + hash_name)
    hash_name = hash_name.lower()
    md = getattr(hashlib, hash_name)()
  
  msg = message.encode("ascii")
  assert len(msg) > 0
  maxchunk = 2**20
  k = maxchunk // len(msg)
  chunk = msg * k
  for i in range(reps // k):
    md.update(chunk)
  md.update(msg * (reps % k))
  if hexoutput:
    return md.hexdigest()
  else:
    return md.digest()

HASHES = ["MD5", "SHA-1", "SHA-256", "SHA-224", "SHA-384", "SHA-512",
          "SHA3-224", "SHA3-256", "SHA3-384", "SHA3-512"]
def gen_samples(hashes=None):
  if hashes is None:
    hashes = HASHES
  for hash_name in hashes:
    for s in ('2**31 - 1', '2**31', '2**32 - 16', '2**32', '2**32 + 1024', '5000000000', '2**33'):
      h = long_hash(hash_name, 'a', eval(s), hexoutput=True)
      print ('  ("%s", "a", %s, "%s"),' % (hash_name, s, h))

test = [
  ("MD5", "a", 2**31-1, "bb2ef53aae423cb9fbf8788f187601e6"),
  ("MD5", "a", 2**31, "d81114fa7eec56193a13ca3cb2526991"),
  ("MD5", "a", 2**32- 16, "484d402af1724e8a8cc80ba8b6c67426"),
  ("MD5", "a", 2**32, "a21d185a70654eaad0d1af114e0b3adf"),
  ("MD5", "a", 2**32 + 1024, "d1e54d4a8fb42c9627a9fc30191779bc"),
  ("MD5", "a", 5000000000, "cf3147924864955e385804daee42d3ef"),
  ("MD5", "a", 2**33, "52242a5a8446b1e7434f1cded4ba0dee"),
  ("SHA-1", "a", 2**31-1, "1e5b490b10255e37fd96d0964f2fbfb91ed47536"),
  ("SHA-1", "a", 2**31, "f85a26c99ae77fcbbcfc9e8d4c482fd8ffe72c09"),
  ("SHA-1", "a", 2**32- 16, "4d78f56946b05365716f84cc89451e48af01f0b1"),
  ("SHA-1", "a", 2**32, "eed1574ca48feb2ef51e598bce8ebdf05ea45084"),
  ("SHA-1", "a", 2**32 + 1024, "3886cf0998354f4bc225165d160fbdf19dd2b0c0"),
  ("SHA-1", "a", 5000000000, "109b426b74c3dc1bd0e15d3524c5b837557647f2"),
  ("SHA-1", "a", 2**33, "971a7246e08be6e4d11ccdf362e19b19ca358792"),
  ("SHA-256", "a", 2**31-1, "6cc47f3907eea90fb8de9493cf025923fff2b88fcac896cbf38036d5913b6bed"),
  ("SHA-256", "a", 2**31, "95df3ea61db557b22c1abf609645c3423bf83774c22c75e3c637f8cb7fc33fd8"),
  ("SHA-256", "a", 2**32- 16, "cd91458b0129822c4b394ac9408e2ad00067d6fd79088a36b4ccb87bbd6e543a"),
  ("SHA-256", "a", 2**32, "70894e7706a54c8a00f46e0ee4fe61b7254b2c5963ccd892aa09b45ed02f8e6a"),
  ("SHA-256", "a", 2**32 + 1024, "af848f15171280fde11f3b4fbe0fb4dce3f15fafa6617d1e3cc6c7aa4ec7c263"),
  ("SHA-256", "a", 5000000000, "59fefaeb480c09b569fb8e5f277e0165e3f33bd322a2d2148cf6dd49af40779c"),
  ("SHA-256", "a", 2**33, "fd52390e23dfd41bfd1ceb1bf3ad789c178fe6426c0e40a0f7c8b4447db933ea"),
  ("SHA-224", "a", 2**31-1, "bf5dbff84919d0bd40316439d102c6f856553b7a89ef9212fd200d9e"),
  ("SHA-224", "a", 2**31, "547cf2bd9ab4109268e5e5fe8c5729525246100dc355fda33ecb48b4"),
  ("SHA-224", "a", 2**32- 16, "37797bb4fc3eaffb254c11f717d183c4bb2a8378d6fd6f5d78882aff"),
  ("SHA-224", "a", 2**32, "0cbaa64e713d9f7432d93d818b527c80ef4416fef56a7827db61c2b3"),
  ("SHA-224", "a", 2**32 + 1024, "77cead8a190bdaf4c5f993d0a1e93cacffebc81414c7c18b2b45e05a"),
  ("SHA-224", "a", 5000000000, "01acee23c428420235b7cd6a4e8c7ee453242f094f1d4477de6ad61a"),
  ("SHA-224", "a", 2**33, "97a8753024f1c1f379a3d4472be6bc45e2bfd5e0e83f28c2a9c15b53"),
  ("SHA-384", "a", 2**31-1, "08879ffbedb441c65ecf1c66286036c853632cf73262d5d3d6ecc621ee148e89f8acf29c0849f72e2a98756d4d4b895f"),
  ("SHA-384", "a", 2**31, "eb15ca8c5ae47ca8b0c6d516ecb1a236f208644d192cf38d2d24391cd7da6b0a00cfa6a63381d3c4425a568e8a6ec026"),
  ("SHA-384", "a", 2**32- 16, "8dae2a8d757a5cfa1034e333b5b35bece3bb220a1490525faed4062f5609574beb8b8b1418075edf9a0dff7bf9b59ecf"),
  ("SHA-384", "a", 2**32, "d70b9b21ab47bbfda2ddb907741f3ece6332313e5e228c0511878640513e879da12187878f56db108a383c78046eb234"),
  ("SHA-384", "a", 2**32 + 1024, "895f04352e23ce039d1748c8ee598a6b56566f387bceed2a3f494739ea55702c7bd50cd35f59992b290c6b81edc56fc6"),
  ("SHA-384", "a", 5000000000, "7f1541299d24f30155b4a849c4e8abd67cbf273a996d7a8c384476e87c143abd35eef2e1dd576960b9e5a0cd10607c43"),
  ("SHA-384", "a", 2**33, "0d799fb1bd5bb76c36984092c0512ed3731d617fb09b9db7c2ea0d51047eb56706e53b16ce5af8592515e3a9929c60ca"),
  ("SHA-512", "a", 2**31-1, "7c69df3c6a06437c6d6ea91cb10812edcdaaeabda16c6436bf3279d82c7cf40e2a94cc4b363206c1dce79904f9ce876e434cf78745a426ceef199c4d748acea9"),
  ("SHA-512", "a", 2**31, "bf2af33be6eb64d0f101e152d591d49153ee4cd9db108cab0463095ddee40ba861a86f93b73e58f6c6c0dff573923104c6011c4be09e7ccb28bc582cd309ee95"),
  ("SHA-512", "a", 2**32- 16, "65bce9775420f7d025bb29510d89adcc4b8f0cfbd73119840c20c3dbf1ea1884d8af2c0569b792b451cdc252c9f63ce451cb4ef64c73cb64d79a03cfc37733df"),
  ("SHA-512", "a", 2**32, "5cd650e79eb16c7729156feaaaf1a10e5095735fe88c1e2aa50bb5ca9632d5f8605e1e9431920eafac5b4682942dd36350facb56ccfcacb31b39e0e5bd48bd7c"),
  ("SHA-512", "a", 2**32 + 1024, "0784fd1ed973a0ab3f199d29682388464c1c0f9c498e745e55f27f21e52a3f4dd5477820b3060fd0fd20cac8d8261a02da19df69a7f6e20c7aa87cfb60663660"),
  ("SHA-512", "a", 5000000000, "080c2d9527c960c2a4a9124d728d36cd2effcaac73de09221bfc8b4afc6d52e04006f962f4fb31640642aece873f7906180cc3ebf794cd319d27d30889428011"),
  ("SHA-512", "a", 2**33, "07fea6d78bf331f66d3370691ba71ec5b2238bc040a1942b8fedfa88280ca012366dd19e200725ddaa400811d36aa42178d138631ca2dad46137d462e341e8f4"),
  ("SHA3-224", "a", 2**31-1, "24abc6b4055cea68422fa8d73031f45f73f2afda09be9c0dae2ab88e"),
  ("SHA3-224", "a", 2**31, "b26f8b390c7bd131ebf7ca10a4ca19b54634776c9e3ca15571a7a9b3"),
  ("SHA3-224", "a", 2**32- 16, "4578749f976a1299679a015d66522d86c379a1071305b8bebcf64d84"),
  ("SHA3-224", "a", 2**32, "3a662c7103e4b18e0dfe0bb69f845fa68d6c36f53620ddcfae950995"),
  ("SHA3-224", "a", 2**32 + 1024, "29ecd6dcadac15fc5d6e3bf3c4c251d2e09306c7591b95a50fe2e61c"),
  ("SHA3-224", "a", 5000000000, "96ce1138a9f42ba22929594a636404c13a99fe3c31a05fe3a00a8fda"),
  ("SHA3-224", "a", 2**33, "710b6a325e0362df0800a0599feb23fbdb0109d9922d1184f23da36c"),
  ("SHA3-256", "a", 2**31-1, "8bcd31a0d849cca71991062525ffe8b5dd07b41f686880e6c30bfe4382bb2beb"),
  ("SHA3-256", "a", 2**31, "26bd38486452d81aeac0f3f9484de088b572ba4cfffbcb83e992a3e6a154028e"),
  ("SHA3-256", "a", 2**32- 16, "d8e1667c70986a9475c35d2d2c5a669f9a51572b9fce10dc70a2cd6b10d23650"),
  ("SHA3-256", "a", 2**32, "be86a518eebe157b2da0d300be9a867880e1d1fe7493e416ee1d301b4284253b"),
  ("SHA3-256", "a", 2**32 + 1024, "2cd57d5179b7639ab60087ceddc7fea24d3ede3ac17ec7a9a9e0d66a513f71b8"),
  ("SHA3-256", "a", 5000000000, "ecb2ba5fe2a2632ea91c59ec40b113d843409f3c91cb7ec4cced351cec1202fb"),
  ("SHA3-256", "a", 2**33, "eab8fe46d76eb0621ca50a8919a49e4d93e90cdfb63c4ad4418b705d0e182dc8"),
  ("SHA3-384", "a", 2**31-1, "23a834892c1bd880e6aa2070b18a73dc8abb744e08446c3cfafb4b07c23a240106828a950d6ececf9a2901c9afff2260"),
  ("SHA3-384", "a", 2**31, "e27e6d8d7eba689126a344241d70ec2a82898b46869a34ef062c104d6880a51f7789736fc10434aa85c5129c04ab4ec1"),
  ("SHA3-384", "a", 2**32- 16, "35e79a51674433b672bc22525881b47f3b0684dd644a85feb3a72d18a541dd66ea58340f04b795d5edd3ccc68be95f2e"),
  ("SHA3-384", "a", 2**32, "6952bfeb0f4acf6263ad203183d1e9ef87a6d737ef0a38b52766f5f60911ef61be68220801018b73506f18cabff833bb"),
  ("SHA3-384", "a", 2**32 + 1024, "f5bf242b040cbc2e28603c2d673ad3ebee71c4c0600bbee10511b80b519db3cba94bf3eeffd9f34ed9bc440906ae6219"),
  ("SHA3-384", "a", 5000000000, "70872456924c5791993f18b15cc7170be5b06e609b6925e56972a7451b2e7e2e85c8317579057d90637da979f82e71f3"),
  ("SHA3-384", "a", 2**33, "3c5543c87ae1340d9f59fb267c799c8c3b9965ad3eed8e1b1c3c468388465fdfbb03bf6491db529fd82c0b434d56f43c"),
  ("SHA3-512", "a", 2**31-1, "40bd9ee7e496c2e4d086553242175b935cadb2cfc030405f67b11a1fd3dc492624933e6fe0d8b163a16bd3585401017847673189cffd8250d02af47e4a587745"),
  ("SHA3-512", "a", 2**31, "07b4f3f885938f1624d35187d35ea02aa53c87c3d0fa3841174a159e082c37afa44007fa3fdeda8f161b9f0419af8a5306485c935e4c892646db619fe7b9924d"),
  ("SHA3-512", "a", 2**32- 16, "afaec3230e89575f65f33396272962fe7d60a3a08b990eb31f1ad46094a727ca0c6967c2ea2ea4ec2b5909df53edcb9076177d4bd782a390d0d4d96b74bf6341"),
  ("SHA3-512", "a", 2**32, "8efd604006680d6ef984636d320f0cbdb65a935429927b15d95c16ea8db7f6befe01374a4b92d1d14de643ab81fa5ba5bf47416127b34a6e37fca6be43a528fd"),
  ("SHA3-512", "a", 2**32 + 1024, "949fc05b9f62a65069de0511c7091baef860a1f484397942d2a7780af4b4f5c9cd17e4193e185bfc37fe5e3189528434cd45e5cc729bfe2cf0c4e2c59eb2b1b4"),
  ("SHA3-512", "a", 5000000000, "348216749aefd183244737248de016fdc113877aad833e0ad4ae5631c5af1362e6cc5a81a5ff634f31be8f71ae8a271369abd86e6baaddfa7b9a016a6084afc2"),
  ("SHA3-512", "a", 2**33, "ed30f6cb2b14878e820efe22464c9f48baec8922a313b28e89b22976dab5dfc9642593b12601643b5dce2225134dbb7f2d69a12e0e4cbca444f1967bee030b0f"),
]


