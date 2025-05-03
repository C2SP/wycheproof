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

import eddsa
from typing import Optional

def strip(s: Optional[str] = None):
  if s is None:
    return s
  return s.replace('\n', '').replace(' ','')

class Test:
  def __init__(self,
               tc: str,
               sk: str,
               pk: Optional[str] = None,
               msg: Optional[str] = None,
               sig: Optional[str] = None,
               ctx: str = '',
               alg: str = 'ed25519',
               validity: str = 'valid'):
    self.tc = tc
    self.sk_hex = strip(sk)
    self.pk_hex = strip(pk)
    self.msg_hex = strip(msg)
    self.sig_hex = strip(sig)
    self.ctx = ctx
    self.alg = alg
    self.validity = validity

  def runTest(self):
    if self.alg == 'ed25519':
      group = eddsa.ed25519_group
    elif self.alg == 'ed448':
      group = eddsa.ed448_group
    else:
      print("Can't run test for:" + self.alg)
      return
    if self.ctx:
      print("Can't run tests with context")
      return

    sk = eddsa.EddsaPrivateKey(bytes.fromhex(self.sk_hex), group=group)
    pk = sk.publickey()
    if self.pk_hex is not None:
      pk_hex = pk.raw().hex()
      if pk_hex != self.pk_hex:
        print('pk:      ', pk_hex)
        print('expected:', self.pk_hex)
        raise Exception("Public key is wrong")
    msg = bytes.fromhex(self.msg_hex)
    sig = sk.sign(msg)
    assert isinstance(sig, bytes)
    if self.validity == "valid" and self.sig_hex is not None:
      if sig.hex() != self.sig_hex:
        print('sig:     ', sig.hex())
        print('expected:', self.sig_hex)
        raise Exception("wrong signature")\

    if self.sig_hex is not None:
      try:
        pk.verify(msg, bytes.fromhex(self.sig_hex))
        verified = True
      except Exception:
        verified = False
      if self.validity == "valid":
        assert verified
      elif self.validity == "invalid":
        assert not verified



Tests = [
  # Test cases from https://tools.ietf.org/html/draft-josefsson-eddsa-ed25519-02
  Test(
    tc = "draft-josefsson-eddsa-ed25519-02: Test 1",
    sk = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
    pk = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
    msg = "",
    sig = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
          "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"),
  Test(
    tc = "draft-josefsson-eddsa-ed25519-02: Test 2",
    sk = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
    pk = "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
    msg = "72",
    sig = "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
          "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"),
  Test(
    tc = "draft-josefsson-eddsa-ed25519-02: Test 3",
    sk = "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
    pk = "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
    msg = "af82",
    sig = "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac"
          "18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"),
  Test(
    tc = "draft-josefsson-eddsa-ed25519-02: Test 1024",
    sk = "f5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255f5cc0ee5",
    pk = "278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426e",
    msg = "08b8b2b733424243760fe426a4b54908"
          "632110a66c2f6591eabd3345e3e4eb98"
          "fa6e264bf09efe12ee50f8f54e9f77b1"
          "e355f6c50544e23fb1433ddf73be84d8"
          "79de7c0046dc4996d9e773f4bc9efe57"
          "38829adb26c81b37c93a1b270b20329d"
          "658675fc6ea534e0810a4432826bf58c"
          "941efb65d57a338bbd2e26640f89ffbc"
          "1a858efcb8550ee3a5e1998bd177e93a"
          "7363c344fe6b199ee5d02e82d522c4fe"
          "ba15452f80288a821a579116ec6dad2b"
          "3b310da903401aa62100ab5d1a36553e"
          "06203b33890cc9b832f79ef80560ccb9"
          "a39ce767967ed628c6ad573cb116dbef"
          "efd75499da96bd68a8a97b928a8bbc10"
          "3b6621fcde2beca1231d206be6cd9ec7"
          "aff6f6c94fcd7204ed3455c68c83f4a4"
          "1da4af2b74ef5c53f1d8ac70bdcb7ed1"
          "85ce81bd84359d44254d95629e9855a9"
          "4a7c1958d1f8ada5d0532ed8a5aa3fb2"
          "d17ba70eb6248e594e1a2297acbbb39d"
          "502f1a8c6eb6f1ce22b3de1a1f40cc24"
          "554119a831a9aad6079cad88425de6bd"
          "e1a9187ebb6092cf67bf2b13fd65f270"
          "88d78b7e883c8759d2c4f5c65adb7553"
          "878ad575f9fad878e80a0c9ba63bcbcc"
          "2732e69485bbc9c90bfbd62481d9089b"
          "eccf80cfe2df16a2cf65bd92dd597b07"
          "07e0917af48bbb75fed413d238f5555a"
          "7a569d80c3414a8d0859dc65a46128ba"
          "b27af87a71314f318c782b23ebfe808b"
          "82b0ce26401d2e22f04d83d1255dc51a"
          "ddd3b75a2b1ae0784504df543af8969b"
          "e3ea7082ff7fc9888c144da2af58429e"
          "c96031dbcad3dad9af0dcbaaaf268cb8"
          "fcffead94f3c7ca495e056a9b47acdb7"
          "51fb73e666c6c655ade8297297d07ad1"
          "ba5e43f1bca32301651339e22904cc8c"
          "42f58c30c04aafdb038dda0847dd988d"
          "cda6f3bfd15c4b4c4525004aa06eeff8"
          "ca61783aacec57fb3d1f92b0fe2fd1a8"
          "5f6724517b65e614ad6808d6f6ee34df"
          "f7310fdc82aebfd904b01e1dc54b2927"
          "094b2db68d6f903b68401adebf5a7e08"
          "d78ff4ef5d63653a65040cf9bfd4aca7"
          "984a74d37145986780fc0b16ac451649"
          "de6188a7dbdf191f64b5fc5e2ab47b57"
          "f7f7276cd419c17a3ca8e1b939ae49e4"
          "88acba6b965610b5480109c8b17b80e1"
          "b7b750dfc7598d5d5011fd2dcc5600a3"
          "2ef5b52a1ecc820e308aa342721aac09"
          "43bf6686b64b2579376504ccc493d97e"
          "6aed3fb0f9cd71a43dd497f01f17c0e2"
          "cb3797aa2a2f256656168e6c496afc5f"
          "b93246f6b1116398a346f1a641f3b041"
          "e989f7914f90cc2c7fff357876e506b5"
          "0d334ba77c225bc307ba537152f3f161"
          "0e4eafe595f6d9d90d11faa933a15ef1"
          "369546868a7f3a45a96768d40fd9d034"
          "12c091c6315cf4fde7cb68606937380d"
          "b2eaaa707b4c4185c32eddcdd306705e"
          "4dc1ffc872eeee475a64dfac86aba41c"
          "0618983f8741c5ef68d3a101e8a3b8ca"
          "c60c905c15fc910840b94c00a0b9d0",
    sig = "0aab4c900501b3e24d7cdf4663326a3a"
          "87df5e4843b2cbdb67cbf6e460fec350"
          "aa5371b1508f9f4528ecea23c436d94b"
          "5e8fcd4f681e30a6ac00a9704a188a03"),
  # https://boringssl.googlesource.com/boringssl/+/c42baf84dfa43fc5a708aa83ad829b925ad3c2ca/crypto/curve25519/ed25519_test.cc#68
  Test(
    tc = "Signature with S just under the bound. [David Benjamin]",
    sk = "a59a4130fcfd293c9737db8f14177ce034305cf34bdc4346f24b4d262e07b5c2",
    pk = "100fdf47fb94f1536a4f7c3fda27383fa03375a8f527c537e6f1703c47f94f86",
    msg = "124e583f8b8eca58bb29c271b41d36986bbc45541f8e51f9cb0133eca447601e",
    sig = "dac119d6ca87fc59ae611c157048f4d4fc932a149dbe20ec6effd1436abf83ea"
          "05c7df0fef06147241259113909bc71bd3c53ba4464ffcad3c0968f2ffffff0f"),
  Test(
    tc = "Signature with S just above the bound. [David Benjamin]",
    sk = "a59a4130fcfd293c9737db8f14177ce034305cf34bdc4346f24b4d262e07b5c2",
    pk = "100fdf47fb94f1536a4f7c3fda27383fa03375a8f527c537e6f1703c47f94f86",
    msg = "6a0bc2b0057cedfc0fa2e3f7f7d39279b30f454a69dfd1117c758d86b19d85e0",
    sig = "0971f86d2c9c78582524a103cb9cf949522ae528f8054dc20107d999be673ff4"
          "e25ebf2f2928766b1248bec6e91697775f8446639ede46ad4df4053000000010",
    validity="invalid"),
  # Tink failures in verification: CL 166653627
  Test(
    tc = "Random test failure 1",
    msg = "b0729a713593a92e46b56eaa66b9e435f7a09a8e7de03b078f6f282285276635"
          "f301e7aaafe42187c45d6f5b13f9f16b11195cc125c05b90d24dfe4c",
    sig = "7db17557ac470c0eda4eedaabce99197ab62565653cf911f632ee8be0e5ffcfc"
          "88fb94276b42e0798fd3aa2f0318be7fc6a29fae75f70c3dcdc414a0ad866601",
    sk =  "d7ad3f1f6bbe0477c3c357a806a19eb41ae3f94025035bc87f281f8ee9fc0e34",
    pk =  "8fd659b77b558ed93882c1157438450ac86ec62d421d568e98ee236f3810295a"),
  Test(
    tc = "Random test failure 2",
    msg = "a8546e50ba31cae3234310d32672447be213fad91a227a19669c53d309b95978"
          "2b0e6b71f8791fdb470043b58122003157d2d96a43a6cbd7d3a8d86bf4c97391"
          "883e268d50af80e1e6e12939c2bd50ca746cdadfad4edf1bda87529974072414"
          "8efb1ebe73fb60088cda890317658627a5f7ab5a0c075d9d8f3f97b6492b3551"
          "9e50ff6b38377432a7081f9176bb1c29a862deac1336ca20b097a47829cec10a"
          "6a7cec178eda2d12f6dc6c87f910454af0123555ba184e68804d9cced60fd5c8"
          "c90943e56599c8f0ba59a38491ba5e5a53460682474c07e40ca142983314fd76"
          "2856bb1093f359da6eb0a756bd93a3160c10dd8feea6b97e7c6a17cb54bd5d76"
          "49c05c66d7bdee056671dfdaf689fa3945bb8e29a429f4bd5d355dce9687b06f"
          "01d5e33e3999f0e8",
    sig = "67d84d4c3945aaf06e06d524be63acbfb5dbb1988c4aea96a5ee9f7a9b9eecc2"
          "9df4f66b8aa1d9e8607a58fb1ef0c2ad69aac005b4f58e34103344a9c8871a09",
    sk =  "ad9b22793336fcdac10e136c4deea599be187a38eef91c1cf7c7a4ec884dda08",
    pk =  "2a606bf67ac770c607038b004101b325edb569efd3413d2d1f2c3e6b4e6e3082"),
  Test(
    tc = "Random test failure 3",
    msg = "cd2212eddb0706f62c995cef958634f0cb7793444cbf4d30e81c27c41ebea6cb"
          "02607510131f9c015692dfd521b148841e9a2d3564d20ac401f6cb8e40f520fe"
          "0cafbeaa88840b83013369d879f013463fe52a13267aa0c8c59c45cde9399cd1"
          "e6be8cc64cf48315ac2eb31a1c567a4fb7d601746d1f63b5ac020712adbbe075"
          "19bded6f",
    sig = "24087d47f3e20af51b9668ae0a88ce76586802d0ec75d8c0f28fc30962b5e1d1"
          "a1d509571a1624ed125a8df92a6e963728d6b5de99200b8e285f70feb6f05207",
    sk = "04a6553d68a9baef78a2175af375458eaa01cdb77350c61e282ef5f0c7116599",
    pk = "c9c946cbc5544ac74eef491f07c5881c16faf7ec31ce4aa91bb60ae7b4539051"),
  Test(
    tc = "Random test failure 4",
    msg = "ec5c7cb078",
    sig = "d920d421a5956b69bfe1ba834c025e2babb6c7a6d78c97de1d9bb1116dfdd118"
          "5147b2887e34e15578172e150774275ea2aad9e02106f7e8ca1caa669a066f0c",
    sk =  "c367c8d2ebeeecd70c1e8985b70c3808b75657f243b21ba4f322792540e92257",
    pk =  "32ad026f693d0d2afe7f4388d91c4c964426fcb9e3665c3ebd8650009b815c8e"),
  Test(
    tc = "Random test failure 5",
    msg = "4668c6a76f0e482190a7175b9f3806a5fe4314a004fa69f988373f7a",
    sig = "4f62daf7f7c162038552ad7d306e195baa37ecf6ca7604142679d7d1128e1f8a"
          "f52e4cb3545748c44ef1ff1c64e877e4f4d248259b7f6eb56e3ef72097dc8e0c",
    sk =  "c367c8d2ebeeecd70c1e8985b70c3808b75657f243b21ba4f322792540e92257",
    pk =  "32ad026f693d0d2afe7f4388d91c4c964426fcb9e3665c3ebd8650009b815c8e"),
  Test(
    tc = "Random test failure 6",
    msg = "0f325ffd87e58131ffa23c05ea4579513b287fdba87b44",
    sig = "6669acf94667c5b541afe5307bde9476b13ae7e0e6058a772101ac8eb0a94331"
          "428eb4db0a2c68a9b6c1763b8624dab259b0876cdcfaeacc17b21a18e3fc010a",
    sk =  "56c1e22d616cbb6dea869288b4b1c02bb98696583c2f6e650013a03e17049c62",
    pk =  "c29ec1894e06d27b4e40486b4fa5063d66a746c7f9c323b12203c03b72b8b78a"),
  Test(
    tc = "Random test failure 7",
    msg = "ec5c7cb078",
    sig = "30490c28f806298225df62103521dcee047153912c33ab8ab8bbdd1ffabd70fd"
          "4fdb360f05be535b067d1cf4e78c2cb432206bf280aab3bd21aaa1cb894c5b06",
    sk =  "b7d2f64276df417fed27d8e15b4e90f6fd93dace707294c338bd32bc4bbd8fdb",
    pk =  "cfda5b899e35764c5229e59295fe1222b7ddce176643697c29e46ecbba10cf10"),
  Test(
    tc = "Random test failure 8",
    msg = "5dc9bb87eb11621a93f92abe53515697d2611b2eef73",
    sig = "deecafb6f2ede73fec91a6f10e45b9c1c61c4b9bfbe6b6147e2de0b1df693897"
          "1f7896c3ab83851fb5d9e537037bff0fca0ccb4a3cc38f056f91f7d7a0557e08",
    sk = "c367c8d2ebeeecd70c1e8985b70c3808b75657f243b21ba4f322792540e92257",
    pk = "32ad026f693d0d2afe7f4388d91c4c964426fcb9e3665c3ebd8650009b815c8e"),
  Test(
    tc = "Random test failure 9",
    msg = "67484059b2490b1a0a4f8dee77979e26",
    sig = "4cd4f77ed473a6647387f3163541c67a1708a3c3bd1673247cb87f0cb68b3c56"
          "f04bfa72970c8a483efe659c87009ab4020b590b6641316b3deddb5450544e02",
    sk =  "b7d2f64276df417fed27d8e15b4e90f6fd93dace707294c338bd32bc4bbd8fdb",
    pk =  "cfda5b899e35764c5229e59295fe1222b7ddce176643697c29e46ecbba10cf10"),
  Test(
    tc = "Random test failure 10",
    msg = "7dcfe60f881e1285676f35b68a1b2dbcdd7be6f719a288ababc28d36e3a42ac3"
          "010a1ca54b32760e74",
    sig = "7f8663cf98cbd39d5ff553f00bcf3d0d520605794f8866ce75714d77cc51e66c"
          "91818b657d7b0dae430a68353506edc4a714c345f5ddb5c8b958ba3d035f7a01",
    sk = "c367c8d2ebeeecd70c1e8985b70c3808b75657f243b21ba4f322792540e92257",
    pk = "32ad026f693d0d2afe7f4388d91c4c964426fcb9e3665c3ebd8650009b815c8e"),
  Test(
    tc = "Random test failure 11",
    msg = "a020a4381dc9141f47ee508871ab7a8b5a3648727c4281ae9932376f23a8e1bc"
          "da0626b7129197d864178631ec89c4332dbb18",
    sig = "1e41a24fe732bd7cab14c2a2f5134ee8c87fcbd2e987e60957ed9239e5c32404"
          "d56977e1b4282871896cb10625a1937468e4dc266e16a9c1b8e9891177eca802",
    sk = "b7d2f64276df417fed27d8e15b4e90f6fd93dace707294c338bd32bc4bbd8fdb",
    pk = "cfda5b899e35764c5229e59295fe1222b7ddce176643697c29e46ecbba10cf10"),
  Test(
    tc = "Random test failure 12",
    msg = "58e456064dff471109def4ca27fa8310a1df32739655b624f27e6418d34b7f00"
          "7173f3faa5",
    sig = "6aab49e5c0bc309b783378ee03ffda282f0185cdf94c847701ff307a6ee8d086"
          "5411c44e0a8206f6a5f606107451940c2593af790ce1860f4c14ab25b2deae08",
    sk = "c367c8d2ebeeecd70c1e8985b70c3808b75657f243b21ba4f322792540e92257",
    pk = "32ad026f693d0d2afe7f4388d91c4c964426fcb9e3665c3ebd8650009b815c8e"),
  Test(
    tc = "Random test failure 13",
    msg = "e1cbf2d86827825613fb7a85811d",
    sig =  "01abfa4d6bbc726b196928ec84fd03f0c953a4fa2b228249562ff1442a4f63a7"
           "150b064f3712b51c2af768d2c2711a71aabf8d186833e941a0301b82f0502905",
    sk = "7d597c3b7283929d07ed8f01f31d2596823e5e46ab226c7be4234d1a9dcaef37",
    pk = "529919c9c780985a841c42ba6c180ff2d67a276ccfbe281080e47ab71a758f56"),
  Test(
    tc = "Random test failure 14",
    msg = "a25176b3afea318b2ec11ddacb10caf7179c0b3f8eabbfa2895581138d3c1e0e",
    sig = "2a833aadecd9f28235cb5896bf3781521dc71f28af2e91dbe1735a61dce3e31a"
          "c15ca24b3fc47817a59d386bbbb2ce60a6adc0a2703bb2bdea8f70f91051f706",
    sk = "b7d2f64276df417fed27d8e15b4e90f6fd93dace707294c338bd32bc4bbd8fdb",
    pk = "cfda5b899e35764c5229e59295fe1222b7ddce176643697c29e46ecbba10cf10"),
  Test(
    tc = "Random test failure 15",
    msg = "a1",
    sig = "1a74ed2cbdc7d8f3827014e8e6ecf8fd2698ac8f86833acccdd400df710fe0d6"
          "b0543c9cfa00d52bf024ab7ce0d91981944097233ec134d5c7abbd44bfd32d0d",
    sk = "c367c8d2ebeeecd70c1e8985b70c3808b75657f243b21ba4f322792540e92257",
    pk = "32ad026f693d0d2afe7f4388d91c4c964426fcb9e3665c3ebd8650009b815c8e"),
  Test(
    tc = "Random test failure 16",
    msg = "975ef941710071a9e1e6325a0c860becd7c695b5117c3107b686e330e5",
    sig = "af0fd9dda7e03e12313410d8d8844ebb6fe6b7f65141f22d7bcba5695a25414a"
          "9e54326fb44d59fb14707899a8aae70857b23d4080d7ab2c396ef3a36d45ce02",
    sk = "f401cee4bfb1732f0e9b8d8ba79469565c3115296141dbdf7e9c311a0ac1823b",
    pk = "2252b3d57c74cbf8bc460dc2e082847926bc022f09ab6ae95756362bfd1167c1"),
  Test(
    tc = "Random test failure 17",
    msg = "",
    sig = "0280427e713378f49d478df6373c6cac847b622b567daa2376c839e7ac10e22c"
          "380ab0fa8617c9dcfe76c4d9db5459b21dc1413726e46cc8f387d359e344f407",
    sk = "3d658956410377d0644676d2599542412a4f3b0e4eadfb7f3f836615f42b18bc",
    pk = "c0a773110f975de3732355bb7ec7f0c41c091c0252966070205516693b992a4a"),
  Test(
    tc = "Random test failure 18",
    msg = "a9e6d94870a67a9fe1cf13b1e6f9150cdd407bf6480ec841ea586ae3935e9787"
          "163cf419c1",
    sig = "c97e3190f83bae7729ba473ad46b420b8aad735f0808ea42c0f898ccfe6addd4"
          "fd9d9fa3355d5e67ee21ab7e1f805cd07f1fce980e307f4d7ad36cc924eef00c",
    sk = "b7d2f64276df417fed27d8e15b4e90f6fd93dace707294c338bd32bc4bbd8fdb",
    pk = "cfda5b899e35764c5229e59295fe1222b7ddce176643697c29e46ecbba10cf10"),
  Test(
    tc = "Random test failure 19",
    msg = "11cb1eafa4c42a8402c4193c4696f7b2e6d4585e4b42dcf1a8b67a80b2da80bc"
          "9d4b649fb2f35eaf1f56c426fd0b",
    sig = "14ceb2eaf4688d995d482f44852d71ad878cd7c77b41e60b0065fd01a59b054e"
          "e74759224187dbde9e59a763a70277c960892ef89fba997aba2576b2c54ba608",
    sk = "c367c8d2ebeeecd70c1e8985b70c3808b75657f243b21ba4f322792540e92257",
    pk = "32ad026f693d0d2afe7f4388d91c4c964426fcb9e3665c3ebd8650009b815c8e"),
  Test(
    tc = "Random test failure 20",
    msg = '27d465bc632743522aefa23c',
    sig = 'c2656951e2a0285585a51ff0eda7e9a23c2dfd2ffa273aee7808f4604e8f9a8c'
          '8ea49e9fce4eb2d8d75d36b7238fe6fc13b6c5d9427dd58f8c6615d033c0bd0f',
    sk = '04a6553d68a9baef78a2175af375458eaa01cdb77350c61e282ef5f0c7116599',
    pk = 'c9c946cbc5544ac74eef491f07c5881c16faf7ec31ce4aa91bb60ae7b4539051'),
  Test(
    tc = "Random test failure 21",
    msg = '5ffa',
    sig = '931e5152fcef078c22cc5d6a3a65f06e396289f6f5f2d1efa6340254a53526ef'
          '5dc6874eeddf35c3f50991c53cd02bf06313e37d93ee1f7022128ffa3b8f300b',
    sk = '56c1e22d616cbb6dea869288b4b1c02bb98696583c2f6e650013a03e17049c62',
    pk = 'c29ec1894e06d27b4e40486b4fa5063d66a746c7f9c323b12203c03b72b8b78a'),
  Test(
    tc = "Random test failure 22",
    msg = '25',
    sig = 'e4ae21f7a8f4b3b325c161a8c6e53e2edd7005b9c2f8a2e3b0ac4ba94aa80be6'
          'f2ee22ac8d4a96b9a3eb73a825e7bb5aff4a3393bf5b4a38119e9c9b1b041106',
    sk = '7d597c3b7283929d07ed8f01f31d2596823e5e46ab226c7be4234d1a9dcaef37',
    pk = '529919c9c780985a841c42ba6c180ff2d67a276ccfbe281080e47ab71a758f56'),
  Test(
    tc = "Random test failure 23",
    msg = '80fdd6218f29c8c8f6bd820945f9b0854e3a8824',
    sig = 'e097e0bd0370bff5bde359175a11b728ee9639095d5df8eda496395565616edf'
          'e079977f7d4dc8c75d6113a83d6a55e6e1676408c0967a2906339b43337dcb01',
    sk =  'f401cee4bfb1732f0e9b8d8ba79469565c3115296141dbdf7e9c311a0ac1823b',
    pk =  '2252b3d57c74cbf8bc460dc2e082847926bc022f09ab6ae95756362bfd1167c1'),
  Test(
    tc = "Random test failure 24",
    msg = 'b477b0480bb84642608b908d29a51cf2fce63f24ee95',
    sig = '28fafbb62b4d688fa79e1ac92851f46e319b161f801d4dc09acc21fdd6780a2c'
          '4292b8c1003c61c2bcebe7f3f88ccc4bb26d407387c5f27cb8c94cf6ce810405',
    sk =  'ad9b22793336fcdac10e136c4deea599be187a38eef91c1cf7c7a4ec884dda08',
    pk =  '2a606bf67ac770c607038b004101b325edb569efd3413d2d1f2c3e6b4e6e3082'),
  Test(
    tc = "Random test failure 25",
    msg = 'aa365b442d12b7f3c925',
    sig = '83c40ce13d483cc58ff65844875862d93df4bd367af77efa469ec06a8ed9e6d7'
          '905a04879535708ddf225567a815c9b941d405c98e918fd0c151165cea7fb101',
    sk =  'c367c8d2ebeeecd70c1e8985b70c3808b75657f243b21ba4f322792540e92257',
    pk =  '32ad026f693d0d2afe7f4388d91c4c964426fcb9e3665c3ebd8650009b815c8e'),
  Test(
    tc = "Random test failure 26",
    msg = '27e792b28b2f1702',
    sig = '14d9b497c19b91d43481c55bb6f5056de252d9ecb637575c807e58e9b4c5eac8'
          'b284089d97e2192dc242014363208e2c9a3435edf8928fb1d893553e9be4c703',
    sk =  'bccb61323840c2a96fc36f7e54ea6c8e55f9d221f7f05791ed60025e06064439',
    pk =  '54cda623245759ad6d43e620a606908befc633d60792bc7798447a0ef38e7311'),
  Test(
    tc = "Random test failure 27",
    msg = "eef3bb0f617c17d0420c115c21c28e3762edc7b7fb048529b84a9c2bc6",
    sig = "242ddb3a5d938d07af690b1b0ef0fa75842c5f9549bf39c8750f75614c712e7c"
          "baf2e37cc0799db38b858d41aec5b9dd2fca6a3c8e082c10408e2cf3932b9d08",
    sk =  "f2d3023b9c19e241748bc4039a7a43c595701f23675505015213a8a2a0274c1b",
    pk =  "2362bac514d5fad33802642e979a1e82de6eb6f1bcbf6a5b304f2bb02b9e57fe"),
  Test(
    tc = "Random test failure 28",
    msg = '475f',
    sig = '71a4a06a34075f2fd47bc3abf4714d46db7e97b08cb6180d3f1539ac50b18ce5'
          '1f8af8ae95ed21d4fa0daab7235925631ecea1fd9d0d8a2ba7a7583fd04b900c',
    sk = 'c367c8d2ebeeecd70c1e8985b70c3808b75657f243b21ba4f322792540e92257',
    pk = '32ad026f693d0d2afe7f4388d91c4c964426fcb9e3665c3ebd8650009b815c8e'),

  Test(
    tc = "Test case for overflow in signature generation",
    msg = "01234567",
    sig = "c964e100033ce8888b23466677da4f4aea29923f642ae508f9d0888d78815063"
          "6ab9b2c3765e91bbb05153801114d9e52dc700df377212222bb766be4b8c020d",
    sk = "12fc31c40d5a7af71e05424623ba970b670cf6ecb44cda6120210e6370245ddb",
    pk = "037b55b427dc8daa0f80fcebaf0846902309f8a6cf18b465c0ce9b6539629ac8"),
  # Tink failures in signature generation.
  # TODO: Check whether this is exploitable.
  #   Such failures would leak the private key if the failures are correlated
  #   with the secret exponent.
  # keynr: 1127
  Test(
    tc = "Test case for overflow in signature generation",
    sk = "e54bcc4ce95db48072c7b49575617dd1f9403b072105259ca06d8d01530d07fb",
    msg = "9399a6db9433d2a28d2b0c11c8794ab7d108c95b"),
  # keynr: 227
  Test(
    tc = "Test case for overflow in signature generation",
    sk = "de7f2bb12b875a79ccb057344b2867a2edb25dbc1ecfc8cb07c69e2dd3df3e02",
    msg = "7af783afbbd44c1833ab7237ecaf63b94ffdd003"),
  Test(
    tc = "Test case for overflow in signature generation",
    sk = "ea792b7a9d420bf74f6a82a78e58a2cc94f3ab3eb931270611b1f8da75c3d60b",
    msg = "321b5f663c19e30ee7bbb85e48ecf44db9d3f512"),
  Test(
    tc = "Test case for overflow in signature generation",
    sk = "eca28645f63646575ee2e4bdb36f51838142ce2474664c2b66ef054b37af6124",
    msg = "c48890e92aeeb3af04858a8dc1d34f16a4347b91"),
  # ED448
  Test(
    alg = 'ed448',
    tc = "RFC 8032",
    sk = '6c82a562cb808d10d632be89c8513ebf6c929f34ddfa8c9f63c9960ef6e348a3'
         '528c8a3fcc2f044e39a3fc5b94492f8f032e7549a20098f95b',
    pk = '5fd7449b59b461fd2ce787ec616ad46a1da1342485a70e1f8a0ea75d80e96778'
         'edf124769b46c7061bd6783df1e50f6cd1fa1abeafe8256180',
    msg = '',
    sig = '533a37f6bbe457251f023c0d88f976ae2dfb504a843e34d2074fd823d41a591f'
          '2b233f034f628281f2fd7a22ddd47d7828c59bd0a21bfd3980ff0d2028d4b18a'
          '9df63e006c5d1c2d345b925d8dc00b4104852db99ac5c7cdda8530a113a0f4db'
          'b61149f05a7363268c71d95808ff2e652600'),
  Test(
   alg = 'ed448',
   tc = "RFC 8032: 1 octet",
   sk = 'c4eab05d357007c632f3dbb48489924d552b08fe0c353a0d4a1f00acda2c463a'
        'fbea67c5e8d2877c5e3bc397a659949ef8021e954e0a12274e',
   pk = '43ba28f430cdff456ae531545f7ecd0ac834a55d9358c0372bfa0c6c6798c086'
        '6aea01eb00742802b8438ea4cb82169c235160627b4c3a9480',
   msg = '03',
   sig = '26b8f91727bd62897af15e41eb43c377efb9c610d48f2335cb0bd0087810f435'
         '2541b143c4b981b7e18f62de8ccdf633fc1bf037ab7cd779805e0dbcc0aae1cb'
         'cee1afb2e027df36bc04dcecbf154336c19f0af7e0a6472905e799f1953d2a0f'
         'f3348ab21aa4adafd1d234441cf807c03a00'),

   Test(
   alg = 'ed448',
   tc = "RFC 8032: 1 octet with context",
   sk = 'c4eab05d357007c632f3dbb48489924d552b08fe0c353a0d4a1f00acda2c463a'
        'fbea67c5e8d2877c5e3bc397a659949ef8021e954e0a12274e',
   pk = '43ba28f430cdff456ae531545f7ecd0ac834a55d9358c0372bfa0c6c6798c086'
        '6aea01eb00742802b8438ea4cb82169c235160627b4c3a9480',
   msg = '03',
   ctx = '666f6f',
   sig = 'd4f8f6131770dd46f40867d6fd5d5055de43541f8c5e35abbcd001b32a89f7d2'
         '151f7647f11d8ca2ae279fb842d607217fce6e042f6815ea000c85741de5c8da'
         '1144a6a1aba7f96de42505d7a7298524fda538fccbbb754f578c1cad10d54d0d'
         '5428407e85dcbc98a49155c13764e66c3c00'),
   Test(
   tc = "RFC 8032: 11 bytes",
   alg = 'ed448',
   sk = 'cd23d24f714274e744343237b93290f511f6425f98e64459ff203e8985083ffd'
        'f60500553abc0e05cd02184bdb89c4ccd67e187951267eb328',
   pk = 'dcea9e78f35a1bf3499a831b10b86c90aac01cd84b67a0109b55a36e9328b1e3'
        '65fce161d71ce7131a543ea4cb5f7e9f1d8b00696447001400',
   msg = '0c3e544074ec63b0265e0c',
   sig = '1f0a8888ce25e8d458a21130879b840a9089d999aaba039eaf3e3afa090a09d3'
         '89dba82c4ff2ae8ac5cdfb7c55e94d5d961a29fe0109941e00b8dbdeea6d3b05'
         '1068df7254c0cdc129cbe62db2dc957dbb47b51fd3f213fb8698f064774250a5'
         '028961c9bf8ffd973fe5d5c206492b140e00'),

   Test(
   tc = "RFC 8032: 12 bytes",
   alg = 'ed448',
   sk = '''
   258cdd4ada32ed9c9ff54e63756ae582
   fb8fab2ac721f2c8e676a72768513d93
   9f63dddb55609133f29adf86ec9929dc
   cb52c1c5fd2ff7e21b''',

   pk = '''
   3ba16da0c6f2cc1f30187740756f5e79
   8d6bc5fc015d7c63cc9510ee3fd44adc
   24d8e968b6e46e6f94d19b945361726b
   d75e149ef09817f580''',
   msg = '64a65f3cdedcdd66811e2915',
   sig = '''
   7eeeab7c4e50fb799b418ee5e3197ff6
   bf15d43a14c34389b59dd1a7b1b85b4a
   e90438aca634bea45e3a2695f1270f07
   fdcdf7c62b8efeaf00b45c2c96ba457e
   b1a8bf075a3db28e5c24f6b923ed4ad7
   47c3c9e03c7079efb87cb110d3a99861
   e72003cbae6d6b8b827e4e6c143064ff
   3c00'''),
   Test(
   tc = "RFC 8032: 13 bytes",
   alg = 'ed448',
   sk = '''
   7ef4e84544236752fbb56b8f31a23a10
   e42814f5f55ca037cdcc11c64c9a3b29
   49c1bb60700314611732a6c2fea98eeb
   c0266a11a93970100e''',
   pk = '''b3da079b0aa493a5772029f0467baebe
   e5a8112d9d3a22532361da294f7bb381
   5c5dc59e176b4d9f381ca0938e13c6c0
   7b174be65dfa578e80''',
   msg = '64a65f3cdedcdd66811e2915e7',
   sig = '''
   6a12066f55331b6c22acd5d5bfc5d712
   28fbda80ae8dec26bdd306743c5027cb
   4890810c162c027468675ecf645a8317
   6c0d7323a2ccde2d80efe5a1268e8aca
   1d6fbc194d3f77c44986eb4ab4177919
   ad8bec33eb47bbb5fc6e28196fd1caf5
   6b4e7e0ba5519234d047155ac727a105
   3100'''),
   Test(
   tc = "RFC 8032: 64 bytes",
   alg = 'ed448',
   sk = '''
   d65df341ad13e008567688baedda8e9d
   cdc17dc024974ea5b4227b6530e339bf
   f21f99e68ca6968f3cca6dfe0fb9f4fa
   b4fa135d5542ea3f01''',
   pk = '''df9705f58edbab802c7f8363cfe5560a
   b1c6132c20a9f1dd163483a26f8ac53a
   39d6808bf4a1dfbd261b099bb03b3fb5
   0906cb28bd8a081f00''',
   msg = '''bd0f6a3747cd561bdddf4640a332461a
   4a30a12a434cd0bf40d766d9c6d458e5
   512204a30c17d1f50b5079631f64eb31
   12182da3005835461113718d1a5ef944''',
   sig = '''
   554bc2480860b49eab8532d2a533b7d5
   78ef473eeb58c98bb2d0e1ce488a98b1
   8dfde9b9b90775e67f47d4a1c3482058
   efc9f40d2ca033a0801b63d45b3b722e
   f552bad3b4ccb667da350192b61c508c
   f7b6b5adadc2c8d9a446ef003fb05cba
   5f30e88e36ec2703b349ca229c267083
   3900'''),
   Test(
   tc = "RFC 8032: 256 bytes",
   alg = 'ed448',
   sk = '''
   2ec5fe3c17045abdb136a5e6a913e32a
   b75ae68b53d2fc149b77e504132d3756
   9b7e766ba74a19bd6162343a21c8590a
   a9cebca9014c636df5''',
   pk = '''79756f014dcfe2079f5dd9e718be4171
   e2ef2486a08f25186f6bff43a9936b9b
   fe12402b08ae65798a3d81e22e9ec80e
   7690862ef3d4ed3a00''',
   msg = '''
   15777532b0bdd0d1389f636c5f6b9ba7
   34c90af572877e2d272dd078aa1e567c
   fa80e12928bb542330e8409f31745041
   07ecd5efac61ae7504dabe2a602ede89
   e5cca6257a7c77e27a702b3ae39fc769
   fc54f2395ae6a1178cab4738e543072f
   c1c177fe71e92e25bf03e4ecb72f47b6
   4d0465aaea4c7fad372536c8ba516a60
   39c3c2a39f0e4d832be432dfa9a706a6
   e5c7e19f397964ca4258002f7c0541b5
   90316dbc5622b6b2a6fe7a4abffd9610
   5eca76ea7b98816af0748c10df048ce0
   12d901015a51f189f3888145c03650aa
   23ce894c3bd889e030d565071c59f409
   a9981b51878fd6fc110624dcbcde0bf7
   a69ccce38fabdf86f3bef6044819de11''',
   sig = '''
   c650ddbb0601c19ca11439e1640dd931
   f43c518ea5bea70d3dcde5f4191fe53f
   00cf966546b72bcc7d58be2b9badef28
   743954e3a44a23f880e8d4f1cfce2d7a
   61452d26da05896f0a50da66a239a8a1
   88b6d825b3305ad77b73fbac0836ecc6
   0987fd08527c1a8e80d5823e65cafe2a
   3d00'''),
   Test(
    tc = "RFC 8032: 1023 bytes",
    alg = 'ed448',
    sk = '''
   872d093780f5d3730df7c212664b37b8
   a0f24f56810daa8382cd4fa3f77634ec
   44dc54f1c2ed9bea86fafb7632d8be19
   9ea165f5ad55dd9ce8''',
   pk = '''a81b2e8a70a5ac94ffdbcc9badfc3feb
   0801f258578bb114ad44ece1ec0e799d
   a08effb81c5d685c0c56f64eecaef8cd
   f11cc38737838cf400''',
   msg = '''6ddf802e1aae4986935f7f981ba3f035
   1d6273c0a0c22c9c0e8339168e675412
   a3debfaf435ed651558007db4384b650
   fcc07e3b586a27a4f7a00ac8a6fec2cd
   86ae4bf1570c41e6a40c931db27b2faa
   15a8cedd52cff7362c4e6e23daec0fbc
   3a79b6806e316efcc7b68119bf46bc76
   a26067a53f296dafdbdc11c77f7777e9
   72660cf4b6a9b369a6665f02e0cc9b6e
   dfad136b4fabe723d2813db3136cfde9
   b6d044322fee2947952e031b73ab5c60
   3349b307bdc27bc6cb8b8bbd7bd32321
   9b8033a581b59eadebb09b3c4f3d2277
   d4f0343624acc817804728b25ab79717
   2b4c5c21a22f9c7839d64300232eb66e
   53f31c723fa37fe387c7d3e50bdf9813
   a30e5bb12cf4cd930c40cfb4e1fc6225
   92a49588794494d56d24ea4b40c89fc0
   596cc9ebb961c8cb10adde976a5d602b
   1c3f85b9b9a001ed3c6a4d3b1437f520
   96cd1956d042a597d561a596ecd3d173
   5a8d570ea0ec27225a2c4aaff26306d1
   526c1af3ca6d9cf5a2c98f47e1c46db9
   a33234cfd4d81f2c98538a09ebe76998
   d0d8fd25997c7d255c6d66ece6fa56f1
   1144950f027795e653008f4bd7ca2dee
   85d8e90f3dc315130ce2a00375a318c7
   c3d97be2c8ce5b6db41a6254ff264fa6
   155baee3b0773c0f497c573f19bb4f42
   40281f0b1f4f7be857a4e59d416c06b4
   c50fa09e1810ddc6b1467baeac5a3668
   d11b6ecaa901440016f389f80acc4db9
   77025e7f5924388c7e340a732e554440
   e76570f8dd71b7d640b3450d1fd5f041
   0a18f9a3494f707c717b79b4bf75c984
   00b096b21653b5d217cf3565c9597456
   f70703497a078763829bc01bb1cbc8fa
   04eadc9a6e3f6699587a9e75c94e5bab
   0036e0b2e711392cff0047d0d6b05bd2
   a588bc109718954259f1d86678a579a3
   120f19cfb2963f177aeb70f2d4844826
   262e51b80271272068ef5b3856fa8535
   aa2a88b2d41f2a0e2fda7624c2850272
   ac4a2f561f8f2f7a318bfd5caf969614
   9e4ac824ad3460538fdc25421beec2cc
   6818162d06bbed0c40a387192349db67
   a118bada6cd5ab0140ee273204f628aa
   d1c135f770279a651e24d8c14d75a605
   9d76b96a6fd857def5e0b354b27ab937
   a5815d16b5fae407ff18222c6d1ed263
   be68c95f32d908bd895cd76207ae7264
   87567f9a67dad79abec316f683b17f2d
   02bf07e0ac8b5bc6162cf94697b3c27c
   d1fea49b27f23ba2901871962506520c
   392da8b6ad0d99f7013fbc06c2c17a56
   9500c8a7696481c1cd33e9b14e40b82e
   79a5f5db82571ba97bae3ad3e0479515
   bb0e2b0f3bfcd1fd33034efc6245eddd
   7ee2086ddae2600d8ca73e214e8c2b0b
   db2b047c6a464a562ed77b73d2d841c4
   b34973551257713b753632efba348169
   abc90a68f42611a40126d7cb21b58695
   568186f7e569d2ff0f9e745d0487dd2e
   b997cafc5abf9dd102e62ff66cba87''',
    sig = '''
   e301345a41a39a4d72fff8df69c98075
   a0cc082b802fc9b2b6bc503f926b65bd
   df7f4c8f1cb49f6396afc8a70abe6d8a
   ef0db478d4c6b2970076c6a0484fe76d
   76b3a97625d79f1ce240e7c576750d29
   5528286f719b413de9ada3e8eb78ed57
   3603ce30d8bb761785dc30dbc320869e
   1a00'''),
]

# A small number of failures of tink.
TINK_FAILURES = [
  ("ea792b7a9d420bf74f6a82a78e58a2cc94f3ab3eb931270611b1f8da75c3d60b",
  "321b5f663c19e30ee7bbb85e48ecf44db9d3f512"),
  ("eca28645f63646575ee2e4bdb36f51838142ce2474664c2b66ef054b37af6124",
  "c48890e92aeeb3af04858a8dc1d34f16a4347b91"),
  ("728238602b7e6753b3f49eb0fc4cde38c7bb14ab58ddcaef2537275b13e99dd3",
  "26d5f0631f49106db58c4cfc903691134811b33c"),
  ("dc4092d7809c6b070f2808c434267b6697428f4ab1e4626ab56a3059643be43c",
  "2a71f064af982a3a1103a75cef898732d7881981"),
  ("38765b89ec56836ea4190fc957802b6a47167f9b5ef942e92652803b7de6abfd",
  "bf26796cef4ddafcf5033c8d105057db0210b6ad"),
  ("38765b89ec56836ea4190fc957802b6a47167f9b5ef942e92652803b7de6abfd",
  "bf26796cef4ddafcf5033c8d105057db0210b6ad"),
  ("97575308a490af0c145411dd16d519a073ef03c2e4a0a1cd6b5de2e881e5eabe",
  "ae03da6997e40cea67935020152d3a9a365cc055"),
  ("ad129e89e0eec908df51adc227c8c4908a8095d75621536c8a28dca4b3c30dbb",
  "489d473f7fb83c7f6823baf65482517bccd8f4ea"),
  ("03ce643d6d341b7065bc9e70da8193451cf83ca7ff5a8640fd07af094640365a",
  "1b704d6692d60a07ad1e1d047b65e105a80d3459"),
  ("581f593a5cd94594dc0f5dd142026a436a930e573391b7aeea6a8253eeef6ceb",
  "dc87030862c4c32f56261e93a367caf458c6be27"),
  ("6f207dc94b844d4dc71f982da8d9f3ae0b37b4623e441eca75ba62621c524d98",
  "7f41ef68508343ef18813cb2fb332445ec6480cd"),
  ("dea9bbb9fb20512fa67eea696afd786f3928265f5208aeaba638f3177d0db70e",
  "e1ce107971534bc46a42ac609a1a37b4ca65791d"),
  ("c99c52ae1e61f7c79a164ee4910fdcaa02946259ea5443f68b23d721d0472f63",
  "869a827397c585cf35acf88a8728833ab1c8c81e"),
  ("d8aaad0749db159569a68b46048b3d3e8266e110150251c42806f0752a84e95b",
  "619d8c4f2c93104be01cd574a385ceca08c33a9e"),
  ("e78d26ab5b726c9d4dfb1f634082abded90432a2fd18089c7c85253a5d2fc7d0",
  "5257a0bae8326d259a6ce97420c65e6c2794afe2"),
  ("8e7ca56e07f1438ac3615fd9ec77ae63679d0ec059b4595febf40be59d976a05",
  "5acb6afc9b368f7acac0e71f6a4831c72d628405"),
  ("e77525af5856ab9df5abb64e5312576b498cc27f61f266e21f382e0526d4e6fb",
  "3c87b3453277b353941591fc7eaa7dd37604b42a"),
  ("1f43235ad716f1beb754ab0f546dfa934488fdf7472b493d7cc3c60353005d24",
  "0a68e27ef6847bfd9e398b328a0ded3679d4649d"),
  ("3977785b9f8c5320e51a3a16f8cc22c4f7e64857617f9550147fa35d685ca34f",
  "4e9bef60737c7d4dd10bd52567e1473a36d3573d"),
  ("1aa4415c5db0131bec6fa188d0c23d49a65bf795657153fae94777e3f19bcf54",
  "cc82b3163efda3ba7e9240e765112caa69113694"),
  ("0fb7680a50d3f2940077ea4dfcb7eb040a125c4f4b5dcefa16d3af968fc8e5de",
  "923a5c9e7b5635bb6c32c5a408a4a15b652450eb"),
  ("e222c444d6bc8a4796a0d5a2d71d19b98845cc56e39caaf8233ea4c6b0704f09",
  "6f2f0245de4587062979d0422d349f93ccdc3af2"),
  ("a89ea18476b9ad90cb14b8b1ff24777e4ebd015bc810a60785a9154dacf3be52",
  "6e911edb27a170b983d4dee1110554f804330f41"),
  ("69b1da56cde8d1676c2a8c0e7f95c7d0bf60739efd1304dd2ccb02729d17a22c",
  "b8cf807eea809aaf739aa091f3b7a3f2fd39fb51"),
  ("b332265cf95595f0c90221593b5a2b3c574d60dc634ddff6186f0eed7980a383",
  "01a2b5f7fee813b4e9bd7fc25137648004795010"),
  ("faec9764b369df0ef10890dd022c502e551a3222b43e8429455496c76feea45d",
  "0fbf5d47cb5d498feace8f98f1896208da38a885"),
  ("4eb19e278f7a30a06a7d55e42c44775f4a81b7a45c0512aae026262e71770dac",
  "36e67c1939750bffb3e4ba6cb85562612275e862"),
  ("1998d5949cab365a00f828e7d17b06c708d33fef0031d353a4e15bf7222a73b0",
  "13945c894c1d3fe8562e8b20e5f0efaa26ade8e3"),
  ("6164676114c66bd9887dac341c66209dc587ccf0cc5cd9baffdfac9295a00c4a",
  "4de142af4b8402f80a47fa812df84f42e283cee7"),
  ("4b0bd03a03b20069ccbcc214a7448473f4e7a491fa7ceb48ddbe24c83c4aa4bb",
  "563357f41b8b23b1d83f19f5667177a67da20b18"),
  ("2fce7870be1f392d21fb1d2350ec7877db8aa99b359fe5bdd5338ff35a791d1c",
  "931bbf9c877a6571cf7d4609fc3eb867edd43f51"),
  ("a9ace42195ddbb3a16f366b24dd9d37a8a043ed2e6001f54652296750379367d",
  "44530b0b34f598767a7b875b0caee3c7b9c502d1"),
]


