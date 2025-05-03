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

ASCON_128_KTV = [
    # python reference code
    {
        "key": "000102030405060708090a0b0c0d0e0f",
        "iv": "101112131415161718191a1b1c1d1e1f",
        "msg": "",
        "aad": "",
        "ct": "",
        "tag": "38cca290d1f2ef3df9c8531946499037",
    },
    {
        "key": "000102030405060708090a0b0c0d0e0f",
        "iv": "101112131415161718191a1b1c1d1e1f",
        "msg": "4041424344454647",
        "aad": "6061626364656667",
        "ct": "93a9105db36d5972",
        "tag": "d69022e593ed90a4e71aa10ac070313a",
    },
    {
        "key": "000102030405060708090a0b0c0d0e0f",
        "iv": "101112131415161718191a1b1c1d1e1f",
        "msg": "404142434445464748494a4b4c4d4e",
        "aad": "606162636465666768696a6b6c6d6e",
        "ct": "36e4f75e251413cdbbf609c54e5fd0",
        "tag": "28317ecddf69e6880828c55f98406a5d",
    },
    {
        "key": "000102030405060708090a0b0c0d0e0f",
        "iv": "101112131415161718191a1b1c1d1e1f",
        "msg": "404142434445464748494a4b4c4d4e4f",
        "aad": "606162636465666768696a6b6c6d6e6f",
        "ct": "eee3eda3e3f57281ab105f0f3f200e4e",
        "tag": "329198cfd4b07b523c9ca2258412e593",
    },
    {
        "key": "000102030405060708090a0b0c0d0e0f",
        "iv": "101112131415161718191a1b1c1d1e1f",
        "msg": "404142434445464748494a4b4c4d4e4f50",
        "aad": "606162636465666768696a6b6c6d6e6f70",
        "ct": "1df1b7fa529027cbc55f1f0927043186a2",
        "tag": "b4f014c6f187945f0a8822e157cb7ff5",
    },
    {
        "key": "000102030405060708090a0b0c0d0e0f",
        "iv": "101112131415161718191a1b1c1d1e1f",
        "msg": "404142434445464748494a4b4c4d4e4f5051525354555657",
        "aad": "606162636465666768696a6b6c6d6e6f7071727374757677",
        "ct": "8fa67e2f472c5507bab511f412ffa667469957a7ded0605a",
        "tag": "ab65d74c4af4a0cfc22c54bd2a5abb02",
    },
    # self generated
    {
        "msg": "00000000000000000000000000000000",
        "key": "00000000000000000000000000000000",
        "iv": "00000000000000000000000000000000",
        "aad": "",
        "ct": "b8dff46b0db421f846c100c208a9ff68",
        "tag": "b374a5c15061719095b5e890494346ce"
    },
    {
        "msg": "000102030405060708090a0b0c0d0e0f",
        "key": "9812641238df7623fd0165638294192f",
        "iv": "921d2507fa8009816249dae2e7714202",
        "aad": "00112233445566778899aabbccddeeff",
        "ct": "6e32d339aa45c13efafd0055897560e9",
        "tag": "07dfe6d72cc3f73d40d39268221069c9"
    },
    {
        "msg": "2035af313d1346ab00154fea78322105",
        "key": "aa023d0478dcb2b2312498293d9a9129",
        "iv": "0432bc49ac3441201243141581288127",
        "aad": "aac39231129872a2",
        "ct": "343fef8ea03632ad26d4a82e3b117705",
        "tag": "27016cf7178c9583fc9e43a18e69d56c"
    },
    {
        "msg": "02efd2e5782312827ed5d230189a2a342b277ce048462193",
        "key": "2034a82547276c83dd3212a813572bce",
        "iv": "3254202d854734812398127a3d134421",
        "aad": "1a0293d8f90219058902139013908190bc490890d3ff12a3",
        "ct": "a251bd4da0709339149aba3cd15057afdf88b85c373b2f43",
        "tag": "0f978e68989da9ae3b60584f4d9a7284"
    },
]

ASCON_128A_KTV = [
    # python reference
    {
        "key": "000102030405060708090a0b0c0d0e0f",
        "iv": "101112131415161718191a1b1c1d1e1f",
        "msg": "",
        "aad": "",
        "ct": "",
        "tag": "6db880ca0cfa1d6af9a82abe364084d9",
    },
    {
        "key": "000102030405060708090a0b0c0d0e0f",
        "iv": "101112131415161718191a1b1c1d1e1f",
        "msg": "4041424344454647",
        "aad": "6061626364656667",
        "ct": "548d9e6f568303a9",
        "tag": "9b598aef27e058246321cbcdbc83718f",
    },
    {
        "key": "000102030405060708090a0b0c0d0e0f",
        "iv": "101112131415161718191a1b1c1d1e1f",
        "msg": "404142434445464748494a4b4c4d4e",
        "aad": "606162636465666768696a6b6c6d6e",
        "ct": "6d8237215063d8ec8395c49cee0041",
        "tag": "e469a6302f8f2f4accc097e32d260f03",
    },
    {
        "key": "000102030405060708090a0b0c0d0e0f",
        "iv": "101112131415161718191a1b1c1d1e1f",
        "msg": "404142434445464748494a4b4c4d4e4f",
        "aad": "606162636465666768696a6b6c6d6e6f",
        "ct": "1ff569d3fd9f6eb0d200c2c834be4cf4",
        "tag": "3c9224c5b76298572511af9e3834cd68",
    },
    {
        "key": "000102030405060708090a0b0c0d0e0f",
        "iv": "101112131415161718191a1b1c1d1e1f",
        "msg": "404142434445464748494a4b4c4d4e4f50",
        "aad": "606162636465666768696a6b6c6d6e6f70",
        "ct": "95e312cf86da3128981b77f64e020bc290",
        "tag": "2a82bd8a7c3adf37d0956dce3c454ac7",
    },
    {
        "key": "000102030405060708090a0b0c0d0e0f",
        "iv": "101112131415161718191a1b1c1d1e1f",
        "msg": "404142434445464748494a4b4c4d4e4f5051525354555657",
        "aad": "606162636465666768696a6b6c6d6e6f7071727374757677",
        "ct": "4b91ccce4c6e9794d623dd8d9bcd53fc37c17adc1c29b2bf",
        "tag": "a18add2e78f0c275194b30b23f2b9e9c",
    },
    # self generated
    {
        "msg": "00000000000000000000000000000000",
        "key": "00000000000000000000000000000000",
        "iv": "00000000000000000000000000000000",
        "aad": "",
        "ct": "d7f1dce343e6745b1020415c792e3aca",
        "tag": "df9c87b3196b1755fff0434b943bf5c2"
    },
    {
        "msg": "000102030405060708090a0b0c0d0e0f",
        "key": "9812641238df7623fd0165638294192f",
        "iv": "921d2507fa8009816249dae2e7714202",
        "aad": "00112233445566778899aabbccddeeff",
        "ct": "a2c5535b11924b5dfb7c26ae5835771c",
        "tag": "b9aa82fdbb3b028d629c899cadf39957"
    },
    {
        "msg": "2035af313d1346ab00154fea78322105",
        "key": "aa023d0478dcb2b2312498293d9a9129",
        "iv": "0432bc49ac3441201243141581288127",
        "aad": "aac39231129872a2",
        "ct": "7ee42636af9bbb2df2aa55a8b21746dc",
        "tag": "a93628a8f5811d030216bda49e6d98f3"
    },
    {
        "msg": "02efd2e5782312827ed5d230189a2a342b277ce048462193",
        "key": "2034a82547276c83dd3212a813572bce",
        "iv": "3254202d854734812398127a3d134421",
        "aad": "1a0293d8f90219058902139013908190bc490890d3ff12a3",
        "ct": "00b3b02e1a51d2a8838034ca7f33c56b22d07cbf883a975b",
        "tag": "18d9d60f888e0d0f3a59931ded0fe1b3"
    },
]

ASCON_80PQ_KTV = [
    # python reference code
    {
        "key": "000102030405060708090a0b0c0d0e0f10111213",
        "iv": "101112131415161718191a1b1c1d1e1f",
        "msg": "",
        "aad": "",
        "ct": "",
        "tag": "c02be9c1e93fd10f6519c4eb22c491d8",
    },
    {
        "key": "000102030405060708090a0b0c0d0e0f10111213",
        "iv": "101112131415161718191a1b1c1d1e1f",
        "msg": "4041424344454647",
        "aad": "6061626364656667",
        "ct": "3eb9dcb20536b93c",
        "tag": "9caa910a0c0dce34ab0b1531cdf30987",
    },
    {
        "key": "000102030405060708090a0b0c0d0e0f10111213",
        "iv": "101112131415161718191a1b1c1d1e1f",
        "msg": "404142434445464748494a4b4c4d4e",
        "aad": "606162636465666768696a6b6c6d6e",
        "ct": "02a34120fa2a1685e81a1d2049baf0",
        "tag": "83dc5f517fbece7f859939c9acc094f8",
    },
    {
        "key": "000102030405060708090a0b0c0d0e0f10111213",
        "iv": "101112131415161718191a1b1c1d1e1f",
        "msg": "404142434445464748494a4b4c4d4e4f",
        "aad": "606162636465666768696a6b6c6d6e6f",
        "ct": "6771bf1cb21db9becab91ff5abfcb11b",
        "tag": "a9a75f76fc6cb748bf2b43db39803f31",
    },
    {
        "key": "000102030405060708090a0b0c0d0e0f10111213",
        "iv": "101112131415161718191a1b1c1d1e1f",
        "msg": "404142434445464748494a4b4c4d4e4f50",
        "aad": "606162636465666768696a6b6c6d6e6f70",
        "ct": "c4932684f188d1ffded9f4d2223cb12b19",
        "tag": "1fd144e4b035daf4b27413604f541421",
    },
    {
        "key": "000102030405060708090a0b0c0d0e0f10111213",
        "iv": "101112131415161718191a1b1c1d1e1f",
        "msg": "404142434445464748494a4b4c4d4e4f5051525354555657",
        "aad": "606162636465666768696a6b6c6d6e6f7071727374757677",
        "ct": "cef3cbb7c3c5535ad29e75817eb128e8564ddfa3bcf6cdf3",
        "tag": "92632749804326ad76f96f7c4f862dfd",
    },
    # self generated
    {
        "msg": "00000000000000000000000000000000",
        "key": "0000000000000000000000000000000000000000",
        "iv": "00000000000000000000000000000000",
        "aad": "",
        "ct": "adaaad8122d13debf7cb10b15b0bedc4",
        "tag": "ed589734386a16c05428ae29e19ba0d7"
    },
    {
        "msg": "000102030405060708090a0b0c0d0e0f",
        "key": "98121241234641238df7623fd0165638294192f2",
        "iv": "921d2507fa8009816249dae2e7714202",
        "aad": "00112233445566778899aabbccddeeff",
        "ct": "3559fc345578889aa1d8c872e3a7f073",
        "tag": "024053840deb12a88126624fbc7d05bb"
    },
    {
        "msg": "2035af313d1346ab00154fea78322105",
        "key": "aa023d0478dcb2b2312498293d9a912918274121",
        "iv": "0432bc49ac3441201243141581288127",
        "aad": "aac39231129872a2",
        "ct": "75a4d9fd7262bfd6e42595b6e620146b",
        "tag": "1d62eaee1ef29bfad6c464fe4a3c89b7"
    },
    {
        "msg": "02efd2e5782312827ed5d230189a2a342b277ce048462193",
        "key": "124aa2034a81242547276c83dd3212a813572bce",
        "iv": "3254202d854734812398127a3d134421",
        "aad": "1a0293d8f90219058902139013908190bc490890d3ff12a3",
        "ct": "67e9840082fa2d094ba1b92f85b0b1d2bf0e4a67ada024bb",
        "tag": "3298e769b65af8663ab03a7f35ffb43a"
    },
]

ASCON_XOF_KTV = [
    # python reference code
    {
        "msg":
            "",
        "tag":
            "5d4cbde6350ea4c174bd65b5b332f8408f99740b81aa02735eaefbcf0ba0339e",
    },
    {
        "msg":
            "6173636f6e",
        "tag":
            "85483cc9c035082b093c520b46274aff8c68c05aea11488e636d7db86e4c39d5",
    },
    {
        "msg":
            "000102030405060708090a0b0c0d0e",
        "tag":
            "399e6be584de5091f49711ed6c195f0de0ee811113c68b372399dbbff28f1173",
    },
    {
        "msg":
            "000102030405060708090a0b0c0d0e0f",
        "tag":
            "c861a89cfb1335f278c96cf7ffc9753c290cbe1a4e186d2923b496bb4ea5e519",
    },
    {
        "msg":
            "000102030405060708090a0b0c0d0e0f10",
        "tag":
            "604419f916e9ef78d037e624614fd5988185c6c2aa8ad9c4a35c4b9d9e15b360",
    },
    # self generated
    {
        "msg":
            "000102030405060708090a0b0c" * 13,
        "tag":
            "d22e4be6b5e9c0a337c58de91f093c9acd1136018cb9e45fa66469841efebd2f"
    },
]

ASCON_HASH_KTV = [
    # python reference code
    {
        "msg":
            "",
        "tag":
            "7346bc14f036e87ae03d0997913088f5f68411434b3cf8b54fa796a80d251f91",
    },
    {
        "msg":
            "6173636f6e",
        "tag":
            "02c895cb92d79f195ed9e3e2af89ae307059104aaa819b9a987a76cf7cf51e6e",
    },
    {
        "msg":
            "000102030405060708090a0b0c0d0e",
        "tag":
            "9e48e03e8aae0b9930dff1e801007bc7105d6bd6caaf16e3c31569d8942fc423",
    },
    {
        "msg":
            "000102030405060708090a0b0c0d0e0f",
        "tag":
            "d4e56c4841e2a0069d4f07e61b2dca94fd6d3f9c0df78393e6e8292921bc841d",
    },
    {
        "msg":
            "000102030405060708090a0b0c0d0e0f10",
        "tag":
            "91407cf08bc734ca4cad88d6a848bf87045f56ee2df51563b9ba59d66b489938",
    },
    {
        "msg":
            "101112131415161718191a1b1c1d1e1f",
        "tag":
            "a781f53871e5cbda83ba86bbbdeefe89e495ed4b12f44103ed8f7aa77b977172",
    },
    # self generated
    {
        "msg":
            "000102030405060708090a0b0c" * 13,
        "tag":
            "7d86573d2a3edfe4d4842606fef76339e202731cd2886b4fcafea324f1bbb594"
    },
]

ASCON_XOFA_KTV = [
    # python reference code
    {
        "msg":
            "",
        "tag":
            "7c10dffd6bb03be262d72fbe1b0f530013c6c4eadaabde278d6f29d579e3908d",
    },
    {
        "msg":
            "6173636f6e",
        "tag":
            "1948e5fedc1e016f5a1c32014900303727ac6f3ea31bba72ced3f964f8d21394",
    },
    {
        "msg":
            "000102030405060708090a0b0c0d0e",
        "tag":
            "75f61359f04c77ff4de58a10f9f87b31b5b8da3373f6230fe1735033446b9948",
    },
    {
        "msg":
            "000102030405060708090a0b0c0d0e0f",
        "tag":
            "9424b7ae5fa72d3ee4a266112e7abc4092e815ae29fab26da666c1485ba92bdc",
    },
    {
        "msg":
            "000102030405060708090a0b0c0d0e0f10",
        "tag":
            "e559cdaf16ddd0c6e52ede142b38a713a6a0456ae886a7cc10bad63c554f2557",
    },
    {
        "msg":
            "101112131415161718191a1b1c1d1e1f",
        "tag":
            "83fe543f5fb687b1d60eb70dff833aa981c8211e1180e9a5ee72a00dd1c777aa",
    },
    # self generated
    {
        "msg":
            "000102030405060708090a0b0c" * 13,
        "tag":
            "10d7f1642b7c29ecac9f18e09f85cb74b522f0b369996705a3844c65648a35d4"
    },
]

ASCON_HASHA_KTV = [
    # python reference code
    {
        "msg":
            "",
        "tag":
            "aecd027026d0675f9de7a8ad8ccf512db64b1edcf0b20c388a0c7cc617aaa2c4",
    },
    {
        "msg":
            "6173636f6e",
        "tag":
            "d5919be57877fb2216f9b3e2df202bdf0002131c2fa496ee0de2cdaebc2d7902",
    },
    {
        "msg":
            "000102030405060708090a0b0c0d0e",
        "tag":
            "2cabc9fb4df0c8eb2ed789eb28ac5d464762b1f98c176c370548496ca9229bac",
    },
    {
        "msg":
            "000102030405060708090a0b0c0d0e0f",
        "tag":
            "ea1cb73639bfa0c6de4e60960f4f73510fe4481340f1d956a59e9dd2166f9a99",
    },
    {
        "msg":
            "000102030405060708090a0b0c0d0e0f10",
        "tag":
            "ac3c9c02679819cfc8a482ed6f57bec790dc8054c5b4f55eecac466844dd389b",
    },
    {
        "msg":
            "101112131415161718191a1b1c1d1e1f",
        "tag":
            "1fef6573bc73f82a171c1bdc3abee69155240d7e3b68d2ef269623362be7549c",
    },
    # self generated
    {
        "msg":
            "000102030405060708090a0b0c" * 13,
        "tag":
            "f738118d40ad0c99429b86c5bcc930f6ad89051f219db1ccb1037ade622b96d8"
    },
]
