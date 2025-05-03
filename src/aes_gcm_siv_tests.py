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

import aes_gcm_siv

# Tests from RFC 8452 Appendix C.
raw = """
Appendix C.  Test Vectors

C.1.  AEAD_AES_128_GCM_SIV

   Plaintext (0 bytes) =
   AAD (0 bytes) =
   Key =                       01000000000000000000000000000000
   Nonce =                     030000000000000000000000
   Record authentication key = d9b360279694941ac5dbc6987ada7377
   Record encryption key =     4004a0dcd862f2a57360219d2d44ef6c
   POLYVAL input =             00000000000000000000000000000000
   POLYVAL result =            00000000000000000000000000000000
   POLYVAL result XOR nonce =  03000000000000000000000000000000
   ... and masked =            03000000000000000000000000000000
   Tag =                       dc20e2d83f25705bb49e439eca56de25
   Initial counter =           dc20e2d83f25705bb49e439eca56dea5
   Result (16 bytes) =         dc20e2d83f25705bb49e439eca56de25


   Plaintext (8 bytes) =       0100000000000000
   AAD (0 bytes) =
   Key =                       01000000000000000000000000000000
   Nonce =                     030000000000000000000000
   Record authentication key = d9b360279694941ac5dbc6987ada7377
   Record encryption key =     4004a0dcd862f2a57360219d2d44ef6c
   POLYVAL input =             01000000000000000000000000000000
                               00000000000000004000000000000000
   POLYVAL result =            eb93b7740962c5e49d2a90a7dc5cec74
   POLYVAL result XOR nonce =  e893b7740962c5e49d2a90a7dc5cec74
   ... and masked =            e893b7740962c5e49d2a90a7dc5cec74
   Tag =                       578782fff6013b815b287c22493a364c
   Initial counter =           578782fff6013b815b287c22493a36cc
   Result (24 bytes) =         b5d839330ac7b786578782fff6013b81
                               5b287c22493a364c


   Plaintext (12 bytes) =      010000000000000000000000
   AAD (0 bytes) =
   Key =                       01000000000000000000000000000000
   Nonce =                     030000000000000000000000
   Record authentication key = d9b360279694941ac5dbc6987ada7377
   Record encryption key =     4004a0dcd862f2a57360219d2d44ef6c
   POLYVAL input =             01000000000000000000000000000000
                               00000000000000006000000000000000
   POLYVAL result =            48eb6c6c5a2dbe4a1dde508fee06361b
   POLYVAL result XOR nonce =  4beb6c6c5a2dbe4a1dde508fee06361b
   ... and masked =            4beb6c6c5a2dbe4a1dde508fee06361b
   Tag =                       a4978db357391a0bc4fdec8b0d106639



Gueron, et al.                Informational                    [Page 20]
 
RFC 8452                       AES-GCM-SIV                    April 2019


   Initial counter =           a4978db357391a0bc4fdec8b0d1066b9
   Result (28 bytes) =         7323ea61d05932260047d942a4978db3
                               57391a0bc4fdec8b0d106639


   Plaintext (16 bytes) =      01000000000000000000000000000000
   AAD (0 bytes) =
   Key =                       01000000000000000000000000000000
   Nonce =                     030000000000000000000000
   Record authentication key = d9b360279694941ac5dbc6987ada7377
   Record encryption key =     4004a0dcd862f2a57360219d2d44ef6c
   POLYVAL input =             01000000000000000000000000000000
                               00000000000000008000000000000000
   POLYVAL result =            20806c26e3c1de019e111255708031d6
   POLYVAL result XOR nonce =  23806c26e3c1de019e111255708031d6
   ... and masked =            23806c26e3c1de019e11125570803156
   Tag =                       303aaf90f6fe21199c6068577437a0c4
   Initial counter =           303aaf90f6fe21199c6068577437a0c4
   Result (32 bytes) =         743f7c8077ab25f8624e2e948579cf77
                               303aaf90f6fe21199c6068577437a0c4


   Plaintext (32 bytes) =      01000000000000000000000000000000
                               02000000000000000000000000000000
   AAD (0 bytes) =
   Key =                       01000000000000000000000000000000
   Nonce =                     030000000000000000000000
   Record authentication key = d9b360279694941ac5dbc6987ada7377
   Record encryption key =     4004a0dcd862f2a57360219d2d44ef6c
   POLYVAL input =             01000000000000000000000000000000
                               02000000000000000000000000000000
                               00000000000000000001000000000000
   POLYVAL result =            ce6edc9a50b36d9a98986bbf6a261c3b
   POLYVAL result XOR nonce =  cd6edc9a50b36d9a98986bbf6a261c3b
   ... and masked =            cd6edc9a50b36d9a98986bbf6a261c3b
   Tag =                       1a8e45dcd4578c667cd86847bf6155ff
   Initial counter =           1a8e45dcd4578c667cd86847bf6155ff
   Result (48 bytes) =         84e07e62ba83a6585417245d7ec413a9
                               fe427d6315c09b57ce45f2e3936a9445
                               1a8e45dcd4578c667cd86847bf6155ff


   Plaintext (48 bytes) =      01000000000000000000000000000000
                               02000000000000000000000000000000
                               03000000000000000000000000000000
   AAD (0 bytes) =
   Key =                       01000000000000000000000000000000
   Nonce =                     030000000000000000000000



Gueron, et al.                Informational                    [Page 21]
 
RFC 8452                       AES-GCM-SIV                    April 2019


   Record authentication key = d9b360279694941ac5dbc6987ada7377
   Record encryption key =     4004a0dcd862f2a57360219d2d44ef6c
   POLYVAL input =             01000000000000000000000000000000
                               02000000000000000000000000000000
                               03000000000000000000000000000000
                               00000000000000008001000000000000
   POLYVAL result =            81388746bc22d26b2abc3dcb15754222
   POLYVAL result XOR nonce =  82388746bc22d26b2abc3dcb15754222
   ... and masked =            82388746bc22d26b2abc3dcb15754222
   Tag =                       5e6e311dbf395d35b0fe39c2714388f8
   Initial counter =           5e6e311dbf395d35b0fe39c2714388f8
   Result (64 bytes) =         3fd24ce1f5a67b75bf2351f181a475c7
                               b800a5b4d3dcf70106b1eea82fa1d64d
                               f42bf7226122fa92e17a40eeaac1201b
                               5e6e311dbf395d35b0fe39c2714388f8


   Plaintext (64 bytes) =      01000000000000000000000000000000
                               02000000000000000000000000000000
                               03000000000000000000000000000000
                               04000000000000000000000000000000
   AAD (0 bytes) =
   Key =                       01000000000000000000000000000000
   Nonce =                     030000000000000000000000
   Record authentication key = d9b360279694941ac5dbc6987ada7377
   Record encryption key =     4004a0dcd862f2a57360219d2d44ef6c
   POLYVAL input =             01000000000000000000000000000000
                               02000000000000000000000000000000
                               03000000000000000000000000000000
                               04000000000000000000000000000000
                               00000000000000000002000000000000
   POLYVAL result =            1e39b6d3344d348f6044f89935d1cf78
   POLYVAL result XOR nonce =  1d39b6d3344d348f6044f89935d1cf78
   ... and masked =            1d39b6d3344d348f6044f89935d1cf78
   Tag =                       8a263dd317aa88d56bdf3936dba75bb8
   Initial counter =           8a263dd317aa88d56bdf3936dba75bb8
   Result (80 bytes) =         2433668f1058190f6d43e360f4f35cd8
                               e475127cfca7028ea8ab5c20f7ab2af0
                               2516a2bdcbc08d521be37ff28c152bba
                               36697f25b4cd169c6590d1dd39566d3f
                               8a263dd317aa88d56bdf3936dba75bb8


   Plaintext (8 bytes) =       0200000000000000
   AAD (1 bytes) =             01
   Key =                       01000000000000000000000000000000
   Nonce =                     030000000000000000000000
   Record authentication key = d9b360279694941ac5dbc6987ada7377



Gueron, et al.                Informational                    [Page 22]
 
RFC 8452                       AES-GCM-SIV                    April 2019


   Record encryption key =     4004a0dcd862f2a57360219d2d44ef6c
   POLYVAL input =             01000000000000000000000000000000
                               02000000000000000000000000000000
                               08000000000000004000000000000000
   POLYVAL result =            b26781e7e2c1376f96bec195f3709b2a
   POLYVAL result XOR nonce =  b16781e7e2c1376f96bec195f3709b2a
   ... and masked =            b16781e7e2c1376f96bec195f3709b2a
   Tag =                       3b0a1a2560969cdf790d99759abd1508
   Initial counter =           3b0a1a2560969cdf790d99759abd1588
   Result (24 bytes) =         1e6daba35669f4273b0a1a2560969cdf
                               790d99759abd1508


   Plaintext (12 bytes) =      020000000000000000000000
   AAD (1 bytes) =             01
   Key =                       01000000000000000000000000000000
   Nonce =                     030000000000000000000000
   Record authentication key = d9b360279694941ac5dbc6987ada7377
   Record encryption key =     4004a0dcd862f2a57360219d2d44ef6c
   POLYVAL input =             01000000000000000000000000000000
                               02000000000000000000000000000000
                               08000000000000006000000000000000
   POLYVAL result =            111f5affb18e4cc1164a01bdc12a4145
   POLYVAL result XOR nonce =  121f5affb18e4cc1164a01bdc12a4145
   ... and masked =            121f5affb18e4cc1164a01bdc12a4145
   Tag =                       08299c5102745aaa3a0c469fad9e075a
   Initial counter =           08299c5102745aaa3a0c469fad9e07da
   Result (28 bytes) =         296c7889fd99f41917f4462008299c51
                               02745aaa3a0c469fad9e075a


   Plaintext (16 bytes) =      02000000000000000000000000000000
   AAD (1 bytes) =             01
   Key =                       01000000000000000000000000000000
   Nonce =                     030000000000000000000000
   Record authentication key = d9b360279694941ac5dbc6987ada7377
   Record encryption key =     4004a0dcd862f2a57360219d2d44ef6c
   POLYVAL input =             01000000000000000000000000000000
                               02000000000000000000000000000000
                               08000000000000008000000000000000
   POLYVAL result =            79745ab508622c8a958543675fac4688
   POLYVAL result XOR nonce =  7a745ab508622c8a958543675fac4688
   ... and masked =            7a745ab508622c8a958543675fac4608
   Tag =                       8f8936ec039e4e4bb97ebd8c4457441f
   Initial counter =           8f8936ec039e4e4bb97ebd8c4457449f
   Result (32 bytes) =         e2b0c5da79a901c1745f700525cb335b
                               8f8936ec039e4e4bb97ebd8c4457441f




Gueron, et al.                Informational                    [Page 23]
 
RFC 8452                       AES-GCM-SIV                    April 2019


   Plaintext (32 bytes) =      02000000000000000000000000000000
                               03000000000000000000000000000000
   AAD (1 bytes) =             01
   Key =                       01000000000000000000000000000000
   Nonce =                     030000000000000000000000
   Record authentication key = d9b360279694941ac5dbc6987ada7377
   Record encryption key =     4004a0dcd862f2a57360219d2d44ef6c
   POLYVAL input =             01000000000000000000000000000000
                               02000000000000000000000000000000
                               03000000000000000000000000000000
                               08000000000000000001000000000000
   POLYVAL result =            2ce7daaf7c89490822051255b12eca6b
   POLYVAL result XOR nonce =  2fe7daaf7c89490822051255b12eca6b
   ... and masked =            2fe7daaf7c89490822051255b12eca6b
   Tag =                       e6af6a7f87287da059a71684ed3498e1
   Initial counter =           e6af6a7f87287da059a71684ed3498e1
   Result (48 bytes) =         620048ef3c1e73e57e02bb8562c416a3
                               19e73e4caac8e96a1ecb2933145a1d71
                               e6af6a7f87287da059a71684ed3498e1


   Plaintext (48 bytes) =      02000000000000000000000000000000
                               03000000000000000000000000000000
                               04000000000000000000000000000000
   AAD (1 bytes) =             01
   Key =                       01000000000000000000000000000000
   Nonce =                     030000000000000000000000
   Record authentication key = d9b360279694941ac5dbc6987ada7377
   Record encryption key =     4004a0dcd862f2a57360219d2d44ef6c
   POLYVAL input =             01000000000000000000000000000000
                               02000000000000000000000000000000
                               03000000000000000000000000000000
                               04000000000000000000000000000000
                               08000000000000008001000000000000
   POLYVAL result =            9ca987715d69c1786711dfcd22f830fc
   POLYVAL result XOR nonce =  9fa987715d69c1786711dfcd22f830fc
   ... and masked =            9fa987715d69c1786711dfcd22f8307c
   Tag =                       6a8cc3865f76897c2e4b245cf31c51f2
   Initial counter =           6a8cc3865f76897c2e4b245cf31c51f2
   Result (64 bytes) =         50c8303ea93925d64090d07bd109dfd9
                               515a5a33431019c17d93465999a8b005
                               3201d723120a8562b838cdff25bf9d1e
                               6a8cc3865f76897c2e4b245cf31c51f2


   Plaintext (64 bytes) =      02000000000000000000000000000000
                               03000000000000000000000000000000
                               04000000000000000000000000000000



Gueron, et al.                Informational                    [Page 24]
 
RFC 8452                       AES-GCM-SIV                    April 2019


                               05000000000000000000000000000000
   AAD (1 bytes) =             01
   Key =                       01000000000000000000000000000000
   Nonce =                     030000000000000000000000
   Record authentication key = d9b360279694941ac5dbc6987ada7377
   Record encryption key =     4004a0dcd862f2a57360219d2d44ef6c
   POLYVAL input =             01000000000000000000000000000000
                               02000000000000000000000000000000
                               03000000000000000000000000000000
                               04000000000000000000000000000000
                               05000000000000000000000000000000
                               08000000000000000002000000000000
   POLYVAL result =            ffcd05d5770f34ad9267f0a59994b15a
   POLYVAL result XOR nonce =  fccd05d5770f34ad9267f0a59994b15a
   ... and masked =            fccd05d5770f34ad9267f0a59994b15a
   Tag =                       cdc46ae475563de037001ef84ae21744
   Initial counter =           cdc46ae475563de037001ef84ae217c4
   Result (80 bytes) =         2f5c64059db55ee0fb847ed513003746
                               aca4e61c711b5de2e7a77ffd02da42fe
                               ec601910d3467bb8b36ebbaebce5fba3
                               0d36c95f48a3e7980f0e7ac299332a80
                               cdc46ae475563de037001ef84ae21744


   Plaintext (4 bytes) =       02000000
   AAD (12 bytes) =            010000000000000000000000
   Key =                       01000000000000000000000000000000
   Nonce =                     030000000000000000000000
   Record authentication key = d9b360279694941ac5dbc6987ada7377
   Record encryption key =     4004a0dcd862f2a57360219d2d44ef6c
   POLYVAL input =             01000000000000000000000000000000
                               02000000000000000000000000000000
                               60000000000000002000000000000000
   POLYVAL result =            f6ce9d3dcd68a2fd603c7ecc18fb9918
   POLYVAL result XOR nonce =  f5ce9d3dcd68a2fd603c7ecc18fb9918
   ... and masked =            f5ce9d3dcd68a2fd603c7ecc18fb9918
   Tag =                       07eb1f84fb28f8cb73de8e99e2f48a14
   Initial counter =           07eb1f84fb28f8cb73de8e99e2f48a94
   Result (20 bytes) =         a8fe3e8707eb1f84fb28f8cb73de8e99
                               e2f48a14


   Plaintext (20 bytes) =      03000000000000000000000000000000
                               04000000
   AAD (18 bytes) =            01000000000000000000000000000000
                               0200
   Key =                       01000000000000000000000000000000
   Nonce =                     030000000000000000000000



Gueron, et al.                Informational                    [Page 25]
 
RFC 8452                       AES-GCM-SIV                    April 2019


   Record authentication key = d9b360279694941ac5dbc6987ada7377
   Record encryption key =     4004a0dcd862f2a57360219d2d44ef6c
   POLYVAL input =             01000000000000000000000000000000
                               02000000000000000000000000000000
                               03000000000000000000000000000000
                               04000000000000000000000000000000
                               9000000000000000a000000000000000
   POLYVAL result =            4781d492cb8f926c504caa36f61008fe
   POLYVAL result XOR nonce =  4481d492cb8f926c504caa36f61008fe
   ... and masked =            4481d492cb8f926c504caa36f610087e
   Tag =                       24afc9805e976f451e6d87f6fe106514
   Initial counter =           24afc9805e976f451e6d87f6fe106594
   Result (36 bytes) =         6bb0fecf5ded9b77f902c7d5da236a43
                               91dd029724afc9805e976f451e6d87f6
                               fe106514


   Plaintext (18 bytes) =      03000000000000000000000000000000
                               0400
   AAD (20 bytes) =            01000000000000000000000000000000
                               02000000
   Key =                       01000000000000000000000000000000
   Nonce =                     030000000000000000000000
   Record authentication key = d9b360279694941ac5dbc6987ada7377
   Record encryption key =     4004a0dcd862f2a57360219d2d44ef6c
   POLYVAL input =             01000000000000000000000000000000
                               02000000000000000000000000000000
                               03000000000000000000000000000000
                               04000000000000000000000000000000
                               a0000000000000009000000000000000
   POLYVAL result =            75cbc23a1a10e348aeb8e384b5cc79fd
   POLYVAL result XOR nonce =  76cbc23a1a10e348aeb8e384b5cc79fd
   ... and masked =            76cbc23a1a10e348aeb8e384b5cc797d
   Tag =                       bff9b2ef00fb47920cc72a0c0f13b9fd
   Initial counter =           bff9b2ef00fb47920cc72a0c0f13b9fd
   Result (34 bytes) =         44d0aaf6fb2f1f34add5e8064e83e12a
                               2adabff9b2ef00fb47920cc72a0c0f13
                               b9fd

   Plaintext (0 bytes) =
   AAD (0 bytes) =
   Key =                       e66021d5eb8e4f4066d4adb9c33560e4
   Nonce =                     f46e44bb3da0015c94f70887
   Record authentication key = 036ee1fe2d7926af68898095e54e7b3c
   Record encryption key =     5e46482396008223b5c1d25173d87539
   POLYVAL input =             00000000000000000000000000000000
   POLYVAL result =            00000000000000000000000000000000
   POLYVAL result XOR nonce =  f46e44bb3da0015c94f7088700000000



Gueron, et al.                Informational                    [Page 26]
 
RFC 8452                       AES-GCM-SIV                    April 2019


   ... and masked =            f46e44bb3da0015c94f7088700000000
   Tag =                       a4194b79071b01a87d65f706e3949578
   Initial counter =           a4194b79071b01a87d65f706e39495f8
   Result (16 bytes) =         a4194b79071b01a87d65f706e3949578


   Plaintext (3 bytes) =       7a806c
   AAD (5 bytes) =             46bb91c3c5
   Key =                       36864200e0eaf5284d884a0e77d31646
   Nonce =                     bae8e37fc83441b16034566b
   Record authentication key = 3e28de1120b2981a0155795ca2812af6
   Record encryption key =     6d4b78b31a4c9c03d8db0f42f7507fae
   POLYVAL input =             46bb91c3c50000000000000000000000
                               7a806c00000000000000000000000000
                               28000000000000001800000000000000
   POLYVAL result =            43d9a745511dcfa21b96dd606f1d5720
   POLYVAL result XOR nonce =  f931443a99298e137ba28b0b6f1d5720
   ... and masked =            f931443a99298e137ba28b0b6f1d5720
   Tag =                       711bd85bc1e4d3e0a462e074eea428a8
   Initial counter =           711bd85bc1e4d3e0a462e074eea428a8
   Result (19 bytes) =         af60eb711bd85bc1e4d3e0a462e074ee
                               a428a8


   Plaintext (6 bytes) =       bdc66f146545
   AAD (10 bytes) =            fc880c94a95198874296
   Key =                       aedb64a6c590bc84d1a5e269e4b47801
   Nonce =                     afc0577e34699b9e671fdd4f
   Record authentication key = 43b8de9cea62330d15cccfc84a33e8c8
   Record encryption key =     8e54631607e431e095b54852868e3a27
   POLYVAL input =             fc880c94a95198874296000000000000
                               bdc66f14654500000000000000000000
                               50000000000000003000000000000000
   POLYVAL result =            26498e0d2b1ef004e808c458e8f2f515
   POLYVAL result XOR nonce =  8989d9731f776b9a8f171917e8f2f515
   ... and masked =            8989d9731f776b9a8f171917e8f2f515
   Tag =                       d6a9c45545cfc11f03ad743dba20f966
   Initial counter =           d6a9c45545cfc11f03ad743dba20f9e6
   Result (22 bytes) =         bb93a3e34d3cd6a9c45545cfc11f03ad
                               743dba20f966


   Plaintext (9 bytes) =       1177441f195495860f
   AAD (15 bytes) =            046787f3ea22c127aaf195d1894728
   Key =                       d5cc1fd161320b6920ce07787f86743b
   Nonce =                     275d1ab32f6d1f0434d8848c
   Record authentication key = 8a51df64d93eaf667c2c09bd454ce5c5
   Record encryption key =     43ab276c2b4a473918ca73f2dd85109c



Gueron, et al.                Informational                    [Page 27]
 
RFC 8452                       AES-GCM-SIV                    April 2019


   POLYVAL input =             046787f3ea22c127aaf195d189472800
                               1177441f195495860f00000000000000
                               78000000000000004800000000000000
   POLYVAL result =            63a3451c0b23345ad02bba59956517cf
   POLYVAL result XOR nonce =  44fe5faf244e2b5ee4f33ed5956517cf
   ... and masked =            44fe5faf244e2b5ee4f33ed59565174f
   Tag =                       1d02fd0cd174c84fc5dae2f60f52fd2b
   Initial counter =           1d02fd0cd174c84fc5dae2f60f52fdab
   Result (25 bytes) =         4f37281f7ad12949d01d02fd0cd174c8
                               4fc5dae2f60f52fd2b


   Plaintext (12 bytes) =      9f572c614b4745914474e7c7
   AAD (20 bytes) =            c9882e5386fd9f92ec489c8fde2be2cf
                               97e74e93
   Key =                       b3fed1473c528b8426a582995929a149
   Nonce =                     9e9ad8780c8d63d0ab4149c0
   Record authentication key = 22f50707a95dd416df069d670cb775e8
   Record encryption key =     f674a5584ee21fe97b4cebc468ab61e4
   POLYVAL input =             c9882e5386fd9f92ec489c8fde2be2cf
                               97e74e93000000000000000000000000
                               9f572c614b4745914474e7c700000000
                               a0000000000000006000000000000000
   POLYVAL result =            0cca0423fba9d77fe7e2e6963b08cdd0
   POLYVAL result XOR nonce =  9250dc5bf724b4af4ca3af563b08cdd0
   ... and masked =            9250dc5bf724b4af4ca3af563b08cd50
   Tag =                       c1dc2f871fb7561da1286e655e24b7b0
   Initial counter =           c1dc2f871fb7561da1286e655e24b7b0
   Result (28 bytes) =         f54673c5ddf710c745641c8bc1dc2f87
                               1fb7561da1286e655e24b7b0


   Plaintext (15 bytes) =      0d8c8451178082355c9e940fea2f58
   AAD (25 bytes) =            2950a70d5a1db2316fd568378da107b5
                               2b0da55210cc1c1b0a
   Key =                       2d4ed87da44102952ef94b02b805249b
   Nonce =                     ac80e6f61455bfac8308a2d4
   Record authentication key = 0b00a29a83e7e95b92e3a0783b29f140
   Record encryption key =     a430c27f285aed913005975c42eed5f3
   POLYVAL input =             2950a70d5a1db2316fd568378da107b5
                               2b0da55210cc1c1b0a00000000000000
                               0d8c8451178082355c9e940fea2f5800
                               c8000000000000007800000000000000
   POLYVAL result =            1086ef25247aa41009bbc40871d9b350
   POLYVAL result XOR nonce =  bc0609d3302f1bbc8ab366dc71d9b350
   ... and masked =            bc0609d3302f1bbc8ab366dc71d9b350
   Tag =                       83b3449b9f39552de99dc214a1190b0b
   Initial counter =           83b3449b9f39552de99dc214a1190b8b



Gueron, et al.                Informational                    [Page 28]
 
RFC 8452                       AES-GCM-SIV                    April 2019


   Result (31 bytes) =         c9ff545e07b88a015f05b274540aa183
                               b3449b9f39552de99dc214a1190b0b


   Plaintext (18 bytes) =      6b3db4da3d57aa94842b9803a96e07fb
                               6de7
   AAD (30 bytes) =            1860f762ebfbd08284e421702de0de18
                               baa9c9596291b08466f37de21c7f
   Key =                       bde3b2f204d1e9f8b06bc47f9745b3d1
   Nonce =                     ae06556fb6aa7890bebc18fe
   Record authentication key = 21c874a8bad3603d1c3e8784df5b3f9f
   Record encryption key =     d1c16d72651c3df504eae27129d818e8
   POLYVAL input =             1860f762ebfbd08284e421702de0de18
                               baa9c9596291b08466f37de21c7f0000
                               6b3db4da3d57aa94842b9803a96e07fb
                               6de70000000000000000000000000000
                               f0000000000000009000000000000000
   POLYVAL result =            55462a5afa0da8d646481e049ef9c764
   POLYVAL result XOR nonce =  fb407f354ca7d046f8f406fa9ef9c764
   ... and masked =            fb407f354ca7d046f8f406fa9ef9c764
   Tag =                       3e377094f04709f64d7b985310a4db84
   Initial counter =           3e377094f04709f64d7b985310a4db84
   Result (34 bytes) =         6298b296e24e8cc35dce0bed484b7f30
                               d5803e377094f04709f64d7b985310a4
                               db84


   Plaintext (21 bytes) =      e42a3c02c25b64869e146d7b233987bd
                               dfc240871d
   AAD (35 bytes) =            7576f7028ec6eb5ea7e298342a94d4b2
                               02b370ef9768ec6561c4fe6b7e7296fa
                               859c21
   Key =                       f901cfe8a69615a93fdf7a98cad48179
   Nonce =                     6245709fb18853f68d833640
   Record authentication key = 3724f55f1d22ac0ab830da0b6a995d74
   Record encryption key =     75ac87b70c05db287de779006105a344
   POLYVAL input =             7576f7028ec6eb5ea7e298342a94d4b2
                               02b370ef9768ec6561c4fe6b7e7296fa
                               859c2100000000000000000000000000
                               e42a3c02c25b64869e146d7b233987bd
                               dfc240871d0000000000000000000000
                               1801000000000000a800000000000000
   POLYVAL result =            4cbba090f03f7d1188ea55749fa6c7bd
   POLYVAL result XOR nonce =  2efed00f41b72ee7056963349fa6c7bd
   ... and masked =            2efed00f41b72ee7056963349fa6c73d
   Tag =                       2d15506c84a9edd65e13e9d24a2a6e70
   Initial counter =           2d15506c84a9edd65e13e9d24a2a6ef0
   Result (37 bytes) =         391cc328d484a4f46406181bcd62efd9



Gueron, et al.                Informational                    [Page 29]
 
RFC 8452                       AES-GCM-SIV                    April 2019


                               b3ee197d052d15506c84a9edd65e13e9
                               d24a2a6e70

C.2.  AEAD_AES_256_GCM_SIV

   Plaintext (0 bytes) =
   AAD (0 bytes) =
   Key =                       01000000000000000000000000000000
                               00000000000000000000000000000000
   Nonce =                     030000000000000000000000
   Record authentication key = b5d3c529dfafac43136d2d11be284d7f
   Record encryption key =     b914f4742be9e1d7a2f84addbf96dec3
                               456e3c6c05ecc157cdbf0700fedad222
   POLYVAL input =             00000000000000000000000000000000
   POLYVAL result =            00000000000000000000000000000000
   POLYVAL result XOR nonce =  03000000000000000000000000000000
   ... and masked =            03000000000000000000000000000000
   Tag =                       07f5f4169bbf55a8400cd47ea6fd400f
   Initial counter =           07f5f4169bbf55a8400cd47ea6fd408f
   Result (16 bytes) =         07f5f4169bbf55a8400cd47ea6fd400f


   Plaintext (8 bytes) =       0100000000000000
   AAD (0 bytes) =
   Key =                       01000000000000000000000000000000
                               00000000000000000000000000000000
   Nonce =                     030000000000000000000000
   Record authentication key = b5d3c529dfafac43136d2d11be284d7f
   Record encryption key =     b914f4742be9e1d7a2f84addbf96dec3
                               456e3c6c05ecc157cdbf0700fedad222
   POLYVAL input =             01000000000000000000000000000000
                               00000000000000004000000000000000
   POLYVAL result =            05230f62f0eac8aa14fe4d646b59cd41
   POLYVAL result XOR nonce =  06230f62f0eac8aa14fe4d646b59cd41
   ... and masked =            06230f62f0eac8aa14fe4d646b59cd41
   Tag =                       843122130f7364b761e0b97427e3df28
   Initial counter =           843122130f7364b761e0b97427e3dfa8
   Result (24 bytes) =         c2ef328e5c71c83b843122130f7364b7
                               61e0b97427e3df28


   Plaintext (12 bytes) =      010000000000000000000000
   AAD (0 bytes) =
   Key =                       01000000000000000000000000000000
                               00000000000000000000000000000000
   Nonce =                     030000000000000000000000
   Record authentication key = b5d3c529dfafac43136d2d11be284d7f
   Record encryption key =     b914f4742be9e1d7a2f84addbf96dec3



Gueron, et al.                Informational                    [Page 30]
 
RFC 8452                       AES-GCM-SIV                    April 2019


                               456e3c6c05ecc157cdbf0700fedad222
   POLYVAL input =             01000000000000000000000000000000
                               00000000000000006000000000000000
   POLYVAL result =            6d81a24732fd6d03ae5af544720a1c13
   POLYVAL result XOR nonce =  6e81a24732fd6d03ae5af544720a1c13
   ... and masked =            6e81a24732fd6d03ae5af544720a1c13
   Tag =                       8ca50da9ae6559e48fd10f6e5c9ca17e
   Initial counter =           8ca50da9ae6559e48fd10f6e5c9ca1fe
   Result (28 bytes) =         9aab2aeb3faa0a34aea8e2b18ca50da9
                               ae6559e48fd10f6e5c9ca17e


   Plaintext (16 bytes) =      01000000000000000000000000000000
   AAD (0 bytes) =
   Key =                       01000000000000000000000000000000
                               00000000000000000000000000000000
   Nonce =                     030000000000000000000000
   Record authentication key = b5d3c529dfafac43136d2d11be284d7f
   Record encryption key =     b914f4742be9e1d7a2f84addbf96dec3
                               456e3c6c05ecc157cdbf0700fedad222
   POLYVAL input =             01000000000000000000000000000000
                               00000000000000008000000000000000
   POLYVAL result =            74eee2bf7c9a165f8b25dea73db32a6d
   POLYVAL result XOR nonce =  77eee2bf7c9a165f8b25dea73db32a6d
   ... and masked =            77eee2bf7c9a165f8b25dea73db32a6d
   Tag =                       c9eac6fa700942702e90862383c6c366
   Initial counter =           c9eac6fa700942702e90862383c6c3e6
   Result (32 bytes) =         85a01b63025ba19b7fd3ddfc033b3e76
                               c9eac6fa700942702e90862383c6c366


   Plaintext (32 bytes) =      01000000000000000000000000000000
                               02000000000000000000000000000000
   AAD (0 bytes) =
   Key =                       01000000000000000000000000000000
                               00000000000000000000000000000000
   Nonce =                     030000000000000000000000
   Record authentication key = b5d3c529dfafac43136d2d11be284d7f
   Record encryption key =     b914f4742be9e1d7a2f84addbf96dec3
                               456e3c6c05ecc157cdbf0700fedad222
   POLYVAL input =             01000000000000000000000000000000
                               02000000000000000000000000000000
                               00000000000000000001000000000000
   POLYVAL result =            899b6381b3d46f0def7aa0517ba188f5
   POLYVAL result XOR nonce =  8a9b6381b3d46f0def7aa0517ba188f5
   ... and masked =            8a9b6381b3d46f0def7aa0517ba18875
   Tag =                       e819e63abcd020b006a976397632eb5d
   Initial counter =           e819e63abcd020b006a976397632ebdd



Gueron, et al.                Informational                    [Page 31]
 
RFC 8452                       AES-GCM-SIV                    April 2019


   Result (48 bytes) =         4a6a9db4c8c6549201b9edb53006cba8
                               21ec9cf850948a7c86c68ac7539d027f
                               e819e63abcd020b006a976397632eb5d


   Plaintext (48 bytes) =      01000000000000000000000000000000
                               02000000000000000000000000000000
                               03000000000000000000000000000000
   AAD (0 bytes) =
   Key =                       01000000000000000000000000000000
                               00000000000000000000000000000000
   Nonce =                     030000000000000000000000
   Record authentication key = b5d3c529dfafac43136d2d11be284d7f
   Record encryption key =     b914f4742be9e1d7a2f84addbf96dec3
                               456e3c6c05ecc157cdbf0700fedad222
   POLYVAL input =             01000000000000000000000000000000
                               02000000000000000000000000000000
                               03000000000000000000000000000000
                               00000000000000008001000000000000
   POLYVAL result =            c1f8593d8fc29b0c290cae1992f71f51
   POLYVAL result XOR nonce =  c2f8593d8fc29b0c290cae1992f71f51
   ... and masked =            c2f8593d8fc29b0c290cae1992f71f51
   Tag =                       790bc96880a99ba804bd12c0e6a22cc4
   Initial counter =           790bc96880a99ba804bd12c0e6a22cc4
   Result (64 bytes) =         c00d121893a9fa603f48ccc1ca3c57ce
                               7499245ea0046db16c53c7c66fe717e3
                               9cf6c748837b61f6ee3adcee17534ed5
                               790bc96880a99ba804bd12c0e6a22cc4


   Plaintext (64 bytes) =      01000000000000000000000000000000
                               02000000000000000000000000000000
                               03000000000000000000000000000000
                               04000000000000000000000000000000
   AAD (0 bytes) =
   Key =                       01000000000000000000000000000000
                               00000000000000000000000000000000
   Nonce =                     030000000000000000000000
   Record authentication key = b5d3c529dfafac43136d2d11be284d7f
   Record encryption key =     b914f4742be9e1d7a2f84addbf96dec3
                               456e3c6c05ecc157cdbf0700fedad222
   POLYVAL input =             01000000000000000000000000000000
                               02000000000000000000000000000000
                               03000000000000000000000000000000
                               04000000000000000000000000000000
                               00000000000000000002000000000000
   POLYVAL result =            6ef38b06046c7c0e225efaef8e2ec4c4
   POLYVAL result XOR nonce =  6df38b06046c7c0e225efaef8e2ec4c4



Gueron, et al.                Informational                    [Page 32]
 
RFC 8452                       AES-GCM-SIV                    April 2019


   ... and masked =            6df38b06046c7c0e225efaef8e2ec444
   Tag =                       112864c269fc0d9d88c61fa47e39aa08
   Initial counter =           112864c269fc0d9d88c61fa47e39aa88
   Result (80 bytes) =         c2d5160a1f8683834910acdafc41fbb1
                               632d4a353e8b905ec9a5499ac34f96c7
                               e1049eb080883891a4db8caaa1f99dd0
                               04d80487540735234e3744512c6f90ce
                               112864c269fc0d9d88c61fa47e39aa08


   Plaintext (8 bytes) =       0200000000000000
   AAD (1 bytes) =             01
   Key =                       01000000000000000000000000000000
                               00000000000000000000000000000000
   Nonce =                     030000000000000000000000
   Record authentication key = b5d3c529dfafac43136d2d11be284d7f
   Record encryption key =     b914f4742be9e1d7a2f84addbf96dec3
                               456e3c6c05ecc157cdbf0700fedad222
   POLYVAL input =             01000000000000000000000000000000
                               02000000000000000000000000000000
                               08000000000000004000000000000000
   POLYVAL result =            34e57bafe011b9b36fc6821b7ffb3354
   POLYVAL result XOR nonce =  37e57bafe011b9b36fc6821b7ffb3354
   ... and masked =            37e57bafe011b9b36fc6821b7ffb3354
   Tag =                       91213f267e3b452f02d01ae33e4ec854
   Initial counter =           91213f267e3b452f02d01ae33e4ec8d4
   Result (24 bytes) =         1de22967237a813291213f267e3b452f
                               02d01ae33e4ec854


   Plaintext (12 bytes) =      020000000000000000000000
   AAD (1 bytes) =             01
   Key =                       01000000000000000000000000000000
                               00000000000000000000000000000000
   Nonce =                     030000000000000000000000
   Record authentication key = b5d3c529dfafac43136d2d11be284d7f
   Record encryption key =     b914f4742be9e1d7a2f84addbf96dec3
                               456e3c6c05ecc157cdbf0700fedad222
   POLYVAL input =             01000000000000000000000000000000
                               02000000000000000000000000000000
                               08000000000000006000000000000000
   POLYVAL result =            5c47d68a22061c1ad5623a3b66a8e206
   POLYVAL result XOR nonce =  5f47d68a22061c1ad5623a3b66a8e206
   ... and masked =            5f47d68a22061c1ad5623a3b66a8e206
   Tag =                       c1a4a19ae800941ccdc57cc8413c277f
   Initial counter =           c1a4a19ae800941ccdc57cc8413c27ff
   Result (28 bytes) =         163d6f9cc1b346cd453a2e4cc1a4a19a
                               e800941ccdc57cc8413c277f



Gueron, et al.                Informational                    [Page 33]
 
RFC 8452                       AES-GCM-SIV                    April 2019


   Plaintext (16 bytes) =      02000000000000000000000000000000
   AAD (1 bytes) =             01
   Key =                       01000000000000000000000000000000
                               00000000000000000000000000000000
   Nonce =                     030000000000000000000000
   Record authentication key = b5d3c529dfafac43136d2d11be284d7f
   Record encryption key =     b914f4742be9e1d7a2f84addbf96dec3
                               456e3c6c05ecc157cdbf0700fedad222
   POLYVAL input =             01000000000000000000000000000000
                               02000000000000000000000000000000
                               08000000000000008000000000000000
   POLYVAL result =            452896726c616746f01d11d82911d478
   POLYVAL result XOR nonce =  462896726c616746f01d11d82911d478
   ... and masked =            462896726c616746f01d11d82911d478
   Tag =                       b292d28ff61189e8e49f3875ef91aff7
   Initial counter =           b292d28ff61189e8e49f3875ef91aff7
   Result (32 bytes) =         c91545823cc24f17dbb0e9e807d5ec17
                               b292d28ff61189e8e49f3875ef91aff7


   Plaintext (32 bytes) =      02000000000000000000000000000000
                               03000000000000000000000000000000
   AAD (1 bytes) =             01
   Key =                       01000000000000000000000000000000
                               00000000000000000000000000000000
   Nonce =                     030000000000000000000000
   Record authentication key = b5d3c529dfafac43136d2d11be284d7f
   Record encryption key =     b914f4742be9e1d7a2f84addbf96dec3
                               456e3c6c05ecc157cdbf0700fedad222
   POLYVAL input =             01000000000000000000000000000000
                               02000000000000000000000000000000
                               03000000000000000000000000000000
                               08000000000000000001000000000000
   POLYVAL result =            4e58c1e341c9bb0ae34eda9509dfc90c
   POLYVAL result XOR nonce =  4d58c1e341c9bb0ae34eda9509dfc90c
   ... and masked =            4d58c1e341c9bb0ae34eda9509dfc90c
   Tag =                       aea1bad12702e1965604374aab96dbbc
   Initial counter =           aea1bad12702e1965604374aab96dbbc
   Result (48 bytes) =         07dad364bfc2b9da89116d7bef6daaaf
                               6f255510aa654f920ac81b94e8bad365
                               aea1bad12702e1965604374aab96dbbc


   Plaintext (48 bytes) =      02000000000000000000000000000000
                               03000000000000000000000000000000
                               04000000000000000000000000000000
   AAD (1 bytes) =             01
   Key =                       01000000000000000000000000000000



Gueron, et al.                Informational                    [Page 34]
 
RFC 8452                       AES-GCM-SIV                    April 2019


                               00000000000000000000000000000000
   Nonce =                     030000000000000000000000
   Record authentication key = b5d3c529dfafac43136d2d11be284d7f
   Record encryption key =     b914f4742be9e1d7a2f84addbf96dec3
                               456e3c6c05ecc157cdbf0700fedad222
   POLYVAL input =             01000000000000000000000000000000
                               02000000000000000000000000000000
                               03000000000000000000000000000000
                               04000000000000000000000000000000
                               08000000000000008001000000000000
   POLYVAL result =            2566a4aff9a525df9772c16d4eaf8d2a
   POLYVAL result XOR nonce =  2666a4aff9a525df9772c16d4eaf8d2a
   ... and masked =            2666a4aff9a525df9772c16d4eaf8d2a
   Tag =                       03332742b228c647173616cfd44c54eb
   Initial counter =           03332742b228c647173616cfd44c54eb
   Result (64 bytes) =         c67a1f0f567a5198aa1fcc8e3f213143
                               36f7f51ca8b1af61feac35a86416fa47
                               fbca3b5f749cdf564527f2314f42fe25
                               03332742b228c647173616cfd44c54eb


   Plaintext (64 bytes) =      02000000000000000000000000000000
                               03000000000000000000000000000000
                               04000000000000000000000000000000
                               05000000000000000000000000000000
   AAD (1 bytes) =             01
   Key =                       01000000000000000000000000000000
                               00000000000000000000000000000000
   Nonce =                     030000000000000000000000
   Record authentication key = b5d3c529dfafac43136d2d11be284d7f
   Record encryption key =     b914f4742be9e1d7a2f84addbf96dec3
                               456e3c6c05ecc157cdbf0700fedad222
   POLYVAL input =             01000000000000000000000000000000
                               02000000000000000000000000000000
                               03000000000000000000000000000000
                               04000000000000000000000000000000
                               05000000000000000000000000000000
                               08000000000000000002000000000000
   POLYVAL result =            da58d2f61b0a9d343b2f37fb0c519733
   POLYVAL result XOR nonce =  d958d2f61b0a9d343b2f37fb0c519733
   ... and masked =            d958d2f61b0a9d343b2f37fb0c519733
   Tag =                       5bde0285037c5de81e5b570a049b62a0
   Initial counter =           5bde0285037c5de81e5b570a049b62a0
   Result (80 bytes) =         67fd45e126bfb9a79930c43aad2d3696
                               7d3f0e4d217c1e551f59727870beefc9
                               8cb933a8fce9de887b1e40799988db1f
                               c3f91880ed405b2dd298318858467c89
                               5bde0285037c5de81e5b570a049b62a0



Gueron, et al.                Informational                    [Page 35]
 
RFC 8452                       AES-GCM-SIV                    April 2019


   Plaintext (4 bytes) =       02000000
   AAD (12 bytes) =            010000000000000000000000
   Key =                       01000000000000000000000000000000
                               00000000000000000000000000000000
   Nonce =                     030000000000000000000000
   Record authentication key = b5d3c529dfafac43136d2d11be284d7f
   Record encryption key =     b914f4742be9e1d7a2f84addbf96dec3
                               456e3c6c05ecc157cdbf0700fedad222
   POLYVAL input =             01000000000000000000000000000000
                               02000000000000000000000000000000
                               60000000000000002000000000000000
   POLYVAL result =            6dc76ae84b88916e073a303aafde05cf
   POLYVAL result XOR nonce =  6ec76ae84b88916e073a303aafde05cf
   ... and masked =            6ec76ae84b88916e073a303aafde054f
   Tag =                       1835e517741dfddccfa07fa4661b74cf
   Initial counter =           1835e517741dfddccfa07fa4661b74cf
   Result (20 bytes) =         22b3f4cd1835e517741dfddccfa07fa4
                               661b74cf


   Plaintext (20 bytes) =      03000000000000000000000000000000
                               04000000
   AAD (18 bytes) =            01000000000000000000000000000000
                               0200
   Key =                       01000000000000000000000000000000
                               00000000000000000000000000000000
   Nonce =                     030000000000000000000000
   Record authentication key = b5d3c529dfafac43136d2d11be284d7f
   Record encryption key =     b914f4742be9e1d7a2f84addbf96dec3
                               456e3c6c05ecc157cdbf0700fedad222
   POLYVAL input =             01000000000000000000000000000000
                               02000000000000000000000000000000
                               03000000000000000000000000000000
                               04000000000000000000000000000000
                               9000000000000000a000000000000000
   POLYVAL result =            973ef4fd04bd31d193816ab26f8655ca
   POLYVAL result XOR nonce =  943ef4fd04bd31d193816ab26f8655ca
   ... and masked =            943ef4fd04bd31d193816ab26f86554a
   Tag =                       b879ad976d8242acc188ab59cabfe307
   Initial counter =           b879ad976d8242acc188ab59cabfe387
   Result (36 bytes) =         43dd0163cdb48f9fe3212bf61b201976
                               067f342bb879ad976d8242acc188ab59
                               cabfe307


   Plaintext (18 bytes) =      03000000000000000000000000000000
                               0400
   AAD (20 bytes) =            01000000000000000000000000000000



Gueron, et al.                Informational                    [Page 36]
 
RFC 8452                       AES-GCM-SIV                    April 2019


                               02000000
   Key =                       01000000000000000000000000000000
                               00000000000000000000000000000000
   Nonce =                     030000000000000000000000
   Record authentication key = b5d3c529dfafac43136d2d11be284d7f
   Record encryption key =     b914f4742be9e1d7a2f84addbf96dec3
                               456e3c6c05ecc157cdbf0700fedad222
   POLYVAL input =             01000000000000000000000000000000
                               02000000000000000000000000000000
                               03000000000000000000000000000000
                               04000000000000000000000000000000
                               a0000000000000009000000000000000
   POLYVAL result =            2cbb6b7ab2dbffefb797f825f826870c
   POLYVAL result XOR nonce =  2fbb6b7ab2dbffefb797f825f826870c
   ... and masked =            2fbb6b7ab2dbffefb797f825f826870c
   Tag =                       cfcdf5042112aa29685c912fc2056543
   Initial counter =           cfcdf5042112aa29685c912fc20565c3
   Result (34 bytes) =         462401724b5ce6588d5a54aae5375513
                               a075cfcdf5042112aa29685c912fc205
                               6543

   Plaintext (0 bytes) =
   AAD (0 bytes) =
   Key =                       e66021d5eb8e4f4066d4adb9c33560e4
                               f46e44bb3da0015c94f7088736864200
   Nonce =                     e0eaf5284d884a0e77d31646
   Record authentication key = e40d26f82774aa27f47b047b608b9585
   Record encryption key =     7c7c3d9a542cef53dde0e6de9b580040
                               0f82e73ec5f7ee41b7ba8dcb9ba078c3
   POLYVAL input =             00000000000000000000000000000000
   POLYVAL result =            00000000000000000000000000000000
   POLYVAL result XOR nonce =  e0eaf5284d884a0e77d3164600000000
   ... and masked =            e0eaf5284d884a0e77d3164600000000
   Tag =                       169fbb2fbf389a995f6390af22228a62
   Initial counter =           169fbb2fbf389a995f6390af22228ae2
   Result (16 bytes) =         169fbb2fbf389a995f6390af22228a62


   Plaintext (3 bytes) =       671fdd
   AAD (5 bytes) =             4fbdc66f14
   Key =                       bae8e37fc83441b16034566b7a806c46
                               bb91c3c5aedb64a6c590bc84d1a5e269
   Nonce =                     e4b47801afc0577e34699b9e
   Record authentication key = b546f5a850d0a90adfe39e95c2510fc6
   Record encryption key =     b9d1e239d62cbb5c49273ddac8838bdc
                               c53bca478a770f07087caa4e0a924a55
   POLYVAL input =             4fbdc66f140000000000000000000000
                               671fdd00000000000000000000000000



Gueron, et al.                Informational                    [Page 37]
 
RFC 8452                       AES-GCM-SIV                    April 2019


                               28000000000000001800000000000000
   POLYVAL result =            b91f91f96b159a7c611c05035b839e92
   POLYVAL result XOR nonce =  5dabe9f8c4d5cd0255759e9d5b839e92
   ... and masked =            5dabe9f8c4d5cd0255759e9d5b839e12
   Tag =                       93da9bb81333aee0c785b240d319719d
   Initial counter =           93da9bb81333aee0c785b240d319719d
   Result (19 bytes) =         0eaccb93da9bb81333aee0c785b240d3
                               19719d


   Plaintext (6 bytes) =       195495860f04
   AAD (10 bytes) =            6787f3ea22c127aaf195
   Key =                       6545fc880c94a95198874296d5cc1fd1
                               61320b6920ce07787f86743b275d1ab3
   Nonce =                     2f6d1f0434d8848c1177441f
   Record authentication key = e156e1f9b0b07b780cbe30f259e3c8da
   Record encryption key =     6fc1c494519f944aae52fcd8b14e5b17
                               1b5a9429d3b76e430d49940c0021d612
   POLYVAL input =             6787f3ea22c127aaf195000000000000
                               195495860f0400000000000000000000
                               50000000000000003000000000000000
   POLYVAL result =            2c480ed9d236b1df24c6eec109bd40c1
   POLYVAL result XOR nonce =  032511dde6ee355335b1aade09bd40c1
   ... and masked =            032511dde6ee355335b1aade09bd4041
   Tag =                       6b62b84dc40c84636a5ec12020ec8c2c
   Initial counter =           6b62b84dc40c84636a5ec12020ec8cac
   Result (22 bytes) =         a254dad4f3f96b62b84dc40c84636a5e
                               c12020ec8c2c


   Plaintext (9 bytes) =       c9882e5386fd9f92ec
   AAD (15 bytes) =            489c8fde2be2cf97e74e932d4ed87d
   Key =                       d1894728b3fed1473c528b8426a58299
                               5929a1499e9ad8780c8d63d0ab4149c0
   Nonce =                     9f572c614b4745914474e7c7
   Record authentication key = 0533fd71f4119257361a3ff1469dd4e5
   Record encryption key =     4feba89799be8ac3684fa2bb30ade0ea
                               51390e6d87dcf3627d2ee44493853abe
   POLYVAL input =             489c8fde2be2cf97e74e932d4ed87d00
                               c9882e5386fd9f92ec00000000000000
                               78000000000000004800000000000000
   POLYVAL result =            bf160bc9ded8c63057d2c38aae552fb4
   POLYVAL result XOR nonce =  204127a8959f83a113a6244dae552fb4
   ... and masked =            204127a8959f83a113a6244dae552f34
   Tag =                       c0fd3dc6628dfe55ebb0b9fb2295c8c2
   Initial counter =           c0fd3dc6628dfe55ebb0b9fb2295c8c2
   Result (25 bytes) =         0df9e308678244c44bc0fd3dc6628dfe
                               55ebb0b9fb2295c8c2



Gueron, et al.                Informational                    [Page 38]
 
RFC 8452                       AES-GCM-SIV                    April 2019


   Plaintext (12 bytes) =      1db2316fd568378da107b52b
   AAD (20 bytes) =            0da55210cc1c1b0abde3b2f204d1e9f8
                               b06bc47f
   Key =                       a44102952ef94b02b805249bac80e6f6
                               1455bfac8308a2d40d8c845117808235
   Nonce =                     5c9e940fea2f582950a70d5a
   Record authentication key = 64779ab10ee8a280272f14cc8851b727
   Record encryption key =     25f40fc63f49d3b9016a8eeeb75846e0
                               d72ca36ddbd312b6f5ef38ad14bd2651
   POLYVAL input =             0da55210cc1c1b0abde3b2f204d1e9f8
                               b06bc47f000000000000000000000000
                               1db2316fd568378da107b52b00000000
                               a0000000000000006000000000000000
   POLYVAL result =            cc86ee22c861e1fd474c84676b42739c
   POLYVAL result XOR nonce =  90187a2d224eb9d417eb893d6b42739c
   ... and masked =            90187a2d224eb9d417eb893d6b42731c
   Tag =                       404099c2587f64979f21826706d497d5
   Initial counter =           404099c2587f64979f21826706d497d5
   Result (28 bytes) =         8dbeb9f7255bf5769dd56692404099c2
                               587f64979f21826706d497d5


   Plaintext (15 bytes) =      21702de0de18baa9c9596291b08466
   AAD (25 bytes) =            f37de21c7ff901cfe8a69615a93fdf7a
                               98cad481796245709f
   Key =                       9745b3d1ae06556fb6aa7890bebc18fe
                               6b3db4da3d57aa94842b9803a96e07fb
   Nonce =                     6de71860f762ebfbd08284e4
   Record authentication key = 27c2959ed4daea3b1f52e849478de376
   Record encryption key =     307a38a5a6cf231c0a9af3b527f23a62
                               e9a6ff09aff8ae669f760153e864fc93
   POLYVAL input =             f37de21c7ff901cfe8a69615a93fdf7a
                               98cad481796245709f00000000000000
                               21702de0de18baa9c9596291b0846600
                               c8000000000000007800000000000000
   POLYVAL result =            c4fa5e5b713853703bcf8e6424505fa5
   POLYVAL result XOR nonce =  a91d463b865ab88beb4d0a8024505fa5
   ... and masked =            a91d463b865ab88beb4d0a8024505f25
   Tag =                       b3080d28f6ebb5d3648ce97bd5ba67fd
   Initial counter =           b3080d28f6ebb5d3648ce97bd5ba67fd
   Result (31 bytes) =         793576dfa5c0f88729a7ed3c2f1bffb3
                               080d28f6ebb5d3648ce97bd5ba67fd


   Plaintext (18 bytes) =      b202b370ef9768ec6561c4fe6b7e7296
                               fa85
   AAD (30 bytes) =            9c2159058b1f0fe91433a5bdc20e214e
                               ab7fecef4454a10ef0657df21ac7



Gueron, et al.                Informational                    [Page 39]
 
RFC 8452                       AES-GCM-SIV                    April 2019


   Key =                       b18853f68d833640e42a3c02c25b6486
                               9e146d7b233987bddfc240871d7576f7
   Nonce =                     028ec6eb5ea7e298342a94d4
   Record authentication key = 670b98154076ddb59b7a9137d0dcc0f0
   Record encryption key =     78116d78507fbe69d4a820c350f55c7c
                               b36c3c9287df0e9614b142b76a587c3f
   POLYVAL input =             9c2159058b1f0fe91433a5bdc20e214e
                               ab7fecef4454a10ef0657df21ac70000
                               b202b370ef9768ec6561c4fe6b7e7296
                               fa850000000000000000000000000000
                               f0000000000000009000000000000000
   POLYVAL result =            4e4108f09f41d797dc9256f8da8d58c7
   POLYVAL result XOR nonce =  4ccfce1bc1e6350fe8b8c22cda8d58c7
   ... and masked =            4ccfce1bc1e6350fe8b8c22cda8d5847
   Tag =                       454fc2a154fea91f8363a39fec7d0a49
   Initial counter =           454fc2a154fea91f8363a39fec7d0ac9
   Result (34 bytes) =         857e16a64915a787637687db4a951963
                               5cdd454fc2a154fea91f8363a39fec7d
                               0a49


   Plaintext (21 bytes) =      ced532ce4159b035277d4dfbb7db6296
                               8b13cd4eec
   AAD (35 bytes) =            734320ccc9d9bbbb19cb81b2af4ecbc3
                               e72834321f7aa0f70b7282b4f33df23f
                               167541
   Key =                       3c535de192eaed3822a2fbbe2ca9dfc8
                               8255e14a661b8aa82cc54236093bbc23
   Nonce =                     688089e55540db1872504e1c
   Record authentication key = cb8c3aa3f8dbaeb4b28a3e86ff6625f8
   Record encryption key =     02426ce1aa3ab31313b0848469a1b5fc
                               6c9af9602600b195b04ad407026bc06d
   POLYVAL input =             734320ccc9d9bbbb19cb81b2af4ecbc3
                               e72834321f7aa0f70b7282b4f33df23f
                               16754100000000000000000000000000
                               ced532ce4159b035277d4dfbb7db6296
                               8b13cd4eec0000000000000000000000
                               1801000000000000a800000000000000
   POLYVAL result =            ffd503c7dd712eb3791b7114b17bb0cf
   POLYVAL result XOR nonce =  97558a228831f5ab0b4b3f08b17bb0cf
   ... and masked =            97558a228831f5ab0b4b3f08b17bb04f
   Tag =                       9d6c7029675b89eaf4ba1ded1a286594
   Initial counter =           9d6c7029675b89eaf4ba1ded1a286594
   Result (37 bytes) =         626660c26ea6612fb17ad91e8e767639
                               edd6c9faee9d6c7029675b89eaf4ba1d
                               ed1a286594





Gueron, et al.                Informational                    [Page 40]
 
RFC 8452                       AES-GCM-SIV                    April 2019


C.3.  Counter Wrap Tests

   The tests in this section use AEAD_AES_256_GCM_SIV and are crafted to
   test correct wrapping of the block counter.

   Plaintext (32 bytes) =      00000000000000000000000000000000
                               4db923dc793ee6497c76dcc03a98e108
   AAD (0 bytes) =
   Key =                       00000000000000000000000000000000
                               00000000000000000000000000000000
   Nonce =                     000000000000000000000000
   Record authentication key = dc95c078a24089895275f3d86b4fb868
   Record encryption key =     779b38d15bffb63d39d6e9ae76a9b2f3
                               75d11b0e3a68c422845c7d4690fa594f
   POLYVAL input =             00000000000000000000000000000000
                               4db923dc793ee6497c76dcc03a98e108
                               00000000000000000001000000000000
   POLYVAL result =            7367cdb411b730128dd56e8edc0eff56
   POLYVAL result XOR nonce =  7367cdb411b730128dd56e8edc0eff56
   ... and masked =            7367cdb411b730128dd56e8edc0eff56
   Tag =                       ffffffff000000000000000000000000
   Initial counter =           ffffffff000000000000000000000080
   Result (48 bytes) =         f3f80f2cf0cb2dd9c5984fcda908456c
                               c537703b5ba70324a6793a7bf218d3ea
                               ffffffff000000000000000000000000


   Plaintext (24 bytes) =      eb3640277c7ffd1303c7a542d02d3e4c
                               0000000000000000
   AAD (0 bytes) =
   Key =                       00000000000000000000000000000000
                               00000000000000000000000000000000
   Nonce =                     000000000000000000000000
   Record authentication key = dc95c078a24089895275f3d86b4fb868
   Record encryption key =     779b38d15bffb63d39d6e9ae76a9b2f3
                               75d11b0e3a68c422845c7d4690fa594f
   POLYVAL input =             eb3640277c7ffd1303c7a542d02d3e4c
                               00000000000000000000000000000000
                               0000000000000000c000000000000000
   POLYVAL result =            7367cdb411b730128dd56e8edc0eff56
   POLYVAL result XOR nonce =  7367cdb411b730128dd56e8edc0eff56
   ... and masked =            7367cdb411b730128dd56e8edc0eff56
   Tag =                       ffffffff000000000000000000000000
   Initial counter =           ffffffff000000000000000000000080
   Result (40 bytes) =         18ce4f0b8cb4d0cac65fea8f79257b20
                               888e53e72299e56dffffffff00000000
                               0000000000000000
"""

def keep_line(l):
  """Determines whether a line is text or should be dropped,
     because it is a header. This is heuristic and may be changed
     between versions."""
  if l[:3] != "   ":
    return False
  elif all(c == " " for c in l[max(0, l.find("=") + 1):31]):
    return True
  else:
    return False

def get_test_vectors_ref():
  return "RFC 8452"

def get_test_vectors(txt=None):
  """Returns test vectors from RFC 8452."""
  if txt is None:
    txt = raw
  lines = raw.split("\n")

  lines = list(filter(keep_line, lines))

  # Make vectors
  test_vectors = []
  v = {}
  val = ""
  for l in lines[::-1]:
     if l.find("=") >= 0:
        key, t = l.split("=")
        key = key.split("(")[0].strip()
        val = t.strip() + val
        v[key] = val
        val = ""
        if key == "Plaintext":
          if v:
            # Check tag
            res = v["Result"]
            ct = res[:len(v["Plaintext"])]
            tag = res[len(v["Plaintext"]):]
            assert tag == v["Tag"]
            v["Result"] = ct
            test_vectors.append(v)
          v = {}
          val = ""
     elif l.startswith(" " * 20):
       val = l.strip() + val

  if v: test_vectors.append(v)
  return test_vectors[::-1]

def test(txt: str = None):
  cnt = 0
  for test in get_test_vectors(txt):
    E = aes_gcm_siv.AesGcmSiv(bytes.fromhex(test["Key"]))
    n = bytes.fromhex(test["Nonce"])
    a = bytes.fromhex(test["AAD"])
    m = bytes.fromhex(test["Plaintext"])
    c,t = E.encrypt(n, a, m)
    if c.hex() != test["Result"] or t.hex() != test["Tag"]:
      print(test)
      print(c.hex(), test["Result"])
      print(t.hex(), test["Result"])
      assert False
    else:
      cnt += 1
  print("Test done")
  print("Number of tests: ", cnt)
  assert cnt >= 50

if __name__ == "__main__":
  test()

