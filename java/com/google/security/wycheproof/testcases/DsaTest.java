/**
 * @license
 * Copyright 2016 Google Inc. All rights reserved.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// TODO(bleichen):
// - add tests for signature malleability and ASN parsing.
// - add tests for SHA1WithDSA with wrong key
// - add tests for "alternative" algorithm names
// - convert tests for deterministic DSA variants.
//   Deterministic DSA has a few new drawbacks:
//     * implementations flaws that generate k incorrectly can leak
//       the key if multiple implementations (e.g. one correct one incorrect)
//       is used.
//     * timing attacks are more serious if the attacker can ask for the same
//       signature multiple times, since this allows to get more accurate timings.
package com.google.security.wycheproof;

import com.google.security.wycheproof.WycheproofRunner.ProviderType;
import com.google.security.wycheproof.WycheproofRunner.SlowTest;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.spec.DSAPrivateKeySpec;
import java.security.spec.DSAPublicKeySpec;
import java.util.Arrays;
import javax.crypto.Cipher;
import junit.framework.TestCase;

/**
 * Tests DSA against invalid signatures. The motivation for this test is the DSA implementation in
 * gpg4browsers. This implementation accepts signatures with r=1 and s=0 as valid.
 *
 * @author bleichen@google.com (Daniel Bleichenbacher)
 */
public class DsaTest extends TestCase {
  static final String MESSAGE = "Hello";

  static final DSAPrivateKeySpec privateKey1 =
      new DSAPrivateKeySpec(
          // x
          new BigInteger("15382583218386677486843706921635237927801862255437148328980464126979"),
          // p
          new BigInteger(
              "181118486631420055711787706248812146965913392568235070235446058914"
                  + "1170708161715231951918020125044061516370042605439640379530343556"
                  + "4101919053459832890139496933938670005799610981765220283775567361"
                  + "4836626483403394052203488713085936276470766894079318754834062443"
                  + "1033792580942743268186462355159813630244169054658542719322425431"
                  + "4088256212718983105131138772434658820375111735710449331518776858"
                  + "7867938758654181244292694091187568128410190746310049564097068770"
                  + "8161261634790060655580211122402292101772553741704724263582994973"
                  + "9109274666495826205002104010355456981211025738812433088757102520"
                  + "562459649777989718122219159982614304359"),
          // q
          new BigInteger("19689526866605154788513693571065914024068069442724893395618704484701"),
          // g
          new BigInteger(
              "2859278237642201956931085611015389087970918161297522023542900348"
                  + "0877180630984239764282523693409675060100542360520959501692726128"
                  + "3149190229583566074777557293475747419473934711587072321756053067"
                  + "2532404847508798651915566434553729839971841903983916294692452760"
                  + "2490198571084091890169933809199002313226100830607842692992570749"
                  + "0504363602970812128803790973955960534785317485341020833424202774"
                  + "0275688698461842637641566056165699733710043802697192696426360843"
                  + "1736206792141319514001488556117408586108219135730880594044593648"
                  + "9237302749293603778933701187571075920849848690861126195402696457"
                  + "4111219599568903257472567764789616958430"));

  static final DSAPublicKeySpec publicKey1 =
      new DSAPublicKeySpec(
          new BigInteger(
              "3846308446317351758462473207111709291533523711306097971550086650"
                  + "2577333637930103311673872185522385807498738696446063139653693222"
                  + "3528823234976869516765207838304932337200968476150071617737755913"
                  + "3181601169463467065599372409821150709457431511200322947508290005"
                  + "1780020974429072640276810306302799924668893998032630777409440831"
                  + "4314588994475223696460940116068336991199969153649625334724122468"
                  + "7497038281983541563359385775312520539189474547346202842754393945"
                  + "8755803223951078082197762886933401284142487322057236814878262166"
                  + "5072306622943221607031324846468109901964841479558565694763440972"
                  + "5447389416166053148132419345627682740529"),
          privateKey1.getP(),
          privateKey1.getQ(),
          privateKey1.getG());

  // Signatures for Key1.
  static final String[] VALID_SIGNATURES = {
    "303d021c1e41b479ad576905b960fe14eadb91b0ccf34843dab916173bb8c9cd"
        + "021d00ade65988d237d30f9ef41dd424a4e1c8f16967cf3365813fe8786236",
  };

  static final String[] INVALID_SIGNATURES = {
    // Signatures with special case values for r and s. E.g. r=1, s=0 are values that can lead to
    // forgeries if the DSA implementation does not check boundaries and computes s^(-1) == 0.
    "3022020100021dff450969597a870820211805983688387a10cd4dcc451a7f3f432a96a3",
    "3006020100020101",
    "30060201000201ff",
    "3022020100021d00baf696a68578f7dfdee7fa67c977c785ef32b233bae580c0bcd5695d",
    "3022020100021d00baf696a68578f7dfdee7fa67c977c785ef32b233bae580c0bcd5695e",
    "3022020100021d0100000000000000000000000000000000000000000000000000000000",
    "3082010802010002820101008f7935d9b9aae9bfabed887acf4951b6f32ec59e"
        + "3baf3718e8eac4961f3efd3606e74351a9c4183339b809e7c2ae1c539ba7475b"
        + "85d011adb8b47987754984695cac0e8f14b3360828a22ffa27110a3d62a99345"
        + "3409a0fe696c4658f84bdd20819c3709a01057b195adcd00233dba5484b6291f"
        + "9d648ef883448677979cec04b434a6ac2e75e9985de23db0292fc1118c9ffa9d"
        + "8181e7338db792b730d7b9e349592f68099872153915ea3d6b8b4653c633458f"
        + "803b32a4c2e0f27290256e4e3f8a3b0838a1c450e4e18c1a29a37ddf5ea143de"
        + "4b66ff04903ed5cf1623e158d487c608e97f211cd81dca23cb6e380765f822e3"
        + "42be484c05763939601cd667",
    "3008020100090380fe01",
    "3022020101021dff450969597a870820211805983688387a10cd4dcc451a7f3f432a96a3",
    "3006020101020101",
    "30060201010201ff",
    "3022020101021d00baf696a68578f7dfdee7fa67c977c785ef32b233bae580c0bcd5695d",
    "3022020101021d00baf696a68578f7dfdee7fa67c977c785ef32b233bae580c0bcd5695e",
    "3022020101021d0100000000000000000000000000000000000000000000000000000000",
    "3082010802010102820101008f7935d9b9aae9bfabed887acf4951b6f32ec59e"
        + "3baf3718e8eac4961f3efd3606e74351a9c4183339b809e7c2ae1c539ba7475b"
        + "85d011adb8b47987754984695cac0e8f14b3360828a22ffa27110a3d62a99345"
        + "3409a0fe696c4658f84bdd20819c3709a01057b195adcd00233dba5484b6291f"
        + "9d648ef883448677979cec04b434a6ac2e75e9985de23db0292fc1118c9ffa9d"
        + "8181e7338db792b730d7b9e349592f68099872153915ea3d6b8b4653c633458f"
        + "803b32a4c2e0f27290256e4e3f8a3b0838a1c450e4e18c1a29a37ddf5ea143de"
        + "4b66ff04903ed5cf1623e158d487c608e97f211cd81dca23cb6e380765f822e3"
        + "42be484c05763939601cd667",
    "3008020101090380fe01",
    "30220201ff021dff450969597a870820211805983688387a10cd4dcc451a7f3f432a96a3",
    "30060201ff020101",
    "30060201ff0201ff",
    "30220201ff021d00baf696a68578f7dfdee7fa67c977c785ef32b233bae580c0bcd5695d",
    "30220201ff021d00baf696a68578f7dfdee7fa67c977c785ef32b233bae580c0bcd5695e",
    "30220201ff021d0100000000000000000000000000000000000000000000000000000000",
    "308201080201ff02820101008f7935d9b9aae9bfabed887acf4951b6f32ec59e"
        + "3baf3718e8eac4961f3efd3606e74351a9c4183339b809e7c2ae1c539ba7475b"
        + "85d011adb8b47987754984695cac0e8f14b3360828a22ffa27110a3d62a99345"
        + "3409a0fe696c4658f84bdd20819c3709a01057b195adcd00233dba5484b6291f"
        + "9d648ef883448677979cec04b434a6ac2e75e9985de23db0292fc1118c9ffa9d"
        + "8181e7338db792b730d7b9e349592f68099872153915ea3d6b8b4653c633458f"
        + "803b32a4c2e0f27290256e4e3f8a3b0838a1c450e4e18c1a29a37ddf5ea143de"
        + "4b66ff04903ed5cf1623e158d487c608e97f211cd81dca23cb6e380765f822e3"
        + "42be484c05763939601cd667",
    "30080201ff090380fe01",
    "303e021d00baf696a68578f7dfdee7fa67c977c785ef32b233bae580c0bcd569"
        + "5d021dff450969597a870820211805983688387a10cd4dcc451a7f3f432a96a3",
    "3022021d00baf696a68578f7dfdee7fa67c977c785ef32b233bae580c0bcd5695d020100",
    "3022021d00baf696a68578f7dfdee7fa67c977c785ef32b233bae580c0bcd5695d020101",
    "3022021d00baf696a68578f7dfdee7fa67c977c785ef32b233bae580c0bcd5695d0201ff",
    "303e021d00baf696a68578f7dfdee7fa67c977c785ef32b233bae580c0bcd569"
        + "5d021d00baf696a68578f7dfdee7fa67c977c785ef32b233bae580c0bcd5695d",
    "303e021d00baf696a68578f7dfdee7fa67c977c785ef32b233bae580c0bcd569"
        + "5d021d00baf696a68578f7dfdee7fa67c977c785ef32b233bae580c0bcd5695e",
    "303e021d00baf696a68578f7dfdee7fa67c977c785ef32b233bae580c0bcd569"
        + "5d021d0100000000000000000000000000000000000000000000000000000000",
    "30820124021d00baf696a68578f7dfdee7fa67c977c785ef32b233bae580c0bc"
        + "d5695d02820101008f7935d9b9aae9bfabed887acf4951b6f32ec59e3baf3718"
        + "e8eac4961f3efd3606e74351a9c4183339b809e7c2ae1c539ba7475b85d011ad"
        + "b8b47987754984695cac0e8f14b3360828a22ffa27110a3d62a993453409a0fe"
        + "696c4658f84bdd20819c3709a01057b195adcd00233dba5484b6291f9d648ef8"
        + "83448677979cec04b434a6ac2e75e9985de23db0292fc1118c9ffa9d8181e733"
        + "8db792b730d7b9e349592f68099872153915ea3d6b8b4653c633458f803b32a4"
        + "c2e0f27290256e4e3f8a3b0838a1c450e4e18c1a29a37ddf5ea143de4b66ff04"
        + "903ed5cf1623e158d487c608e97f211cd81dca23cb6e380765f822e342be484c"
        + "05763939601cd667",
    "3024021d00baf696a68578f7dfdee7fa67c977c785ef32b233bae580c0bcd5695d090380fe01",
    "303e021d00baf696a68578f7dfdee7fa67c977c785ef32b233bae580c0bcd569"
        + "5e021dff450969597a870820211805983688387a10cd4dcc451a7f3f432a96a3",
    "3022021d00baf696a68578f7dfdee7fa67c977c785ef32b233bae580c0bcd5695e020100",
    "3022021d00baf696a68578f7dfdee7fa67c977c785ef32b233bae580c0bcd5695e020101",
    "3022021d00baf696a68578f7dfdee7fa67c977c785ef32b233bae580c0bcd5695e0201ff",
    "303e021d00baf696a68578f7dfdee7fa67c977c785ef32b233bae580c0bcd569"
        + "5e021d00baf696a68578f7dfdee7fa67c977c785ef32b233bae580c0bcd5695d",
    "303e021d00baf696a68578f7dfdee7fa67c977c785ef32b233bae580c0bcd569"
        + "5e021d00baf696a68578f7dfdee7fa67c977c785ef32b233bae580c0bcd5695e",
    "303e021d00baf696a68578f7dfdee7fa67c977c785ef32b233bae580c0bcd569"
        + "5e021d0100000000000000000000000000000000000000000000000000000000",
    "30820124021d00baf696a68578f7dfdee7fa67c977c785ef32b233bae580c0bc"
        + "d5695e02820101008f7935d9b9aae9bfabed887acf4951b6f32ec59e3baf3718"
        + "e8eac4961f3efd3606e74351a9c4183339b809e7c2ae1c539ba7475b85d011ad"
        + "b8b47987754984695cac0e8f14b3360828a22ffa27110a3d62a993453409a0fe"
        + "696c4658f84bdd20819c3709a01057b195adcd00233dba5484b6291f9d648ef8"
        + "83448677979cec04b434a6ac2e75e9985de23db0292fc1118c9ffa9d8181e733"
        + "8db792b730d7b9e349592f68099872153915ea3d6b8b4653c633458f803b32a4"
        + "c2e0f27290256e4e3f8a3b0838a1c450e4e18c1a29a37ddf5ea143de4b66ff04"
        + "903ed5cf1623e158d487c608e97f211cd81dca23cb6e380765f822e342be484c"
        + "05763939601cd667",
    "3024021d00baf696a68578f7dfdee7fa67c977c785ef32b233bae580c0bcd5695e090380fe01",
    "303e021d01000000000000000000000000000000000000000000000000000000"
        + "00021dff450969597a870820211805983688387a10cd4dcc451a7f3f432a96a3",
    "3022021d0100000000000000000000000000000000000000000000000000000000020100",
    "3022021d0100000000000000000000000000000000000000000000000000000000020101",
    "3022021d01000000000000000000000000000000000000000000000000000000000201ff",
    "303e021d01000000000000000000000000000000000000000000000000000000"
        + "00021d00baf696a68578f7dfdee7fa67c977c785ef32b233bae580c0bcd5695d",
    "303e021d01000000000000000000000000000000000000000000000000000000"
        + "00021d00baf696a68578f7dfdee7fa67c977c785ef32b233bae580c0bcd5695e",
    "303e021d01000000000000000000000000000000000000000000000000000000"
        + "00021d0100000000000000000000000000000000000000000000000000000000",
    "30820124021d0100000000000000000000000000000000000000000000000000"
        + "00000002820101008f7935d9b9aae9bfabed887acf4951b6f32ec59e3baf3718"
        + "e8eac4961f3efd3606e74351a9c4183339b809e7c2ae1c539ba7475b85d011ad"
        + "b8b47987754984695cac0e8f14b3360828a22ffa27110a3d62a993453409a0fe"
        + "696c4658f84bdd20819c3709a01057b195adcd00233dba5484b6291f9d648ef8"
        + "83448677979cec04b434a6ac2e75e9985de23db0292fc1118c9ffa9d8181e733"
        + "8db792b730d7b9e349592f68099872153915ea3d6b8b4653c633458f803b32a4"
        + "c2e0f27290256e4e3f8a3b0838a1c450e4e18c1a29a37ddf5ea143de4b66ff04"
        + "903ed5cf1623e158d487c608e97f211cd81dca23cb6e380765f822e342be484c"
        + "05763939601cd667",
    "3024021d0100000000000000000000000000000000000000000000000000000000090380fe01",
    "3082012402820101008f7935d9b9aae9bfabed887acf4951b6f32ec59e3baf37"
        + "18e8eac4961f3efd3606e74351a9c4183339b809e7c2ae1c539ba7475b85d011"
        + "adb8b47987754984695cac0e8f14b3360828a22ffa27110a3d62a993453409a0"
        + "fe696c4658f84bdd20819c3709a01057b195adcd00233dba5484b6291f9d648e"
        + "f883448677979cec04b434a6ac2e75e9985de23db0292fc1118c9ffa9d8181e7"
        + "338db792b730d7b9e349592f68099872153915ea3d6b8b4653c633458f803b32"
        + "a4c2e0f27290256e4e3f8a3b0838a1c450e4e18c1a29a37ddf5ea143de4b66ff"
        + "04903ed5cf1623e158d487c608e97f211cd81dca23cb6e380765f822e342be48"
        + "4c05763939601cd667021dff450969597a870820211805983688387a10cd4dcc"
        + "451a7f3f432a96a3",
    "3082010802820101008f7935d9b9aae9bfabed887acf4951b6f32ec59e3baf37"
        + "18e8eac4961f3efd3606e74351a9c4183339b809e7c2ae1c539ba7475b85d011"
        + "adb8b47987754984695cac0e8f14b3360828a22ffa27110a3d62a993453409a0"
        + "fe696c4658f84bdd20819c3709a01057b195adcd00233dba5484b6291f9d648e"
        + "f883448677979cec04b434a6ac2e75e9985de23db0292fc1118c9ffa9d8181e7"
        + "338db792b730d7b9e349592f68099872153915ea3d6b8b4653c633458f803b32"
        + "a4c2e0f27290256e4e3f8a3b0838a1c450e4e18c1a29a37ddf5ea143de4b66ff"
        + "04903ed5cf1623e158d487c608e97f211cd81dca23cb6e380765f822e342be48"
        + "4c05763939601cd667020100",
    "3082010802820101008f7935d9b9aae9bfabed887acf4951b6f32ec59e3baf37"
        + "18e8eac4961f3efd3606e74351a9c4183339b809e7c2ae1c539ba7475b85d011"
        + "adb8b47987754984695cac0e8f14b3360828a22ffa27110a3d62a993453409a0"
        + "fe696c4658f84bdd20819c3709a01057b195adcd00233dba5484b6291f9d648e"
        + "f883448677979cec04b434a6ac2e75e9985de23db0292fc1118c9ffa9d8181e7"
        + "338db792b730d7b9e349592f68099872153915ea3d6b8b4653c633458f803b32"
        + "a4c2e0f27290256e4e3f8a3b0838a1c450e4e18c1a29a37ddf5ea143de4b66ff"
        + "04903ed5cf1623e158d487c608e97f211cd81dca23cb6e380765f822e342be48"
        + "4c05763939601cd667020101",
    "3082010802820101008f7935d9b9aae9bfabed887acf4951b6f32ec59e3baf37"
        + "18e8eac4961f3efd3606e74351a9c4183339b809e7c2ae1c539ba7475b85d011"
        + "adb8b47987754984695cac0e8f14b3360828a22ffa27110a3d62a993453409a0"
        + "fe696c4658f84bdd20819c3709a01057b195adcd00233dba5484b6291f9d648e"
        + "f883448677979cec04b434a6ac2e75e9985de23db0292fc1118c9ffa9d8181e7"
        + "338db792b730d7b9e349592f68099872153915ea3d6b8b4653c633458f803b32"
        + "a4c2e0f27290256e4e3f8a3b0838a1c450e4e18c1a29a37ddf5ea143de4b66ff"
        + "04903ed5cf1623e158d487c608e97f211cd81dca23cb6e380765f822e342be48"
        + "4c05763939601cd6670201ff",
    "3082012402820101008f7935d9b9aae9bfabed887acf4951b6f32ec59e3baf37"
        + "18e8eac4961f3efd3606e74351a9c4183339b809e7c2ae1c539ba7475b85d011"
        + "adb8b47987754984695cac0e8f14b3360828a22ffa27110a3d62a993453409a0"
        + "fe696c4658f84bdd20819c3709a01057b195adcd00233dba5484b6291f9d648e"
        + "f883448677979cec04b434a6ac2e75e9985de23db0292fc1118c9ffa9d8181e7"
        + "338db792b730d7b9e349592f68099872153915ea3d6b8b4653c633458f803b32"
        + "a4c2e0f27290256e4e3f8a3b0838a1c450e4e18c1a29a37ddf5ea143de4b66ff"
        + "04903ed5cf1623e158d487c608e97f211cd81dca23cb6e380765f822e342be48"
        + "4c05763939601cd667021d00baf696a68578f7dfdee7fa67c977c785ef32b233"
        + "bae580c0bcd5695d",
    "3082012402820101008f7935d9b9aae9bfabed887acf4951b6f32ec59e3baf37"
        + "18e8eac4961f3efd3606e74351a9c4183339b809e7c2ae1c539ba7475b85d011"
        + "adb8b47987754984695cac0e8f14b3360828a22ffa27110a3d62a993453409a0"
        + "fe696c4658f84bdd20819c3709a01057b195adcd00233dba5484b6291f9d648e"
        + "f883448677979cec04b434a6ac2e75e9985de23db0292fc1118c9ffa9d8181e7"
        + "338db792b730d7b9e349592f68099872153915ea3d6b8b4653c633458f803b32"
        + "a4c2e0f27290256e4e3f8a3b0838a1c450e4e18c1a29a37ddf5ea143de4b66ff"
        + "04903ed5cf1623e158d487c608e97f211cd81dca23cb6e380765f822e342be48"
        + "4c05763939601cd667021d00baf696a68578f7dfdee7fa67c977c785ef32b233"
        + "bae580c0bcd5695e",
    "3082012402820101008f7935d9b9aae9bfabed887acf4951b6f32ec59e3baf37"
        + "18e8eac4961f3efd3606e74351a9c4183339b809e7c2ae1c539ba7475b85d011"
        + "adb8b47987754984695cac0e8f14b3360828a22ffa27110a3d62a993453409a0"
        + "fe696c4658f84bdd20819c3709a01057b195adcd00233dba5484b6291f9d648e"
        + "f883448677979cec04b434a6ac2e75e9985de23db0292fc1118c9ffa9d8181e7"
        + "338db792b730d7b9e349592f68099872153915ea3d6b8b4653c633458f803b32"
        + "a4c2e0f27290256e4e3f8a3b0838a1c450e4e18c1a29a37ddf5ea143de4b66ff"
        + "04903ed5cf1623e158d487c608e97f211cd81dca23cb6e380765f822e342be48"
        + "4c05763939601cd667021d010000000000000000000000000000000000000000"
        + "0000000000000000",
    "3082020a02820101008f7935d9b9aae9bfabed887acf4951b6f32ec59e3baf37"
        + "18e8eac4961f3efd3606e74351a9c4183339b809e7c2ae1c539ba7475b85d011"
        + "adb8b47987754984695cac0e8f14b3360828a22ffa27110a3d62a993453409a0"
        + "fe696c4658f84bdd20819c3709a01057b195adcd00233dba5484b6291f9d648e"
        + "f883448677979cec04b434a6ac2e75e9985de23db0292fc1118c9ffa9d8181e7"
        + "338db792b730d7b9e349592f68099872153915ea3d6b8b4653c633458f803b32"
        + "a4c2e0f27290256e4e3f8a3b0838a1c450e4e18c1a29a37ddf5ea143de4b66ff"
        + "04903ed5cf1623e158d487c608e97f211cd81dca23cb6e380765f822e342be48"
        + "4c05763939601cd66702820101008f7935d9b9aae9bfabed887acf4951b6f32e"
        + "c59e3baf3718e8eac4961f3efd3606e74351a9c4183339b809e7c2ae1c539ba7"
        + "475b85d011adb8b47987754984695cac0e8f14b3360828a22ffa27110a3d62a9"
        + "93453409a0fe696c4658f84bdd20819c3709a01057b195adcd00233dba5484b6"
        + "291f9d648ef883448677979cec04b434a6ac2e75e9985de23db0292fc1118c9f"
        + "fa9d8181e7338db792b730d7b9e349592f68099872153915ea3d6b8b4653c633"
        + "458f803b32a4c2e0f27290256e4e3f8a3b0838a1c450e4e18c1a29a37ddf5ea1"
        + "43de4b66ff04903ed5cf1623e158d487c608e97f211cd81dca23cb6e380765f8"
        + "22e342be484c05763939601cd667",
    "3082010a02820101008f7935d9b9aae9bfabed887acf4951b6f32ec59e3baf37"
        + "18e8eac4961f3efd3606e74351a9c4183339b809e7c2ae1c539ba7475b85d011"
        + "adb8b47987754984695cac0e8f14b3360828a22ffa27110a3d62a993453409a0"
        + "fe696c4658f84bdd20819c3709a01057b195adcd00233dba5484b6291f9d648e"
        + "f883448677979cec04b434a6ac2e75e9985de23db0292fc1118c9ffa9d8181e7"
        + "338db792b730d7b9e349592f68099872153915ea3d6b8b4653c633458f803b32"
        + "a4c2e0f27290256e4e3f8a3b0838a1c450e4e18c1a29a37ddf5ea143de4b66ff"
        + "04903ed5cf1623e158d487c608e97f211cd81dca23cb6e380765f822e342be48"
        + "4c05763939601cd667090380fe01",
    "3024090380fe01021dff450969597a870820211805983688387a10cd4dcc451a7f3f432a96a3",
    "3008090380fe01020100",
    "3008090380fe01020101",
    "3008090380fe010201ff",
    "3024090380fe01021d00baf696a68578f7dfdee7fa67c977c785ef32b233bae580c0bcd5695d",
    "3024090380fe01021d00baf696a68578f7dfdee7fa67c977c785ef32b233bae580c0bcd5695e",
    "3024090380fe01021d0100000000000000000000000000000000000000000000000000000000",
    "3082010a090380fe0102820101008f7935d9b9aae9bfabed887acf4951b6f32e"
        + "c59e3baf3718e8eac4961f3efd3606e74351a9c4183339b809e7c2ae1c539ba7"
        + "475b85d011adb8b47987754984695cac0e8f14b3360828a22ffa27110a3d62a9"
        + "93453409a0fe696c4658f84bdd20819c3709a01057b195adcd00233dba5484b6"
        + "291f9d648ef883448677979cec04b434a6ac2e75e9985de23db0292fc1118c9f"
        + "fa9d8181e7338db792b730d7b9e349592f68099872153915ea3d6b8b4653c633"
        + "458f803b32a4c2e0f27290256e4e3f8a3b0838a1c450e4e18c1a29a37ddf5ea1"
        + "43de4b66ff04903ed5cf1623e158d487c608e97f211cd81dca23cb6e380765f8"
        + "22e342be484c05763939601cd667",
    "300a090380fe01090380fe01",
  };

  public void testVectors(
      String[] signatures,
      DSAPublicKeySpec key,
      String message,
      String algorithm,
      String signatureType,
      boolean isValid)
      throws Exception {
    byte[] messageBytes = "Hello".getBytes("UTF-8");
    Signature verifier = Signature.getInstance(algorithm);
    KeyFactory kf = KeyFactory.getInstance("DSA");
    PublicKey pub = kf.generatePublic(key);
    int errors = 0;
    for (String signature : signatures) {
      byte[] signatureBytes = TestUtil.hexToBytes(signature);
      verifier.initVerify(pub);
      verifier.update(messageBytes);
      boolean verified = false;
      try {
        verified = verifier.verify(signatureBytes);
      } catch (SignatureException ex) {
        // verify can throw SignatureExceptions if the signature is malformed.
        // We don't flag these cases and simply consider the signature as invalid.
        verified = false;
      } catch (Exception ex) {
        // Other exceptions indicate some internal error, e.g. careless ASN parsing.
        // We count these as errors.
        System.out.println(signatureType + ":" + signature + " throws:" + ex.toString());
        errors++;
        continue;
      }
      if (isValid && !verified) {
        System.out.println(signatureType + " was not verified:" + signature);
        errors++;
      } else if (!isValid && verified) {
        System.out.println(signatureType + " was verified:" + signature);
        errors++;
      }
    }
    assertEquals(0, errors);
  }

  public void testValidSignatures() throws Exception {
    testVectors(
        VALID_SIGNATURES, publicKey1, "Hello", "SHA224WithDSA", "Valid DSA signature", true);
  }

  public void testInvalidSignatures() throws Exception {
    testVectors(
        INVALID_SIGNATURES, publicKey1, "Hello", "SHA224WithDSA", "Invalid DSA signature", false);
  }

  // Extract the integer r from a DSA signature.
  // This method implicitely assumes that the DSA signature is DER encoded.
  BigInteger extractR(byte[] signature) throws Exception {
    int lengthR = signature[3];
    return new BigInteger(Arrays.copyOfRange(signature, 4, 4 + lengthR));
  }

  BigInteger extractS(byte[] signature) throws Exception {
    int lengthR = signature[3];
    int startS = 4 + lengthR;
    int lengthS = signature[startS + 1];
    return new BigInteger(Arrays.copyOfRange(signature, startS + 2, startS + 2 + lengthS));
  }

  /** Extract the k that was used to sign the signature. Validates the k if check == true. */
  BigInteger extractK(byte[] signature, BigInteger h, DSAPrivateKey priv, boolean check)
      throws Exception {
    BigInteger x = priv.getX();
    BigInteger q = priv.getParams().getQ();
    BigInteger r = extractR(signature);
    BigInteger s = extractS(signature);
    BigInteger k = x.multiply(r).add(h).multiply(s.modInverse(q)).mod(q);
    if (check) {
      BigInteger p = priv.getParams().getP();
      BigInteger g = priv.getParams().getG();
      BigInteger r2 = g.modPow(k, p).mod(q);
      assertEquals(r.toString(), r2.toString());
    }
    return k;
  }

  /**
   * Providers that implement SHA1WithDSA but not at least SHA256WithDSA are outdated and should be
   * avoided even if DSA is currently not used in a project. Such providers promote using a weak
   * signature scheme. It can also "inspire" developers to use invalid schemes such as SHA1WithDSA
   * together with 2048-bit key. Such invalid use cases are often untested and can have serious
   * flaws. For example the SUN provider leaked the private keys with 3 to 5 signatures in such
   * instances.
   */
  public void testOutdatedProvider() throws Exception {
    try {
      Signature sig = Signature.getInstance("SHA1WithDSA");
      try {
        Signature.getInstance("SHA256WithDSA");
      } catch (NoSuchAlgorithmException ex) {
        fail("Provider " + sig.getProvider().getName() + " is outdated and should not be used.");
      }
    } catch (NoSuchAlgorithmException ex) {
      System.out.println("SHA1WithDSA is not supported");
    }
  }

  /**
   * This is just a test for basic functionality of DSA. The test generates a public and private
   * key, generates a signature, verifies it and prints the whole thing out. This test is useful
   * when an implementation is seriously broken.
   */
  @SlowTest(providers = {ProviderType.BOUNCY_CASTLE, ProviderType.SPONGY_CASTLE})
  public void testBasic() throws Exception {
    int keySize = 2048;
    String algorithm = "SHA256WithDSA";
    String hashAlgorithm = "SHA-256";
    String message = "Hello";

    byte[] messageBytes = message.getBytes("UTF-8");
    KeyPairGenerator generator = java.security.KeyPairGenerator.getInstance("DSA");
    generator.initialize(keySize);
    KeyPair keyPair = generator.generateKeyPair();
    DSAPublicKey pub = (DSAPublicKey) keyPair.getPublic();
    DSAPrivateKey priv = (DSAPrivateKey) keyPair.getPrivate();
    Signature signer = Signature.getInstance(algorithm);
    Signature verifier = Signature.getInstance(algorithm);
    signer.initSign(priv);
    signer.update(messageBytes);
    byte[] signature = signer.sign();
    verifier.initVerify(pub);
    verifier.update(messageBytes);
    assertTrue(verifier.verify(signature));

    // Extract some parameters.
    byte[] rawHash = MessageDigest.getInstance(hashAlgorithm).digest(messageBytes);
    DSAParams params = priv.getParams();

    // Print keys and signature, so that it can be used to generate new test vectors.
    System.out.println("Message:" + message);
    System.out.println("Hash:" + TestUtil.bytesToHex(rawHash));
    System.out.println("Params:");
    System.out.println("p:" + params.getP().toString());
    System.out.println("q:" + params.getQ().toString());
    System.out.println("g:" + params.getG().toString());
    System.out.println("Private key:");
    System.out.println("X:" + priv.getX().toString());
    System.out.println("encoded:" + TestUtil.bytesToHex(priv.getEncoded()));
    System.out.println("Public key:");
    System.out.println("Y:" + pub.getY().toString());
    System.out.println("encoded:" + TestUtil.bytesToHex(pub.getEncoded()));
    System.out.println("Signature:" + TestUtil.bytesToHex(signature));
    System.out.println("r:" + extractR(signature).toString());
    System.out.println("s:" + extractS(signature).toString());
  }

  /**
   * Checks whether the one time key k in DSA is biased. For example the SUN provider fell for this
   * test until April 2016.
   */
  public void testDsaBias() throws Exception {
    // q is close to 2/3 * 2^160.
    BigInteger q = new BigInteger("974317976835659416858874959372334979171063697271");
    BigInteger p =
        new BigInteger(
            "1106803511314772711673172950296693567629309594518393175860816428"
                + "6658764043763662129010863568011543182924292444458455864283745070"
                + "9908516713302345161980412667892373845670780253725557376379049862"
                + "4062950082444499320797079243439689601679418602390654466821968220"
                + "32212146727497041502702331623782703855119908989712161");
    BigInteger g =
        new BigInteger(
            "1057342118316953575810387190942009018497979302261477972033090351"
                + "7561815639397594841480480197745063606756857212792356354588585967"
                + "3837265237205154744016475608524531648654928648461175919672511710"
                + "4878976887505840764543501512668232945506391524642105449699321960"
                + "32410302985148400531470153936516167243072120845392903");
    BigInteger x = new BigInteger("13706102843888006547723575730792302382646994436");

    KeyFactory kf = KeyFactory.getInstance("DSA");
    DSAPrivateKey priv = (DSAPrivateKey) kf.generatePrivate(new DSAPrivateKeySpec(x, p, q, g));

    // If we make TESTS tests with a fair coin then the probability that
    // either heads or tails appears less than MINCOUNT times is less than
    // 2^{-32}.
    // I.e. 2*sum(binomial(tests,i) for i in range(mincount))*2**32 < 2**tests
    // Therefore the test below is not expected to fail unless the generation
    // of the one time keys is indeed biased.
    final int tests = 1024;
    final int mincount = 410;

    String hashAlgorithm = "SHA";
    String message = "Hello";
    byte[] messageBytes = message.getBytes("UTF-8");
    byte[] digest = MessageDigest.getInstance(hashAlgorithm).digest(messageBytes);
    BigInteger h = new BigInteger(1, digest);

    final BigInteger qHalf = q.shiftRight(1);
    Signature signer = Signature.getInstance("SHA1WithDSA");
    signer.initSign(priv);
    int countLsb = 0; // count the number of k's with msb set
    int countMsb = 0; // count the number of k's with lsb set
    for (int i = 0; i < tests; i++) {
      signer.update(messageBytes);
      byte[] signature = signer.sign();
      BigInteger k = extractK(signature, h, priv, i < 10);
      if (k.testBit(0)) {
        countLsb++;
      }
      if (k.compareTo(qHalf) == 1) {
        countMsb++;
      }
    }
    if (countLsb < mincount || countLsb > tests - mincount) {
      fail("Bias detected in the least significant bit of k:" + countLsb);
    }
    if (countMsb < mincount || countMsb > tests - mincount) {
      fail("Bias detected in the most significant bit of k:" + countMsb);
    }
  }

  /**
   * Checks whether CVE-2016-0695 has been fixed. Before the April 2016 security update, the SUN
   * provider had a serious flaw that leaked the private key with about 3-5 signatures. In
   * particular, "Sha1WithDSA" always generated 160 bit k's independently of q. Unfortunately, it is
   * easily possible to use 2048 and 3072 bit DSA keys together with SHA1WithDSA. All a user has to
   * do is to use the algorithm name "DSA" instead of "SHA256WithDSA" rsp. "SHA224WithDSA".
   *
   * <p>An algorithm to extract the key from the signatures has been described for example in the
   * paper <a href="http://www.hpl.hp.com/techreports/1999/HPL-1999-90.pdf">Lattice Attacks on
   * Digital Signature Schemes</a> by N.A. Howgrave-Graham, N.P. Smart.
   *
   * <p>This bug is the same as US-CERT: VU # 940388: GnuPG generated ElGamal signatures that leaked
   * the private key.
   */
  @SlowTest(providers = {ProviderType.BOUNCY_CASTLE, ProviderType.SPONGY_CASTLE})
  public void testBiasSha1WithDSA() throws Exception {
    String hashAlgorithm = "SHA";
    String message = "Hello";
    byte[] messageBytes = message.getBytes("UTF-8");
    byte[] digest = MessageDigest.getInstance(hashAlgorithm).digest(messageBytes);
    BigInteger h = new BigInteger(1, digest);

    KeyPairGenerator generator = java.security.KeyPairGenerator.getInstance("DSA");
    generator.initialize(2048);
    KeyPair keyPair = generator.generateKeyPair();
    DSAPrivateKey priv = (DSAPrivateKey) keyPair.getPrivate();
    Signature signer = Signature.getInstance("DSA");
    try {
      // Private key and selected algorithm by signer do not match.
      // Hence throwing an exception at this point would be the reasonable.
      signer.initSign(priv);
      signer.update(messageBytes);
      byte[] signature = signer.sign();
      BigInteger q = priv.getParams().getQ();
      BigInteger k = extractK(signature, h, priv, true);

      // Now check if k is heavily biased.
      int lengthDiff = q.bitLength() - k.bitLength();
      if (lengthDiff > 32) {
        fail(
            "Severly biased DSA signature:"
                + " len(q)="
                + q.bitLength()
                + " len(k)="
                + k.bitLength());
      }
    } catch (GeneralSecurityException ex) {
      // The key is invalid, hence getting here is reasonable.
      return;
    }
  }

  /**
   * DSA does not allow encryption. This test verifies that a provider does not implement an ad hoc
   * scheme that attempts to turn DSA into a public key encryption scheme.
   */
  @SuppressWarnings("InsecureCipherMode")
  public void testEncryptionWithDsa() throws Exception {
    try {
      Cipher cipher = Cipher.getInstance("DSA");
      fail("DSA must not be used as a cipher:" + cipher.getProvider().toString());
    } catch (NoSuchAlgorithmException ex) {
      // This is expected
    }
  }
}
