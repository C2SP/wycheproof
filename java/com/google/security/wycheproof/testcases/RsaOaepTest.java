/**
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
package com.google.security.wycheproof;


import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Checks implementations of RSA-OAEP. */

// TODO(bleichen): jdk11 adds parameters to the RSA keys.
//   RSASSA-PSS allows key with such parameters by using KeyFactory.getInstance("RSASSA-PSS").
//   Is there an equivalent algorithm name for RSA-OAEP?
// TODO(bleichen): Maybe add timing tests with long labels
// TODO(bleichen): add documentation.

@RunWith(JUnit4.class)
public class RsaOaepTest {

  /**
   * A list of potential algorithm names for RSA-OAEP.
   *
   * <p>The list contains incorrect and undefined algorithm names.
   *
   * <p>The standard algorithm names for RSA-OAEP are defined in
   * https://docs.oracle.com/en/java/javase/11/docs/specs/security/standard-names.html A good choice
   * is to use "RSA/ECB/OAEPPadding" only and specify the algorithm parameters with
   * OAEPParameterSpec.
   */
  static String[] OaepAlgorithmNames = {
    "RSA/ECB/OAEPPadding",
    "RSA/ECB/OAEPwithSHA-1andMGF1Padding",
    "RSA/ECB/OAEPwithSHA-224andMGF1Padding",
    "RSA/ECB/OAEPwithSHA-256andMGF1Padding",
    "RSA/ECB/OAEPwithSHA-384andMGF1Padding",
    "RSA/ECB/OAEPwithSHA-512andMGF1Padding",
    // Algorithm names supported by BouncyCastle.
    "RSA/None/OAEPPadding",
    "RSA/None/OAEPwithSHA-1andMGF1Padding",
    "RSA/None/OAEPwithSHA-224andMGF1Padding",
    "RSA/None/OAEPwithSHA-256andMGF1Padding",
    "RSA/None/OAEPwithSHA-384andMGF1Padding",
    "RSA/None/OAEPwithSHA-512andMGF1Padding",
    // Algorithm names possibly used by other providers.
    // They may also be just typos.
    "RSA/OAEP",
    // Incorrect algorithm names.
    "RSA/ECB/OAEPwithSHA1andMGF1Padding",
    "RSA/ECB/OAEPwithSHA224andMGF1Padding",
    "RSA/ECB/OAEPwithSHA256andMGF1Padding",
    "RSA/ECB/OAEPwithSHA384andMGF1Padding",
    "RSA/ECB/OAEPwithSHA512andMGF1Padding",
    // Uncommon hash functions
    "RSA/ECB/OAEPwithSHA-512/224andMGF1Padding",
    "RSA/ECB/OAEPwithSHA-512/256andMGF1Padding",
    // To our knowledge, RSA-OAEP with SHA-3 is not defined by any standards or RFC.
    // For example, it is unclear if RSA-OAEP with SHA-3 should simply replace
    // SHA-xxx with SHA3-xxx or if MGF1 should be replaced by SHAKE (similar to RFC 8702).
    // However, the following algorithm names are supported by BouncyCastle.
    "RSA/ECB/OAEPwithSHA3-224andMGF1Padding",
    "RSA/ECB/OAEPwithSHA3-256andMGF1Padding",
    "RSA/ECB/OAEPwithSHA3-384andMGF1Padding",
    "RSA/ECB/OAEPwithSHA3-512andMGF1Padding",
  };

  private static void printParameters(AlgorithmParameterSpec params) {
    if (params instanceof OAEPParameterSpec) {
      OAEPParameterSpec oaepParams = (OAEPParameterSpec) params;
      System.out.println("OAEPParameterSpec");
      System.out.println("digestAlgorithm:" + oaepParams.getDigestAlgorithm());
      System.out.println("mgfAlgorithm:" + oaepParams.getMGFAlgorithm());
      printParameters(oaepParams.getMGFParameters());
    } else if (params instanceof MGF1ParameterSpec) {
      MGF1ParameterSpec mgf1Params = (MGF1ParameterSpec) params;
      System.out.println("MGF1ParameterSpec");
      System.out.println("digestAlgorithm:" + mgf1Params.getDigestAlgorithm());
    } else {
      System.out.println(params.toString());
    }
  }

  /**
   * This is not a real test. The JCE algorithm names only specify one hash algorithm. But OAEP uses
   * two hases. One hash algorithm is used to hash the labels. The other hash algorithm is used for
   * the mask generation function.
   *
   * <p>Different provider use different default values for the hash function that is not specified
   * in the algorithm name. Jdk uses mgfsha1 as default. BouncyCastle and Conscrypt use the same
   * hash for labels and mgf. Every provider allows to specify all the parameters using an
   * OAEPParameterSpec instance.
   *
   * <p>This test simply tries a number of algorithm names for RSA-OAEP and prints the OAEP
   * parameters for the case where no OAEPParameterSpec is used.
   *
   * <p>https://docs.oracle.com/en/java/javase/11/docs/specs/security/standard-names.html claims:
   * "... If OAEPPadding is used, Cipher objects are initialized with a
   * javax.crypto.spec.OAEPParameterSpec object to supply values needed for OAEPPadding ...". This
   * claim is somewhat ambiguous. All providers tested use default parameters for "RSA-OAEP". This
   * is different than for example "RSASSA-PSS", where jdk requires that parameters are set
   * explicitly.
   *
   * <p>The default parameters for "RSA/ECB/OAEPPadding" are typically SHA-1 and MGF1-SHA1. These
   * values are acceptable since RSA-OAEP does not require a collision resistant hash function for
   * its security.
   *
   * <p>https://jdk.java.net/19/release-notes claims that OAEPParameterSpec.DEFAULT static constant
   * is deprecated. Hence callers should not rely on such default behaviour.
   */
  @Test
  public void testDefaults() throws Exception {
    String pubKey =
        "30820122300d06092a864886f70d01010105000382010f003082010a02820101"
            + "00bdf90898577911c71c4d9520c5f75108548e8dfd389afdbf9c997769b8594e"
            + "7dc51c6a1b88d1670ec4bb03fa550ba6a13d02c430bfe88ae4e2075163017f4d"
            + "8926ce2e46e068e88962f38112fc2dbd033e84e648d4a816c0f5bd89cadba0b4"
            + "d6cac01832103061cbb704ebacd895def6cff9d988c5395f2169a6807207333d"
            + "569150d7f569f7ebf4718ddbfa2cdbde4d82a9d5d8caeb467f71bfc0099b0625"
            + "a59d2bad12e3ff48f2fd50867b89f5f876ce6c126ced25f28b1996ee21142235"
            + "fb3aef9fe58d9e4ef6e4922711a3bbcd8adcfe868481fd1aa9c13e5c658f5172"
            + "617204314665092b4d8dca1b05dc7f4ecd7578b61edeb949275be8751a5a1fab"
            + "c30203010001";
    KeyFactory kf;
    kf = KeyFactory.getInstance("RSA");
    X509EncodedKeySpec x509keySpec = new X509EncodedKeySpec(TestUtil.hexToBytes(pubKey));
    PublicKey key = kf.generatePublic(x509keySpec);
    for (String oaepName : OaepAlgorithmNames) {
      Cipher c;
      try {
        c = Cipher.getInstance(oaepName);
      } catch (NoSuchAlgorithmException ex) {
        System.out.println("Algorithm " + oaepName + " not supported");
        continue;
      }
      try {
        c.init(Cipher.ENCRYPT_MODE, key);
        System.out.println("Algorithm " + oaepName + " uses the following defaults");
        AlgorithmParameters params = c.getParameters();
        printParameters(params.getParameterSpec(OAEPParameterSpec.class));
      } catch (GeneralSecurityException ex) {
        System.out.println("Algorithm " + oaepName + " throws " + ex.toString());
      }
    }
  }
}


