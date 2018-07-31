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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.security.wycheproof.WycheproofRunner.NoPresubmitTest;
import com.google.security.wycheproof.WycheproofRunner.ProviderType;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashSet;
import java.util.Set;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * This test uses test vectors in JSON format to check digital signature with PSS padding. 
 * There are still a lot of open questions, e.g. the format for the test vectors is not yet
 * finalized. Therefore, we are not integrating the tests here into other tests.
 */
@RunWith(JUnit4.class)
public class RsaPssTest {

  /** Convenience mehtod to get a String from a JsonObject */
  protected static String getString(JsonObject object, String name) throws Exception {
    return object.get(name).getAsString();
  }

  /** Convenience method to get a byte array from a JsonObject */
  protected static byte[] getBytes(JsonObject object, String name) throws Exception {
    return JsonUtil.asByteArray(object.get(name));
  }

  /**
   * Returns the algorithm name for the RSA-PSS signature scheme.
   * algorithm names used in JCA are a bit inconsequential. E.g. a dash is necessary for message
   * digests (e.g. "SHA-256") but are not used in the corresponding names for digital signatures
   * (e.g. "SHA256WITHRSAandMGF1").
   *
   * <p>See http://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html
   *
   * @param group A json dictionary containing a field "sha" with message digest (e.g. "SHA-256")
   *              and the a field "mgf" for the mask generation function (e.g. "MGF1").
   * @return the algorithm name for the signature scheme with the given hash.
   */
  protected static String getAlgorithmName(JsonObject group) throws Exception {
    String md = getString(group, "sha");
    String mgf = getString(group, "mgf");
    if (md.equals("SHA-1")) {
      md = "SHA1";
    } else if (md.equals("SHA-224")) {
      md = "SHA224";
    } else if (md.equals("SHA-256")) {
      md = "SHA256";
    } else if (md.equals("SHA-384")) {
      md = "SHA384";
    } else if (md.equals("SHA-512")) {
      md = "SHA512";
    }
    return md + "WITHRSAand" + mgf;
  }

  /**
   * Get a PublicKey from a JsonObject.
   *
   * <p>object contains the key in multiple formats: "key" : elements of the public key "keyDer":
   * the key in ASN encoding encoded hexadecimal "keyPem": the key in Pem format encoded hexadecimal
   * The test can use the format that is most convenient.
   */
  protected static PublicKey getPublicKey(JsonObject object) throws Exception {
    KeyFactory kf;
    kf = KeyFactory.getInstance("RSA");
    byte[] encoded = TestUtil.hexToBytes(getString(object, "keyDer"));
    X509EncodedKeySpec x509keySpec = new X509EncodedKeySpec(encoded);
    return kf.generatePublic(x509keySpec);
  }

  protected static PSSParameterSpec getPSSParams(JsonObject group) throws Exception {
    String mgf = getString(group, "mgf");
    String mgfSha = getString(group, "mgfSha");
    int saltLen = group.get("sLen").getAsInt();
    return new PSSParameterSpec(mgfSha, mgf, new MGF1ParameterSpec(mgfSha), saltLen, 1);
  }

  /** 
   * Tests the signature verification with test vectors in a given JSON file.
   *
   * <p> Example format for test vectors
   * {
   *   "algorithm" : "RSASSA-PSS",
   *   "generatorVersion" : "0.4.12",
   *   "numberOfTests" : 37,
   *   "header" : [],
   *   "testGroups" : [
   *     {
   *       "e" : "10001",
   *       "keyAsn" : "3082010a02820101...",
   *       "keyDer" : "30820122300d0609...",
   *       "keyPem" : "-----BEGIN PUBLIC KEY-----\n...",
   *       "keysize" : 2048,
   *       "mgf" : "MGF1",
   *       "mgfSha" : "SHA-256",
   *       "n" : "0a2b451a07d0aa5f...",
   *       "saltLen" : 20,
   *       "sha" : "SHA-256",
   *       "type" : "RSASigVer",
   *       "tests" : [
   *         {
   *           "tcId" : 1,
   *           "comment" : "",
   *           "msg" : "313133343030",
   *           "sig" : "577dfef111ae9a39..."
   *           "result" : "valid",
   *           "flags" : []
   *         },
   *        ...
   *
   * @param filename the filename of the test vectors
   * @param allowSkippingKeys if true then keys that cannot be constructed will not fail the test.
   *     This is for example used for files with test vectors that use elliptic curves that are not
   *     commonly supported.
   **/
  public void testRsaPss(String filename, boolean allowSkippingKeys)
      throws Exception {
    // Testing with old test vectors may be a reason for a test failure.
    // Generally mismatched version numbers are of little or no concern, since
    // the test vector version change much more frequently than the format.
    //
    // Version numbers have the format major.minor[status].
    // Versions before 1.0 are experimental and  use formats that are expected to change.
    // Versions after 1.0 change the major number if the format changes and change
    // the minor number if only the test vectors (but not the format) changes.
    // Versions meant for distribution have no status.
    final String expectedVersion = "0.5";
    JsonObject test = JsonUtil.getTestVectors(filename); 
    String generatorVersion = getString(test, "generatorVersion");
    if (!generatorVersion.equals(expectedVersion)) {
      System.out.println(
          "Expecting test vectors with version "
              + expectedVersion
              + " found vectors with version "
              + generatorVersion);
    }
    int numTests = test.get("numberOfTests").getAsInt();
    int cntTests = 0;
    int errors = 0;
    int skippedKeys = 0;
    Set<String> skippedAlgorithms = new HashSet<String>();
    for (JsonElement g : test.getAsJsonArray("testGroups")) {
      JsonObject group = g.getAsJsonObject();
      String algorithm = getAlgorithmName(group);
      PublicKey key = null;
      Signature verifier = null;
      try {
        key = getPublicKey(group);
        PSSParameterSpec pssParams = getPSSParams(group);
        verifier = Signature.getInstance(algorithm);
        verifier.setParameter(pssParams);
      } catch (GeneralSecurityException ex) {
        if (allowSkippingKeys) {
          skippedKeys++;
          skippedAlgorithms.add(algorithm);
        } else {
          System.out.println("Failed to generate verifier for " + algorithm);
          errors++;
        }
        continue;
      }
      for (JsonElement t : group.getAsJsonArray("tests")) {
        cntTests++;
        JsonObject testcase = t.getAsJsonObject();
        byte[] message = getBytes(testcase, "msg");
        byte[] signature = getBytes(testcase, "sig");
        int tcid = testcase.get("tcId").getAsInt();
        String sig = TestUtil.bytesToHex(signature);
        String result = getString(testcase, "result");
        verifier.initVerify(key);
        verifier.update(message);
        boolean verified = false;
        try {
          verified = verifier.verify(signature);
        } catch (SignatureException ex) {
          // verify can throw SignatureExceptions if the signature is malformed.
          // We don't flag these cases and simply consider the signature as invalid.
          verified = false;
        } catch (Exception ex) {
          // Other exceptions (i.e. unchecked exceptions) are considered as error
          // since a third party should never be able to cause such exceptions.
          System.out.println(
              "Signature verification throws "
                  + ex.toString()
                  + " "
                  + filename
                  + " tcId:"
                  + tcid
                  + " sig:"
                  + sig);
          verified = false;
          errors++;
        }
        if (!verified && result.equals("valid")) {
          System.out.println(
              "Valid signature not verified. "
                  + filename
                  + " tcId:"
                  + tcid
                  + " sig:"
                  + sig);
          errors++;
        } else if (verified && result.equals("invalid")) {
          System.out.println(
              "Invalid signature verified. "
                  + filename
                  + " tcId:"
                  + tcid
                  + " sig:"
                  + sig);
          errors++;
        }
      }
    }
    System.out.println("Number of skipped keys:" + skippedKeys);
    for (String s : skippedAlgorithms) {
      System.out.println("Skipped algorithms " + s);
    }
    assertEquals(0, errors);
    if (skippedKeys == 0) {
      assertEquals(numTests, cntTests);
    } else {
      assertTrue(allowSkippingKeys);
    }
  }

  @Test
  public void testRsaPss2048Sha256() throws Exception {
    testRsaPss("rsa_pss_2048_sha256_mgf1_32_test.json", false);
  }

  @NoPresubmitTest(
    providers = {ProviderType.BOUNCY_CASTLE},
    bugs = {"b/111634359"}
  )
  @Test
  public void testRsaPss3072Sha256() throws Exception {
    testRsaPss("rsa_pss_3072_sha256_mgf1_32_test.json", false);
  }

  @Test
  public void testRsaPss4096Sha256() throws Exception {
    testRsaPss("rsa_pss_4096_sha256_mgf1_32_test.json", false);
  }

  @Test
  public void testRsaPss4096Sha512() throws Exception {
    testRsaPss("rsa_pss_4096_sha512_mgf1_32_test.json", false);
  }

  @Test
  public void testRsaPss2048Sha256NoSalt() throws Exception {
    testRsaPss("rsa_pss_2048_sha256_mgf1_0_test.json", false);
  }

  /**
   * Checks RSA-PSS with various combinations of hashes and salt lengths.
   * Some providers restrict the range of supported parameters.
   * E.g. BouncyCastle requires that the signature hash and the mgf hash
   * are the same. The test expects that unsupported combinations are
   * rejected during the initialization of the Signature instance.
   */
  @Test
  public void testRsaPssMisc() throws Exception {
    testRsaPss("rsa_pss_misc_test.json", true);
  }
}

