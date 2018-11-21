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

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.KeyAgreement;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** 
 * This test uses test vectors in JSON format to check implementations of XDH.
 *
 * XDH is a Diffie-Hellman key agreement scheme.
 * It has been added to jdk11 (http://openjdk.java.net/jeps/324) 
 */
@RunWith(JUnit4.class)
public class JsonXdhTest {

  /** Convenience mehtod to get a String from a JsonObject */
  protected static String getString(JsonObject object, String name) throws Exception {
    return object.get(name).getAsString();
  }

  /** Convenience method to get a byte array from a JsonObject */
  protected static byte[] getBytes(JsonObject object, String name) throws Exception {
    return JsonUtil.asByteArray(object.get(name));
  }

  /**
   * This test requires test vectors where the public key is X.509 encoded and
   * the private key is PKCS #8 encoded. This is different than the ECDH tests where
   * private key in the test vectors is an integer.
   *
   * The main reason for using this encoding is that the tests below can be implemented
   * without using new interfaces such as XECPublicKey, XECPrivateKey, so that the
   * code still compiles on older jdk versions and tests are simply skipped. 
   *
   * Example for test vector
   * {
   * "algorithm" : "XDH",
   * "generatorVersion" : "0.6",
   * "numberOfTests" : 32,
   * "header" : [],
   * "testGroups" : [
   *   {
   *      "curve" : "curve25519",
   *      "type" : "XDHComp",
   *      "tests" : [
   *        {
   *          "tcId" : 1,
   *          "comment" : "normal case",
   *          "public" : "302c300706032b...",
   *          "private" : "302e0201003007...",
   *          "shared" : "87b7f212b627f7...",
   *          "result" : "valid",
   *          "flags" : []
   *        },
   *     ...
   **/
  public void testXdhComp(String filename) throws Exception {
    // Checks the precondition for this test.
    // XDH has been added in jdk11.
    try {
      KeyAgreement.getInstance("XDH");
    } catch (NoSuchAlgorithmException ex) {
      System.out.println("XDH is not supported: skipping test");
      return;
    }

    final String expectedVersion = "0.6";
    JsonObject test = JsonUtil.getTestVectors(filename);
    String generatorVersion = test.get("generatorVersion").getAsString();
    if (!generatorVersion.equals(expectedVersion)) {
      System.out.println(
          "XDH: expecting test vectors with version "
              + expectedVersion
              + " found vectors with version "
              + generatorVersion);
    }
    int numTests = test.get("numberOfTests").getAsInt();
    int passedTests = 0;
    int rejectedTests = 0;  // invalid test vectors leading to exceptions
    int skippedTests = 0;  // valid test vectors leading to exceptions
    int errors = 0;
    for (JsonElement g : test.getAsJsonArray("testGroups")) {
      JsonObject group = g.getAsJsonObject();
      for (JsonElement t : group.getAsJsonArray("tests")) {
        JsonObject testcase = t.getAsJsonObject();
        int tcid = testcase.get("tcId").getAsInt();
        String comment = getString(testcase, "comment");
        byte[] priv = getBytes(testcase, "private");
        byte[] publicEncoded = getBytes(testcase, "public");
        String result = getString(testcase, "result");
        String expectedHex = getString(testcase, "shared");
        KeyFactory kf = KeyFactory.getInstance("XDH");
        try {
          PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(priv);
          PrivateKey privKey = kf.generatePrivate(privKeySpec);
          X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(publicEncoded);
          PublicKey pubKey = kf.generatePublic(pubKeySpec);
          KeyAgreement ka = KeyAgreement.getInstance("XDH");
          ka.init(privKey);
          ka.doPhase(pubKey, true);
          String sharedHex = TestUtil.bytesToHex(ka.generateSecret());
          if (result.equals("invalid")) {
            System.out.println(
                "Computed XDH with invalid parameters"
                    + " tcId:"
                    + tcid
                    + " comment:"
                    + comment
                    + " shared:"
                    + sharedHex);
            errors++;
          } else if (!expectedHex.equals(sharedHex)) {
            System.out.println(
                "Incorrect XDH computation"
                    + " tcId:"
                    + tcid
                    + " comment:"
                    + comment
                    + "\nshared:"
                    + sharedHex
                    + "\nexpected:"
                    + expectedHex);
            errors++;
          } else {
            passedTests++;
          }
        } catch (InvalidKeySpecException | InvalidKeyException | NoSuchAlgorithmException ex) {
          // These are the exception that we expect to see when a curve is not implemented
          // or when a key is not valid.
          if (result.equals("valid")) {
            skippedTests++;
          } else {
            rejectedTests++;
          }
        } catch (Exception ex) {
          // Other exceptions typically indicate that something is wrong with the implementation.
          System.out.println(
              "Test vector with tcId:" + tcid + " comment:" + comment + " throws:" + ex.toString());
          errors++;
        }
      }
    }
    assertEquals(0, errors);
    assertEquals(numTests, passedTests + rejectedTests + skippedTests);
  }

  @Test
  public void testX25519() throws Exception {
    testXdhComp("x25519_asn_test.json");
  }

  @Test
  public void testX448() throws Exception {
    testXdhComp("x448_asn_test.json");
  }
}
