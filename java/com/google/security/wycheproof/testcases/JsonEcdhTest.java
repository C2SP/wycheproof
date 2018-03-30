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
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.KeyAgreement;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** This test uses test vectors in JSON format to check implementations of ECDH. */
@RunWith(JUnit4.class)
public class JsonEcdhTest {

  /** Convenience mehtod to get a String from a JsonObject */
  protected static String getString(JsonObject object, String name) throws Exception {
    return object.get(name).getAsString();
  }

  /** Convenience method to get a BigInteger from a JsonObject */
  protected static BigInteger getBigInteger(JsonObject object, String name) throws Exception {
    return JsonUtil.asBigInteger(object.get(name));
  }

  /** Convenience method to get a byte array from a JsonObject */
  protected static byte[] getBytes(JsonObject object, String name) throws Exception {
    return JsonUtil.asByteArray(object.get(name));
  }

  /**
   * Example for test vector
   * {
   * "algorithm" : "ECDH",
   * "generatorVersion" : "0.1.3",
   * "numberOfTests" : 335,
   * "header" : [],
   * "testGroups" : [
   *   {
   *     "type" : "ECDHComp",
   *     "tests" : [
   *        {
   *         "comment" : "normal case",
   *         "curve" : "secp224r1",
   *         "private" : "565577a49415ca761a0322ad54e4ad0ae7625174baf372c2816f5328",
   *         "public" : "30...",
   *         "result" : "valid",
   *         "shared" : "b8ecdb552d39228ee332bafe4886dbff272f7109edf933bc7542bd4f",
   *         "tcId" : 1
   *        },
   *     ...
   **/
  public void testEcdhComp(String filename) throws Exception {
    // Testing with old test vectors may a reason for a test failure.
    // Version number have the format major.minor[status].
    // Versions before 1.0 are experimental and  use formats that are expected to change.
    // Versions after 1.0 change the major number if the format changes and change
    // the minor number if only the test vectors (but not the format) changes.
    // Versions meant for distribution have no status.
    final String expectedVersion = "0.4";
    JsonObject test = JsonUtil.getTestVectors(filename);
    String generatorVersion = test.get("generatorVersion").getAsString();
    if (!generatorVersion.equals(expectedVersion)) {
      System.out.println(
          "ECDH: expecting test vectors with version "
              + expectedVersion
              + " found vectors with version "
              + generatorVersion);
    }
    int numTests = test.get("numberOfTests").getAsInt();
    int passedTests = 0;
    int rejectedTests = 0; // invalid test vectors leading to exceptions
    int skippedTests = 0; // valid test vectors leading to exceptions
    int errors = 0;
    for (JsonElement g : test.getAsJsonArray("testGroups")) {
      JsonObject group = g.getAsJsonObject();
      for (JsonElement t : group.getAsJsonArray("tests")) {
        JsonObject testcase = t.getAsJsonObject();
        int tcid = testcase.get("tcId").getAsInt();
        String curve = getString(testcase, "curve");
        String comment = getString(testcase, "comment");
        BigInteger priv = getBigInteger(testcase, "private");
        byte[] publicEncoded = getBytes(testcase, "public");
        String result = getString(testcase, "result");
        String expectedHex = getString(testcase, "shared");
        KeyFactory kf = KeyFactory.getInstance("EC");
        try {
          ECPrivateKeySpec spec = new ECPrivateKeySpec(priv, EcUtil.getCurveSpecRef(curve));
          PrivateKey privKey = kf.generatePrivate(spec);
          X509EncodedKeySpec x509keySpec = new X509EncodedKeySpec(publicEncoded);
          PublicKey pubKey = kf.generatePublic(x509keySpec);
          KeyAgreement ka = KeyAgreement.getInstance("ECDH");
          ka.init(privKey);
          ka.doPhase(pubKey, true);
          String sharedHex = TestUtil.bytesToHex(ka.generateSecret());
          if (result.equals("invalid")) {
            System.out.println(
                "Computed ECDH with invalid parameters"
                    + " tcId:"
                    + tcid
                    + " comment:"
                    + comment
                    + " shared:"
                    + sharedHex);
            errors++;
          } else if (!expectedHex.equals(sharedHex)) {
            System.out.println(
                "Incorrect ECDH computation"
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
  public void testEcdh() throws Exception {
    testEcdhComp("ecdh_test.json");
  }
}
