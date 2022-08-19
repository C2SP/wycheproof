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

  /** Convenience method to get a BigInteger from a JsonObject */
  protected static BigInteger getBigInteger(JsonObject object, String name) throws Exception {
    return JsonUtil.asBigInteger(object.get(name));
  }

  /** Convenience method to get a byte array from a JsonObject */
  protected static byte[] getBytes(JsonObject object, String name) throws Exception {
    return JsonUtil.asByteArray(object.get(name));
  }

  private static void singleTest(JsonObject testcase, String curve, TestResult testResult)
      throws Exception {

    BigInteger priv = getBigInteger(testcase, "private");
    byte[] publicEncoded = getBytes(testcase, "public");
    String result = testcase.get("result").getAsString();
    String expectedHex = testcase.get("shared").getAsString();
    int tcId = testcase.get("tcId").getAsInt();

    try {
      KeyFactory kf = KeyFactory.getInstance("EC");
      ECPrivateKeySpec spec = new ECPrivateKeySpec(priv, EcUtil.getCurveSpec(curve));
      PrivateKey privKey = kf.generatePrivate(spec);
      X509EncodedKeySpec x509keySpec = new X509EncodedKeySpec(publicEncoded);
      PublicKey pubKey = kf.generatePublic(x509keySpec);
      KeyAgreement ka = KeyAgreement.getInstance("ECDH");
      ka.init(privKey);
      ka.doPhase(pubKey, true);
      String sharedHex = TestUtil.bytesToHex(ka.generateSecret());
      TestResult.Type res;
      String comment = "";
      if (expectedHex.equals(sharedHex)) {
        if (result.equals("valid") || result.equals("acceptable")) {
          res = TestResult.Type.PASSED_VALID;
        } else {
          res = TestResult.Type.PASSED_MALFORMED;
        }
      } else {
        if (result.equals("valid") || result.equals("acceptable")) {
          res = TestResult.Type.WRONG_RESULT;
        } else {
          res = TestResult.Type.NOT_REJECTED_INVALID;
        }
        comment = "Incorrect result: " + sharedHex;
      }
      testResult.addResult(tcId, res, comment);
    } catch (NoSuchAlgorithmException ex) {
      testResult.addResult(tcId, TestResult.Type.REJECTED_ALGORITHM, ex.toString());
    } catch (InvalidKeySpecException | InvalidKeyException ex) {
      if (result.equals("valid")) {
        testResult.addResult(tcId, TestResult.Type.REJECTED_VALID, ex.toString());
      } else {
        testResult.addResult(tcId, TestResult.Type.REJECTED_INVALID, ex.toString());
      }
    } catch (Exception ex) {
      testResult.addResult(tcId, TestResult.Type.WRONG_EXCEPTION, ex.toString());
    }
  }

  /**
   * Example for test vector
   *
   * <pre>
   * {
   * "algorithm" : "ECDH",
   * "header" : [],
   * "notes" : {
   *   "AddSubChain" : "The private key has a special value....",
   * }
   * "generatorVersion" : "0.7",
   * "numberOfTests" : 308,
   * "testGroups" : [
   *   {
   *     "type" : "EcdhTest",
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
   * </pre>
   */
  public static TestResult allTests(TestVectors testVectors) throws Exception {
    var testResult = new TestResult(testVectors);
    String name = testVectors.getName();
    JsonObject test = testVectors.getTest();
    final String expectedSchema = "ecdh_test_schema.json";
    String schema = test.get("schema").getAsString();
    assertEquals("Unexpected schema in:" + name, expectedSchema, schema);
    for (JsonElement g : test.getAsJsonArray("testGroups")) {
      JsonObject group = g.getAsJsonObject();
      String curve = group.get("curve").getAsString();
      for (JsonElement t : group.getAsJsonArray("tests")) {
        JsonObject testcase = t.getAsJsonObject();
        singleTest(testcase, curve, testResult);
      }
    }
    return testResult;
  }

  public void testEcdhComp(String filename) throws Exception {
    JsonObject test = JsonUtil.getTestVectorsV1(filename);
    TestResult testResult = allTests(new TestVectors(test, filename));
    if (testResult.skipTest()) {
      System.out.println("Skipping " + filename + " no valid test vectors passed.");
      TestUtil.skipTest("No valid test vectors passed");
      return;
    }
    System.out.print(testResult.asString());
    assertEquals(0, testResult.errors());
  }

  @Test
  public void testSecp224r1() throws Exception {
    testEcdhComp("ecdh_secp224r1_test.json");
  }

  @Test
  public void testSecp256r1() throws Exception {
    testEcdhComp("ecdh_secp256r1_test.json");
  }

  @Test
  public void testSecp384r1() throws Exception {
    testEcdhComp("ecdh_secp384r1_test.json");
  }

  @Test
  public void testSecp521r1() throws Exception {
    testEcdhComp("ecdh_secp521r1_test.json");
  }

  @Test
  public void testSecp256k1() throws Exception {
    testEcdhComp("ecdh_secp256k1_test.json");
  }

  @Test
  public void testBrainpoolP224r1() throws Exception {
    testEcdhComp("ecdh_brainpoolP224r1_test.json");
  }

  @Test
  public void testBrainpoolP256r1() throws Exception {
    testEcdhComp("ecdh_brainpoolP256r1_test.json");
  }

  @Test
  public void testBrainpoolP320r1() throws Exception {
    testEcdhComp("ecdh_brainpoolP320r1_test.json");
  }

  @Test
  public void testBrainpoolP384r1() throws Exception {
    testEcdhComp("ecdh_brainpoolP384r1_test.json");
  }

  @Test
  public void testBrainpoolP512r1() throws Exception {
    testEcdhComp("ecdh_brainpoolP512r1_test.json");
  }

  /* TODO(bleichen): needs test vectors with the new format.
  @Test
  public void testSect283k1() throws Exception {
    testEcdhComp("ecdh_sect283k1_test.json");
  }

  @Test
  public void testSect283r1() throws Exception {
    testEcdhComp("ecdh_sect283r1_test.json");
  }

  @Test
  public void testSect409k1() throws Exception {
    testEcdhComp("ecdh_sect409k1_test.json");
  }

  @Test
  public void testSect409r1() throws Exception {
    testEcdhComp("ecdh_sect409r1_test.json");
  }

  @Test
  public void testSect571k1() throws Exception {
    testEcdhComp("ecdh_sect571k1_test.json");
  }

  @Test
  public void testSect571r1() throws Exception {
    testEcdhComp("ecdh_sect571r1_test.json");
  } */
}
