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
import com.google.security.wycheproof.WycheproofRunner.ExcludedTest;
import com.google.security.wycheproof.WycheproofRunner.NoPresubmitTest;
import com.google.security.wycheproof.WycheproofRunner.ProviderType;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * This test uses test vectors in JSON format to test symmetric ciphers.
 *
 * <p>Ciphers tested in this class are unauthenticated ciphers (i.e. don't have additional data) and
 * are randomized using an initialization vector as long as the JSON test vectors are represented
 * with the type "IndCpaTest".
 */
@RunWith(JUnit4.class)
public class JsonCipherTest {

  /** Convenience method to get a byte array from a JsonObject. */
  protected static byte[] getBytes(JsonObject object, String name) {
    return JsonUtil.asByteArray(object.get(name));
  }

  protected static Cipher getCipher(String algorithm)
      throws NoSuchAlgorithmException, NoSuchPaddingException {
    switch (algorithm) {
      case "AES-CBC-PKCS5":
        return Cipher.getInstance("AES/CBC/PKCS5Padding");
      case "ARIA-CBC-PKCS5":
        return Cipher.getInstance("ARIA/CBC/PKCS5Padding");
      case "CAMELLIA-CBC-PKCS5":
        return Cipher.getInstance("CAMELLIA/CBC/PKCS5Padding");
      default:
        throw new NoSuchAlgorithmException("Unsupported algorithm:" + algorithm);
    }
  }

  /**
   * Returns an initialized Cipher instance.
   *
   * @param algorithm the name of the algorithm used (e.g. "AES/CBC/PKCS5Padding")
   * @param opmode either Cipher.ENCRYPT_MODE or Cipher.DECRYPT_MODE
   * @param key raw key bytes
   * @param iv the initialisation vector
   */
  protected static Cipher getInitializedCipher(String algorithm, int opmode, byte[] key, byte[] iv)
      throws GeneralSecurityException {
    Cipher cipher = getCipher(algorithm);
    SecretKeySpec keySpec;
    AlgorithmParameterSpec parameters;
    switch (algorithm) {
      case "AES-CBC-PKCS5":
        keySpec = new SecretKeySpec(key, "AES");
        parameters = new IvParameterSpec(iv);
        break;
      case "ARIA-CBC-PKCS5":
        keySpec = new SecretKeySpec(key, "ARIA");
        parameters = new IvParameterSpec(iv);
        break;
      case "CAMELLIA-CBC-PKCS5":
        keySpec = new SecretKeySpec(key, "CAMELLIA");
        parameters = new IvParameterSpec(iv);
        break;
      default:
        throw new NoSuchAlgorithmException("Unsupported algorithm:" + algorithm);
    }
    cipher.init(opmode, keySpec, parameters);
    return cipher;
  }

  /**
   * Example format for test vectors
   *
   * <pre>
   * {
   * "algorithm" : "AES-CBC-PKCS5",
   * "schema" : "ind_cpa_test_schema.json",
   * "generatorVersion" : "0.9",
   * "numberOfTests" : 216,
   * "header" : [
   *   ...
   * ],
   * "notes" : {
   *   "BadPadding" : {
   *     "bugType" : "MISSING_STEP",
   *     "description" : "..."
   *   },
   *   ...
   * },
   * "testGroups" : [
   *   {
   *     "type" : "IndCpaTest",
   *     "keySize" : 128,
   *     "ivSize" : 128,
   *     "tests" : [
   *       {
   *         "tcId" : 1,
   *         "comment" : "empty message",
   *         "flags" : [
   *           "Pseudorandom"
   *         ],
   *         "key" : "e34f15c7bd819930fe9d66e0c166e61c",
   *         "iv" : "da9520f7d3520277035173299388bee2",
   *         "msg" : "",
   *         "ct" : "b10ab60153276941361000414aed0a9d",
   *         "result" : "valid"
   *       },
   *       ...
   * </pre>
   */
  private static void singleTest(String algorithm, JsonObject testcase, TestResult testResult) {
    int tcId = testcase.get("tcId").getAsInt();
    byte[] key = getBytes(testcase, "key");
    byte[] iv = getBytes(testcase, "iv");
    byte[] msg = getBytes(testcase, "msg");
    byte[] ciphertext = getBytes(testcase, "ct");
    // Result is one of "valid", "invalid", "acceptable".
    // "valid" are test vectors with matching plaintext, ciphertext and tag.
    // "invalid" are test vectors with invalid parameters or invalid ciphertext and tag.
    // "acceptable" are test vectors with weak parameters or legacy formats.
    String result = testcase.get("result").getAsString();

    // Test encryption
    Cipher cipher;
    try {
      cipher = getInitializedCipher(algorithm, Cipher.ENCRYPT_MODE, key, iv);
    } catch (GeneralSecurityException ex) {
      // Some libraries restrict key size, iv size and tag size.
      // Because of the initialization of the cipher might fail.
      testResult.addResult(tcId, TestResult.Type.REJECTED_ALGORITHM, ex.toString());
      return;
    }
    TestResult.Type resultType;
    String comment = "";
    // Normally the test tries to encrypt and decrypt a ciphertext.
    // tryDecrypt is set to false if a bug during encryption was serious enough,
    // so that trying to decrypt no longer makes sense.
    boolean tryDecrypt = true;
    try {
      byte[] encrypted = cipher.doFinal(msg);
      boolean eq = Arrays.equals(ciphertext, encrypted);
      if (result.equals("invalid")) {
        if (eq) {
          // Some test vectors use invalid parameters that should be rejected.
          // E.g. an implementation must never encrypt using AES-GCM with an IV of length 0,
          // since this leaks the authentication key.
          resultType = TestResult.Type.NOT_REJECTED_INVALID;
          tryDecrypt = false;
        } else {
          // Invalid test vectors frequently have invalid tags.
          // Hence encryption just gives a different result.
          resultType = TestResult.Type.REJECTED_INVALID;
        }
      } else {
        if (!eq) {
          // If encryption returns the wrong result then something is
          // broken. Hence we can stop here.
          resultType = TestResult.Type.WRONG_RESULT;
          comment = "ciphertext: " + TestUtil.bytesToHex(encrypted);
          tryDecrypt = false;
        } else {
          resultType = TestResult.Type.PASSED_VALID;
        }
      }
    } catch (GeneralSecurityException ex) {
      if (result.equals("valid")) {
        resultType = TestResult.Type.REJECTED_VALID;
      } else {
        resultType = TestResult.Type.REJECTED_INVALID;
      }
    }

    if (tryDecrypt) {
      // Test decryption
      try {
        Cipher decCipher = getInitializedCipher(algorithm, Cipher.DECRYPT_MODE, key, iv);
        byte[] decrypted = decCipher.doFinal(ciphertext);
        boolean eq = Arrays.equals(decrypted, msg);
        if (result.equals("invalid")) {
          resultType = TestResult.Type.NOT_REJECTED_INVALID;
        } else if (!eq) {
          resultType = TestResult.Type.WRONG_RESULT;
          comment = "decrypted:" + TestUtil.bytesToHex(decrypted);
        } else {
          resultType = TestResult.Type.PASSED_VALID;
        }
      } catch (GeneralSecurityException ex) {
        comment = ex.toString();
        if (result.equals("valid")) {
          resultType = TestResult.Type.REJECTED_VALID;
        } else {
          resultType = TestResult.Type.REJECTED_INVALID;
        }
      }
    }
    testResult.addResult(tcId, resultType, comment);
  }

  /**
   * Checks each test vector in a file of test vectors.
   *
   * <p>One motivation for running all the test vectors in a file at once is that this allows us to
   * test if invalid paddings result in distinguishable exceptions. Throwing distinguishable
   * exceptions can contain information that helps an attacker in a chosen ciphertext attack.
   *
   * @param testVectors the test vectors
   * @return a test result
   */
  public static TestResult allTests(TestVectors testVectors) {
    var testResult = new TestResult(testVectors);
    JsonObject test = testVectors.getTest();
    String algorithm = test.get("algorithm").getAsString();
    try {
      Cipher unused = getCipher(algorithm);
    } catch (NoSuchAlgorithmException | NoSuchPaddingException ex) {
      testResult.addFailure(TestResult.Type.REJECTED_ALGORITHM, algorithm);
      return testResult;
    }
    for (JsonElement g : test.getAsJsonArray("testGroups")) {
      JsonObject group = g.getAsJsonObject();
      for (JsonElement t : group.getAsJsonArray("tests")) {
        JsonObject testcase = t.getAsJsonObject();
        singleTest(algorithm, testcase, testResult);
      }
    }
    // Test vectors with invalid padding must have indistinguishable behavior.
    // The test here checks for distinct exceptions. There are other ways to
    // distinguish paddings, such as timing differences. Such differences are
    // not checked here.
    // Some invalid paddings are excluded here: E.g., BouncyCastle throws
    // IllegalBlockSize exceptions if the ciphertext is empty. This exception
    // is of course distinguishable from BadPaddingExceptions. It can be excluded
    // since it does not leak information. Such test vectors do not include
    // a "BadPadding" flag.
    testResult.checkIndistinguishableResult("BadPadding");
    return testResult;
  }

  public void testCipher(String filename) throws Exception {
    JsonObject test = JsonUtil.getTestVectorsV1(filename);
    TestVectors testVectors = new TestVectors(test, filename);
    TestResult testResult = allTests(testVectors);

    if (testResult.skipTest()) {
      System.out.println("Skipping " + filename + " no ciphertext decrypted.");
      TestUtil.skipTest("No ciphertext decrypted");
      return;
    }
    System.out.print(testResult.asString());
    assertEquals(0, testResult.errors());
  }

  // jdk11 accepts an empty ciphertext.
  @NoPresubmitTest(
      providers = {ProviderType.OPENJDK, ProviderType.CONSCRYPT},
      bugs = {"b/258666069"})
  @ExcludedTest(
      providers = {ProviderType.CONSCRYPT},
      comment = "Conscrypt accepts empyt ciphertexts.")
  @Test
  public void testAesCbcPkcs5() throws Exception {
    testCipher("aes_cbc_pkcs5_test.json");
  }

  @Test
  public void testAriaCbcPkcs5() throws Exception {
    testCipher("aria_cbc_pkcs5_test.json");
  }

  @Test
  public void testCamelliaCbcPkcs5() throws Exception {
    testCipher("camellia_cbc_pkcs5_test.json");
  }
}
