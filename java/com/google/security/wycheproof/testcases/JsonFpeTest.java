/**
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 * <p>http://www.apache.org/licenses/LICENSE-2.0
 *
 * <p>Unless required by applicable law or agreed to in writing, software distributed under the
 * License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.google.security.wycheproof;

import static org.junit.Assert.assertEquals;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.security.wycheproof.WycheproofRunner.NoPresubmitTest;
import com.google.security.wycheproof.WycheproofRunner.ProviderType;
import java.io.IOException;
import java.lang.reflect.Constructor;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** This class tests format preserving encryptions. */
@RunWith(JUnit4.class)
public class JsonFpeTest {

  /** Wycheproof represents byte arrays as hexadeciamal strings. */
  private static byte[] getBytes(JsonObject object, String name) {
    String hex = object.get(name).getAsString();
    return TestUtil.hexToBytes(hex);
  }

  /**
   * Plaintext and ciphertexts are represented as list of integers in the range 0 .. radix-1.
   * BouncyCastle uses bytes.
   */
  private static byte[] getMessage(JsonObject object, String name, int radix) {
    JsonArray ba = object.get(name).getAsJsonArray();
    byte[] res = new byte[ba.size()];
    for (int i = 0; i < ba.size(); i++) {
      int val = ba.get(i).getAsInt();
      if (val < 0 || val >= radix) {
        return null;
      }
      res[i] = (byte) val;
    }
    return res;
  }

  /**
   * Returns the algorithm parameters for encrypting and decrypting with a given radix and tweak.
   *
   * @param radix the radix of plaintext and ciphertext
   * @param tweak the tweak for encryption and decryption.
   * @return algorithm parameters for encryption and decryption.
   * @throws NoSuchAlgorithmException if no suitable class for the algorithm parameters was found.
   * @throws java.lang.ReflectiveOperationException if reflection was incorrectly used. This should
   *     not happen unless the code here is incorrect or incomplete.
   */
  private static AlgorithmParameterSpec algorithmParameters(int radix, byte[] tweak)
      throws NoSuchAlgorithmException, ReflectiveOperationException {
    try {
      // Tries the parameter specification from BouncyCastle.
      // This code uses reflection, because there appears to be no way to use the JCA interface.
      Class<?> clazz = Class.forName("org.bouncycastle.jcajce.spec.FPEParameterSpec");
      Constructor<?> ctor = clazz.getDeclaredConstructor(int.class, byte[].class);
      return (AlgorithmParameterSpec) ctor.newInstance(radix, tweak);
    } catch (ClassNotFoundException ex) {
      // org.bouncycastle.jcajce.spec.FPEParameterSpec was not found
    }
    throw new NoSuchAlgorithmException("Can't construct an AlgorithmParameterSpec");
  }

  private static byte[] encrypt(
      Cipher cipher, AlgorithmParameterSpec params, byte[] key, byte[] pt)
      throws GeneralSecurityException {
    SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
    cipher.init(Cipher.ENCRYPT_MODE, keySpec, params);
    return cipher.doFinal(pt);
  }

  private static byte[] decrypt(
      Cipher cipher, AlgorithmParameterSpec params, byte[] key, byte[] ct)
      throws GeneralSecurityException {
    SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
    cipher.init(Cipher.DECRYPT_MODE, keySpec, params);
    return cipher.doFinal(ct);
  }

  private static Cipher getCipher(String algorithmName)
      throws NoSuchAlgorithmException, NoSuchPaddingException {
    if (algorithmName.equals("AES-FF1")) {
      return Cipher.getInstance("AES/FF1/NoPadding");
    } else {
      throw new NoSuchAlgorithmException(algorithmName + " not supported");
    }
  }

  private static void singleTest(
      String algorithm, int radix, JsonObject testcase, TestResult testResult) {
    Cipher cipher;
    try {
      cipher = getCipher(algorithm);
    } catch (GeneralSecurityException ex) {
      testResult.addFailure(TestResult.Type.REJECTED_ALGORITHM, algorithm);
      return;
    }
    int tcid = testcase.get("tcId").getAsInt();
    byte[] key = getBytes(testcase, "key");
    byte[] tweak = getBytes(testcase, "tweak");
    byte[] msg = getMessage(testcase, "msg", radix);
    byte[] ct = getMessage(testcase, "ct", radix);
    if (msg == null || ct == null) {
      return;
    }
    String result = testcase.get("result").getAsString();
    TestResult.Type resultType;
    String comment = "";
    // Normally the test tries to encrypt and decrypt a ciphertext.
    // tryDecrypt is set to false if the result from encryption is serious enough,
    // so that trying to decrypt no longer makes sense.
    boolean tryDecrypt = true;
    AlgorithmParameterSpec fpeParameterSpec;
    try {
      fpeParameterSpec = algorithmParameters(radix, tweak);
    } catch (NoSuchAlgorithmException ex) {
      testResult.addFailure(TestResult.Type.REJECTED_ALGORITHM, algorithm);
      return;
    } catch (ReflectiveOperationException ex) {
      testResult.addFailure(TestResult.Type.WRONG_SETUP, ex.toString());
      return;
    }
    try {
      byte[] encrypted = encrypt(cipher, fpeParameterSpec, key, msg);
      boolean eq = Arrays.equals(ct, encrypted);
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
    } catch (GeneralSecurityException | IllegalArgumentException ex) {
      if (result.equals("valid")) {
        // Test vectors can be rejected because of the message size.
        resultType = TestResult.Type.REJECTED_ALGORITHM;
        tryDecrypt = false;
      } else {
        resultType = TestResult.Type.REJECTED_INVALID;
      }
    }

    if (tryDecrypt) {
      // Test decryption
      try {
        byte[] decrypted = decrypt(cipher, fpeParameterSpec, key, ct);
        boolean eq = Arrays.equals(decrypted, msg);
        if (result.equals("invalid")) {
          resultType = TestResult.Type.NOT_REJECTED_INVALID;
        } else if (!eq) {
          resultType = TestResult.Type.WRONG_RESULT;
          comment = "decrypted:" + TestUtil.bytesToHex(decrypted);
        } else {
          resultType = TestResult.Type.PASSED_VALID;
        }
      } catch (GeneralSecurityException | IllegalArgumentException ex) {
        comment = ex.toString();
        if (result.equals("valid")) {
          resultType = TestResult.Type.REJECTED_VALID;
        } else {
          resultType = TestResult.Type.REJECTED_INVALID;
        }
      }
    }
    testResult.addResult(tcid, resultType, comment);
  }

  /**
   * Checks each test vector in a file of test vectors.
   *
   * <p>This method is the part of testVerification that does not log any result. The main idea
   * behind splitting off this part from testVerification is that it may be easier to call from a
   * third party.
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
      int radix = group.get("radix").getAsInt();
      if (radix > 256) {
        // This is not implemented since messages use byte arrays.
        continue;
      }
      for (JsonElement t : group.getAsJsonArray("tests")) {
        JsonObject testcase = t.getAsJsonObject();
        singleTest(algorithm, radix, testcase, testResult);
      }
    }
    return testResult;
  }

  /**
   * Tests format preserving encryption against test vectors.
   *
   * <p>Example:
   *
   * <pre>
   * "algorithm" : "AES-FF1",
   * "generatorVersion" : "0.9rc5",
   * "numberOfTests" : 1852,
   * "header" : [
   *   "Test vectors of type FpeListTest are intended for format preserving encryption."
   * ],
   * "notes" : { ... },
   * "schema" : "fpe_list_test_schema.json",
   *  "testGroups" : [
   * {
   *   "keySize" : 128,
   *   "msgSize" : 0,
   *   "radix" : 85,
   *   "type" : "FpeListTest",
   *   "tests" : [
   *     {
   *       "tcId" : 1,
   *       "comment" : "Invalid message size",
   *       "flags" : [
   *         "InvalidMessageSize"
   *       ],
   *       "key" : "fb9fc869af3e4828da6efa18b5fa71a0",
   *       "tweak" : "379f81cab6ed2517",
   *       "msg" : [],
   *       "ct" : [],
   *       "result" : "invalid"
   *     }
   *   ]
   * },
   * </pre>
   *
   * @param filename the JSON file with the test vectors.
   * @throws AssumptionViolatedException when the test was skipped. This happens when the primitive
   *     or the radix is not supported.
   * @throws AssertionError when the test failed.
   * @throws IOException when the test vectors could not be read.
   */
  public void testFpe(String filename) throws IOException {
    // Testing with old test vectors may a reason for a test failure.
    // Version number have the format major.minor[status].
    // Versions before 1.0 are experimental and  use formats that are expected to change.
    // Versions after 1.0 change the major number if the format changes and change
    // the minor number if only the test vectors (but not the format) changes.
    // Versions meant for distribution have no status.
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

  @Test
  public void testAesFf1Radix10() throws Exception {
    testFpe("aes_ff1_radix10_test.json");
  }

  @NoPresubmitTest(
      providers = {ProviderType.BOUNCY_CASTLE},
      bugs = {"b/257491344"})
  @Test
  public void testAesFf1Radix16() throws Exception {
    testFpe("aes_ff1_radix16_test.json");
  }

  @Test
  public void testAesFf1Radix26() throws Exception {
    testFpe("aes_ff1_radix26_test.json");
  }

  @NoPresubmitTest(
      providers = {ProviderType.BOUNCY_CASTLE},
      bugs = {"b/257491344"})
  @Test
  public void testAesFf1Radix32() throws Exception {
    testFpe("aes_ff1_radix32_test.json");
  }

  @Test
  public void testAesFf1Radix36() throws Exception {
    testFpe("aes_ff1_radix36_test.json");
  }

  @Test
  public void testAesFf1Radix45() throws Exception {
    testFpe("aes_ff1_radix45_test.json");
  }

  @Test
  public void testAesFf1Radix62() throws Exception {
    testFpe("aes_ff1_radix62_test.json");
  }

  @Test
  public void testAesFf1Radix64() throws Exception {
    testFpe("aes_ff1_radix64_test.json");
  }

  @Test
  public void testAesFf1Radix85() throws Exception {
    testFpe("aes_ff1_radix85_test.json");
  }

  @Test
  public void testAesFf1Radix255() throws Exception {
    testFpe("aes_ff1_radix255_test.json");
  }

  @NoPresubmitTest(
      providers = {ProviderType.BOUNCY_CASTLE},
      bugs = {"b/257491344"})
  @Test
  public void testAesFf1Radix256() throws Exception {
    testFpe("aes_ff1_radix256_test.json");
  }
}
