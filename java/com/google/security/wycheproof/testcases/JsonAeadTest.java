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
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** This test uses test vectors in JSON format to test AEAD schemes. */
@RunWith(JUnit4.class)
public class JsonAeadTest {


  /** Joins two bytearrays. */
  protected static byte[] join(byte[] head, byte[] tail) {
    byte[] res = new byte[head.length + tail.length];
    System.arraycopy(head, 0, res, 0, head.length);
    System.arraycopy(tail, 0, res, head.length, tail.length);
    return res;
  }

  /** Convenience method to get a byte array from an JsonObject */
  protected static byte[] getBytes(JsonObject obj, String name) {
    return JsonUtil.asByteArray(obj.get(name));
  }

  protected static Cipher getCipher(String algorithm)
      throws NoSuchAlgorithmException, NoSuchPaddingException {
    switch (algorithm) {
      case "AES-GCM":
        return Cipher.getInstance("AES/GCM/NoPadding");
      case "AES-GCM-SIV":
        // Tries the name used in Conscrypt
        return Cipher.getInstance("AES/GCM-SIV/NoPadding");
      case "AES-CCM":
        return Cipher.getInstance("AES/CCM/NoPadding");
      case "AES-EAX":
        return Cipher.getInstance("AES/EAX/NoPadding");
      case "CHACHA20-POLY1305":
        try {
          // Tries the algorithm name used by BouncyCastle
          return Cipher.getInstance("CHACHA20-POLY1305");
        } catch (GeneralSecurityException ex) {
          // Not found. Try the next known name.
        }
        try {
          // Tries the algorithm name used by Conscrypt
          return Cipher.getInstance("CHACHA20/POLY1305/NoPadding");
        } catch (GeneralSecurityException ex) {
          // Not found either.
        }
        break;
      case "XCHACHA20-POLY1305":
        // JDK-8256529
        try {
          // Tries the algorithm naming scheme used by BouncyCastle
          return Cipher.getInstance("XCHACHA20-POLY1305");
        } catch (GeneralSecurityException ex) {
          // Not found. Try the next known name.
        }
        try {
          // Tries the algorithm naming scheme used by other providers.
          return Cipher.getInstance("XCHACHA20/POLY1305/NoPadding");
        } catch (GeneralSecurityException ex) {
          // Not found either.
        }
        break;
      case "ARIA-GCM":
        // BouncyCastle also knows "ARIA-GCM"
        return Cipher.getInstance("ARIA/GCM/NoPadding");
      case "ARIA-CCM":
        return Cipher.getInstance("ARIA/CCM/NoPadding");
      case "CAMELLIA-CCM":
        return Cipher.getInstance("CAMELLIA/CCM/NoPadding");
      case "SEED-GCM":
        return Cipher.getInstance("SEED/GCM/NoPadding");
      case "SEED-CCM":
        return Cipher.getInstance("SEED/CCM/NoPadding");
      case "SM4-GCM":
        return Cipher.getInstance("SM4/GCM/NoPadding");
      case "SM4-CCM":
        return Cipher.getInstance("SM4/CCM/NoPadding");
      default:
        break;
    }
    throw new NoSuchAlgorithmException("No provider found for " + algorithm);
  }

  /**
   * Returns an initialized instance of Cipher.
   *
   * <p>This method tries to be as provider independent as possible. Unfortunately, this is not
   * always possible. One reason is that many ciphers require algorithm parameters and JCE does not
   * provide predefined classes for these parameters.
   *
   * @param algorithm the cipher algorithm from the test vector file.
   * @param opmode one of Cipher.ENCRYPT_MODE or Cipher.DECRYPT_MODE
   * @param key the key bytes
   * @param iv the bytes of the initialization vector
   * @param tagSize the expected size of the tag in bits
   * @return an initialized instance of Cipher
   * @throws NoSuchAlgorithmException if the algorithm is not supported.
   * @throws NoSuchPaddingException if the padding is not available
   * @throws InvalidKeyException if the key is invalid
   * @throws InvalidParameterException if the algorithm parameters are invalid or not supported.
   */
  protected static Cipher getInitializedCipher(
      String algorithm, int opmode, byte[] key, byte[] iv, int tagSize)
      throws GeneralSecurityException {
    Cipher cipher = getCipher(algorithm);
    SecretKeySpec keySpec;
    AlgorithmParameterSpec parameters;
    switch (algorithm) {
      case "AES-GCM":
        parameters = new GCMParameterSpec(tagSize, iv);
        keySpec = new SecretKeySpec(key, "AES");
        break;
      case "AES-CCM":
      case "AES-EAX":
        // Unfortunately there is no JCE ParameterSpec for CCM or EAX.
        // Some provider (e.g. BouncyCastle) reuse GCMParameterSpec for CCM and EAX, since these
        // encryption modes have the same algorithm parameters as GCM.
        // It is also possible to use provider dependent classes to specify the parameters.
        // (e.g, org.bouncycastle.crypto.params.AEADParameters)
        // However the use of such classes would add dependencies that we want to avoid.
        parameters = new GCMParameterSpec(tagSize, iv);
        keySpec = new SecretKeySpec(key, "AES");
        break;
      case "AES-GCM-SIV":
        keySpec = new SecretKeySpec(key, "AES");
        parameters = new IvParameterSpec(iv);
        break;
      case "CHACHA20-POLY1305":
        // also seen: new SecretKeySpec(key, "ChaCha20-Poly1305");
        keySpec = new SecretKeySpec(key, "ChaCha20");
        parameters = new IvParameterSpec(iv);
        break;
      case "XCHACHA20-POLY1305":
        keySpec = new SecretKeySpec(key, "XChaCha20");
        parameters = new IvParameterSpec(iv);
        break;
      case "ARIA-GCM":
      case "ARIA-CCM":
        parameters = new GCMParameterSpec(tagSize, iv);
        keySpec = new SecretKeySpec(key, "ARIA");
        break;
      case "CAMELLIA-CCM":
        parameters = new GCMParameterSpec(tagSize, iv);
        keySpec = new SecretKeySpec(key, "CAMELLIA");
        break;
      case "SEED-GCM":
      case "SEED-CCM":
        parameters = new GCMParameterSpec(tagSize, iv);
        keySpec = new SecretKeySpec(key, "SEED");
        break;
      case "SM4-GCM":
      case "SM4-CCM":
        parameters = new GCMParameterSpec(tagSize, iv);
        keySpec = new SecretKeySpec(key, "SM4");
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
   *   "algorithm" : "AES-EAX",
   *   "generatorVersion" : "0.0a14",
   *   "numberOfTests" : 143,
   *   "testGroups" : [
   *     {
   *       "ivSize" : 128,
   *       "keySize" : 128,
   *       "tagSize" : 128,
   *       "type" : "AES-EAX",
   *       "tests" : [
   *         {
   *           "aad" : "6bfb914fd07eae6b",
   *           "comment" : "eprint.iacr.org/2003/069",
   *           "ct" : "",
   *           "iv" : "62ec67f9c3a4a407fcb2a8c49031a8b3",
   *           "key" : "233952dee4d5ed5f9b9c6d6ff80ff478",
   *           "msg" : "",
   *           "result" : "valid",
   *           "tag" : "e037830e8389f27b025a2d6527e79d01",
   *           "tcId" : 1
   *         },
   *        ...
   * </pre>
   */
  private static void singleTest(
      String algorithm, int tagSize, JsonObject testcase, TestResult testResult) {
    int tcId = testcase.get("tcId").getAsInt();
    byte[] key = getBytes(testcase, "key");
    byte[] iv = getBytes(testcase, "iv");
    byte[] msg = getBytes(testcase, "msg");
    byte[] aad = getBytes(testcase, "aad");
    byte[] ciphertext = join(getBytes(testcase, "ct"), getBytes(testcase, "tag"));
    // Result is one of "valid", "invalid", "acceptable".
    // "valid" are test vectors with matching plaintext, ciphertext and tag.
    // "invalid" are test vectors with invalid parameters or invalid ciphertext and tag.
    // "acceptable" are test vectors with weak parameters or legacy formats.
    String result = testcase.get("result").getAsString();

    // Test encryption
    Cipher cipher;
    try {
      cipher = getInitializedCipher(algorithm, Cipher.ENCRYPT_MODE, key, iv, tagSize);
    } catch (GeneralSecurityException ex) {
      // Some libraries restrict key size, iv size and tag size.
      // Because of the initialization of the cipher might fail.
      testResult.addResult(tcId, TestResult.Type.REJECTED_ALGORITHM, ex.toString());
      return;
    }
    TestResult.Type resultType;
    String comment = "";
    // Normally the test tries to encrypt and decrypt a ciphertext.
    // tryDecrypt is set to false if the result from encryption is serious enough,
    // so that trying to decrypt no longer makes sense.
    boolean tryDecrypt = true;
    try {
      cipher.updateAAD(aad);
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
        Cipher decCipher = getInitializedCipher(algorithm, Cipher.DECRYPT_MODE, key, iv, tagSize);
        decCipher.updateAAD(aad);
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
      int tagSize = group.get("tagSize").getAsInt();
      for (JsonElement t : group.getAsJsonArray("tests")) {
        JsonObject testcase = t.getAsJsonObject();
        singleTest(algorithm, tagSize, testcase, testResult);
      }
    }
    return testResult;
  }

  /**
   * Tests AEAD ciphers against test vectors.
   *
   * @param filename the JSON file with the test vectors.
   * @throws AssumptionViolatedException when the test was skipped. This happens for example when
   *     the underlying cipher is not supported (or when the provider uses unusual algorithm names).
   * @throws AssertionError when the test failed.
   * @throws IOException when the test vectors could not be read.
   */
  public void testAead(String filename) throws Exception {
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
  public void testAesGcm() throws Exception {
    testAead("aes_gcm_test.json");
  }

  @Test
  public void testAesGcmSiv() throws Exception {
    testAead("aes_gcm_siv_test.json");
  }

  @Test
  public void testAesEax() throws Exception {
    testAead("aes_eax_test.json");
  }

  @Test
  public void testAesCcm() throws Exception {
    testAead("aes_ccm_test.json");
  }

  @Test
  public void testAriaGcm() throws Exception {
    testAead("aria_gcm_test.json");
  }

  @Test
  public void testAriaCcm() throws Exception {
    testAead("aria_ccm_test.json");
  }

  @Test
  public void testCamelliaCcm() throws Exception {
    testAead("camellia_ccm_test.json");
  }

  @Test
  public void testSeedGcm() throws Exception {
    testAead("seed_gcm_test.json");
  }

  @Test
  public void testSeedCcm() throws Exception {
    testAead("seed_ccm_test.json");
  }

  @Test
  public void testSm4Gcm() throws Exception {
    testAead("sm4_gcm_test.json");
  }

  @Test
  public void testSm4Ccm() throws Exception {
    testAead("sm4_ccm_test.json");
  }

  @Test
  public void testChaCha20Poly1305() throws Exception {
    testAead("chacha20_poly1305_test.json");
  }

  @Test
  public void testXChaCha20Poly1305() throws Exception {
    testAead("xchacha20_poly1305_test.json");
  }
}
