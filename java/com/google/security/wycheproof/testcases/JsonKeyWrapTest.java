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
import com.google.security.wycheproof.WycheproofRunner.NoPresubmitTest;
import com.google.security.wycheproof.WycheproofRunner.ProviderType;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * This test uses test vectors in JSON format to test key wrapping.
 *
 * <p>This test is mainly for key wrappings such as RFC 3349 and RFC 5469. I.e. these algorithms
 * have the following properties:
 *
 * <ul>
 *   <li>The wrapping is deterministic. Hence wrapping can be compared against known results.
 *   <li>The wrapping has an integrity check. Modified wrapped keys can be detected with high
 *       probability.
 * </ul>
 *
 * <p>References:
 *
 * <ul>
 *   <li>RFC 3394 defines the key wrap algorithm for AES.
 *   <li>RFC 5649 defines the key wrap algroithm with padding for AES.
 *   <li>NIST SP 800-38F also define key wrap and key wrap with padding for AES. This document also
 *       includes similar algorithms for Triple DES. (However, triple DES not tested here.)
 *   <li>RFC 3657 generalizes RFC 3394 to Camellia. There is no version with padding.
 *   <li>RFC 4010 generalizes RFC 3394 to SEED.
 *   <li>RFC 5794 generalizes KW and KWP to ARIA.
 * </ul>
 *
 * <p><b>Algorithm names</b>: Unfortunately, the algorithm names for the various key wrapping
 * algorithms differ by provider. The code uses the algorithm names proposed by Oracle
 * https://docs.oracle.com/en/java/javase/17/docs/specs/security/standard-names.html . I.e., the
 * proposed algorithm names are "AESWrap" and "AESWrapPad". Alternative names are:
 *
 * <ul>
 *   <li>OpenJdk also allows names with explicit key size (e.g. "AESWrap_128" or "AESWrapPad_128"
 *       etc.).
 *   <li>JDK-8261910 added the algorithm modes "KW" and "KWP". Hence "AES/KW/NoPadding" and
 *       "AES/KWP/NoPadding" are options. This change also added "AES/KW/Pkcs5Padding". This
 *       algorithm is not tested here.
 *   <li>BouncyCastle knows "AESWRAP" and "AESWRAPPAD". Alternatively, the algorithm name
 *       AESRFC5649WRAP is possible. AESRFC3211WRAP is an unrelated algorithm not tested here.
 *       BouncyCastle also implements key wrappings using Aria, Camellia and Seed. (There are also
 *       implementations using RC2 and DesEDE. These are not tested here.)
 *   <li>IAIK allows algorithm names such as "AESWrap/ECB/RFC5649Padding" and "AESWrapWithPadding".
 *       https://javadoc.iaik.tugraz.at/iaik_jce/current/iaik/security/cipher/AESKeyWrap.html
 *   <li>Other names that can be found are "AESWrap/ECB/ZeroPadding" or AESWrap/ECB/PKCS5Padding.
 * </ul>
 *
 * The algorithm names used in the test vectors Are <cipher>-WRAP and <cipher>-KWP.
 */
@RunWith(JUnit4.class)
public class JsonKeyWrapTest {

  /** Convenience method to get a byte array from a JsonObject. */
  protected static byte[] getBytes(JsonObject object, String name) {
    return JsonUtil.asByteArray(object.get(name));
  }

  protected static Cipher getCipher(String algorithm)
      throws NoSuchAlgorithmException, NoSuchPaddingException {
    switch (algorithm) {
      case "AES-WRAP":
        try {
          return Cipher.getInstance("AESWRAP");
        } catch (NoSuchAlgorithmException ex) {
          // AESWRAP is not known, but the encryption mode KW might be supported.
        }
        return Cipher.getInstance("AES/KW/NoPadding");
      case "AES-KWP":
        try {
          return Cipher.getInstance("AESWRAPPAD");
        } catch (NoSuchAlgorithmException ex) {
          // AESWRAPPAD is not known, but the encryption mode KWP might be supported.
        }
        return Cipher.getInstance("AES/KWP/NoPadding");
      case "ARIA-WRAP":
        return Cipher.getInstance("ARIAWRAP");
      case "ARIA-KWP":
        return Cipher.getInstance("ARIAWRAPPAD");
      case "CAMELLIA-WRAP":
        return Cipher.getInstance("CAMELLIAWRAP");
      case "SEED-WRAP":
        return Cipher.getInstance("SEEDWRAP");
      default:
        throw new NoSuchAlgorithmException(algorithm);
    }
  }

  protected static SecretKeySpec getSecretKeySpec(String algorithm, byte[] key)
      throws InvalidKeyException, NoSuchAlgorithmException {
    try {
      switch (algorithm) {
        case "AES-WRAP":
        case "AES-KWP":
          return new SecretKeySpec(key, "AES");
        case "ARIA-WRAP":
        case "ARIA-KWP":
          return new SecretKeySpec(key, "ARIA");
        case "CAMELLIA-WRAP":
          return new SecretKeySpec(key, "CAMELLIA");
        case "SEED-WRAP":
          return new SecretKeySpec(key, "SEED");
        default:
          throw new NoSuchAlgorithmException(algorithm);
      }
    } catch (IllegalArgumentException ex) {
      // IllegalArgumentException is thrown by SecretKeySpec if the key has size 0.
      // The code below assumes that it is a GeneralSecurityException.
      throw new InvalidKeyException(ex);
    }
  }

  /**
   * Generates a SecretKeySpec for key.
   *
   * <p>This function returns a SecretKeySpec for a given raw key.
   *
   * @param wrappedAlgorithm the algorithm of the key to wrap.
   * @param key the bytes to wrap
   * @return a secret key whose encoding is equal to key.
   * @throws InvalidKeyException if a no SecretkeySpec could be generated. This should only happend
   *     when key is empty.
   */
  protected static SecretKeySpec getKeyToWrap(String wrappedAlgorithm, byte[] key)
      throws InvalidKeyException {
    try {
      return new SecretKeySpec(key, wrappedAlgorithm);
    } catch (IllegalArgumentException ex) {
      throw new InvalidKeyException(ex);
    }
  }

  private static void singleTest(String algorithm, JsonObject testcase, TestResult testResult)
      throws Exception {
    int tcId = testcase.get("tcId").getAsInt();
    byte[] key = getBytes(testcase, "key");
    byte[] data = getBytes(testcase, "msg");
    byte[] expected = getBytes(testcase, "ct");
    // Result is one of "valid", "invalid", "acceptable".
    // "valid" are test vectors with matching plaintext, ciphertext and tag.
    // "invalid" are test vectors with invalid parameters or invalid ciphertext and tag.
    // "acceptable" are test vectors with weak parameters or legacy formats.
    String result = testcase.get("result").getAsString();
    boolean tryUnwrap = true;
    TestResult.Type resultType;
    String comment = "";
    // The algorithm of the wrapped key. This algorithm is not very important since it is not
    // included in the encoding. HMACSHA256 is used here, because HMAC allows arbitrary key
    // sizes and is a widely implemented algorithm.
    final String wrappedAlgorithm = "HMACSHA256";

    Cipher cipher;
    try {
      cipher = getCipher(algorithm);
    } catch (NoSuchAlgorithmException ex) {
      testResult.addResult(tcId, TestResult.Type.REJECTED_ALGORITHM, ex.toString());
      return;
    }
    SecretKeySpec keySpec;
    try {
      keySpec = getSecretKeySpec(algorithm, key);
    } catch (InvalidKeyException ex) {
      testResult.addResult(tcId, TestResult.Type.REJECTED_ALGORITHM, ex.toString());
      return;
    }
    try {
      cipher.init(Cipher.WRAP_MODE, keySpec);
      SecretKeySpec keyToWrap = getKeyToWrap(wrappedAlgorithm, data);
      byte[] wrapped = cipher.wrap(keyToWrap);
      boolean eq = Arrays.equals(expected, wrapped);
      if (result.equals("invalid")) {
        if (eq) {
          // Some test vectors use invalid inputs that should be rejected.
          // E.g., AES-KW only allows to wrap inputs with a size that is a multiple of 8 bytes.
          resultType = TestResult.Type.NOT_REJECTED_INVALID;
          tryUnwrap = false;
        } else {
          // Invalid test vectors frequently have invalid paddings.
          // Hence encryption just gives a different result.
          resultType = TestResult.Type.REJECTED_INVALID;
        }
      } else {
        if (!eq) {
          // If wrapping returns the wrong result then something is broken.
          // Hence we can stop here.
          resultType = TestResult.Type.WRONG_RESULT;
          comment = "wrapped: " + TestUtil.bytesToHex(wrapped);
          tryUnwrap = false;
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
    } catch (RuntimeException ex) {
      resultType = TestResult.Type.WRONG_EXCEPTION;
      comment = ex.toString();
      tryUnwrap = false;
    }

    if (tryUnwrap) {
      try {
        cipher.init(Cipher.UNWRAP_MODE, keySpec);
        Key wrappedKey = cipher.unwrap(expected, wrappedAlgorithm, Cipher.SECRET_KEY);
        byte[] unwrapped = wrappedKey.getEncoded();
        boolean eq = Arrays.equals(data, unwrapped);

        if (result.equals("invalid")) {
          resultType = TestResult.Type.NOT_REJECTED_INVALID;
        } else if (!eq) {
          resultType = TestResult.Type.WRONG_RESULT;
          comment = "unwrapped:" + TestUtil.bytesToHex(unwrapped);
        } else {
          resultType = TestResult.Type.PASSED_VALID;
        }
      } catch (GeneralSecurityException | IllegalArgumentException ex) {
        // The test currently accepts an IllegalArgumentException.
        // This is done, because
        comment = ex.toString();
        if (result.equals("valid")) {
          resultType = TestResult.Type.REJECTED_VALID;
        } else {
          resultType = TestResult.Type.REJECTED_INVALID;
        }
      } catch (RuntimeException ex) {
        resultType = TestResult.Type.WRONG_EXCEPTION;
        comment = ex.toString();
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
  public static TestResult allTests(TestVectors testVectors) throws Exception {
    var testResult = new TestResult(testVectors);
    JsonObject test = testVectors.getTest();
    String algorithm = test.get("algorithm").getAsString();
    try {
      Cipher unused = getCipher(algorithm);
    } catch (NoSuchAlgorithmException ex) {
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
    return testResult;
  }

  public void testKeywrap(String filename) throws Exception {
    JsonObject test = JsonUtil.getTestVectorsV1(filename);
    TestVectors testVectors = new TestVectors(test, filename);
    TestResult testResult = allTests(testVectors);

    if (testResult.skipTest()) {
      TestUtil.skipTest("No valid test passed");
      return;
    }
    System.out.print(testResult.asString());
    assertEquals(0, testResult.errors());
  }

  // BouncyCastle 1.71 incorrectly wraps keys of size 8.
  // Such keys should either not be wrapped (NIST) or they should be wrapped using
  // a single encryption with AES.
  @NoPresubmitTest(
      providers = {ProviderType.BOUNCY_CASTLE},
      bugs = {"b/77572633"})
  @Test
  public void testAesWrap() throws Exception {
    testKeywrap("aes_wrap_test.json");
  }

  @Test
  public void testAesKwp() throws Exception {
    testKeywrap("aes_kwp_test.json");
  }

  @NoPresubmitTest(
      providers = {ProviderType.BOUNCY_CASTLE},
      bugs = {"b/77572633"})
  @Test
  public void testAriaWrap() throws Exception {
    testKeywrap("aria_wrap_test.json");
  }

  @Test
  public void testAriaKwp() throws Exception {
    testKeywrap("aria_kwp_test.json");
  }

  @NoPresubmitTest(
      providers = {ProviderType.BOUNCY_CASTLE},
      bugs = {"b/77572633"})
  @Test
  public void testCamelliaWrap() throws Exception {
    testKeywrap("camellia_wrap_test.json");
  }

  @NoPresubmitTest(
      providers = {ProviderType.BOUNCY_CASTLE},
      bugs = {"b/77572633"})
  @Test
  public void testSeedWrap() throws Exception {
    testKeywrap("seed_wrap_test.json");
  }
}
