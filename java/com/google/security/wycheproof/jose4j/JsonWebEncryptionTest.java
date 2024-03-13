/**
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
package com.google.security.wycheproof.jose4j;

import static com.google.common.truth.Truth.assertThat;
import static com.google.common.truth.Truth.assertWithMessage;

import com.google.common.collect.ImmutableSet;
import com.google.common.flogger.GoogleLogger;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.security.wycheproof.JsonUtil;
import com.google.security.wycheproof.TestUtil;
import com.google.testing.testsize.MediumTest;
import java.security.Key;
import java.util.ArrayList;
import java.util.List;
import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.lang.JoseException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameter;
import org.junit.runners.Parameterized.Parameters;

/** Tests for <a href="https://tools.ietf.org/html/rfc7516">JSON Web Encryption RFC</a>. */
@MediumTest
@RunWith(Parameterized.class)
public class JsonWebEncryptionTest {

  private static ImmutableSet<String> allTestNames;

  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  private ImmutableSet<String> getSuppressedTests() {
    return ImmutableSet.of(
        // An AES key for one encryption mode is used with another encryption mode.
        // Using a key with an incorrect encryption mode is a mistake, but jose4j
        // nonetheless accepts such ciphertexts.
        "jwe_aes_GcmKeyUsedWithKw_tcId106",
        "jwe_aes_KwKeyUsedWithGcm_tcId107",
        "jwe_aes_GcmKeyUsedWithKw_tcId108",
        "jwe_aes_KwKeyUsedWithGcm_tcId109",
        // An RSA-OAEP key is used with PKCS #1 v1.5 padding. Such ciphertexts
        // should be rejected. jose4j accepts them. The problem with allowing
        // PKCS #1 v1.5 padding is that weaknesses in the implementation can
        // be exploited for an attack even if the key is an RSA-OAEP key.
        "jwe_rsa_oaep_OaepKeyUsedWithPkcs1_5_tcId110",
        "jwe_rsa_oaep_256_OaepKeyUsedWithPkcs1_5_tcId111");
  }

  /** A JsonWebCryptoTestGroup that contains key information and tests against those keys. */
  @Parameter(value = 0)
  public JsonObject testGroup;

  /** A JsonWebCryptoTestVector that contains a single test in this {@link #testGroup}. */
  @Parameter(value = 1)
  public JsonObject testCase;

  @Parameter(value = 2)
  public String testName;

  @Parameters(name = "{2}")
  public static Iterable<Object[]> produceTestCases() throws Exception {
    JsonObject test = JsonUtil.getTestVectors("json_web_encryption_test.json");

    // Generate test cases.
    List<Object[]> testParams = new ArrayList<>();
    ImmutableSet.Builder<String> testNames = ImmutableSet.builder();
    for (JsonElement testGroupElement : test.getAsJsonArray("testGroups")) {
      // Contains group-level configuration as well as all of the tests for this group.
      JsonObject testGroup = testGroupElement.getAsJsonObject();

      String groupComment = testGroup.get("comment").getAsString();
      for (JsonElement testsElement : testGroup.getAsJsonArray("tests")) {
        JsonObject testCase = testsElement.getAsJsonObject();

        int testId = testCase.get("tcId").getAsInt();
        String testComment = testCase.get("comment").getAsString();
        String testName = String.format("%s_%s_tcId%d", groupComment, testComment, testId);
        testParams.add(new Object[] {testGroup, testCase, testName});
        testNames.add(testName);
      }
    }

    allTestNames = testNames.build();
    return testParams;
  }


  private boolean checkKnownException(Exception ex, String[] expected) {
    String actual = ex.toString();
    for (String exception : expected) {
      if (exception.equals(actual)) {
        return true;
      }
    }
    return false;
  }

  /**
   * Checks exceptions agains padding attacks.
   *
   * Checks if an exception deviates from the expected result. Test vectors with
   * certain flags have been constructed to check for padding oracles. For these test
   * vectors we expect that the library returns the same exceptions so that distinct
   * padding errors are not distinguishable. The current test runs each test vector
   * individually. Hence it is not possible to collect all test vectors thrown and
   * compare them with each other. Eventually the test should be rewritten to deal
   * with this situation. Currently the exceptions thrown by jose4j are hard-coded
   * into this function. Hard coding the exceptions has the disadvantage that
   * tests will fail with new versions.
   *
   * @param ex the exceptions thrown for this test vector
   * @return false if an unexpected exception was thrown
   */
  private boolean checkException(Exception ex) {
    // Tests for PKCS #1 oracles.
    if (containsFlag(testCase, "ModifiedPkcs15Padding")) {
      // If the padding has been modified then jose4j typically throws one of the following
      // exceptions. If trying to decrypt a modified ciphertext throws another exception then
      // this may allow a PKCS #1 oracle.
      String[] expectedExceptionsPkcs15 =
          new String[] {
            // Exception thrown when using jdk11
            "org.jose4j.lang.JoseException: javax.crypto.AEADBadTagException: Tag mismatch!",
            // Exception thrown when unsing jdk20
            "org.jose4j.lang.JoseException: javax.crypto.AEADBadTagException: Tag mismatch"
          };
      return checkKnownException(ex, expectedExceptionsPkcs15);
    }
    // Tests for PKCS #5 padding oracles.
    // Ciphertexts with modified PKCS #5 paddings should not be distinguishable from
    // ciphertexts with valid PKCS #5 padding. The typical way to detect such modifications
    // is to check the HMAC before decrypting the ciphertext. Some libraries do decryption
    // and HMAC verification in the wrong order (see e.g., CVE-2021-29443)
    if (containsFlag(testCase, "Pkcs5Padding")) {
      // jose4j includes the tag into the error message.
      if (ex.toString().startsWith(
          "org.jose4j.lang.IntegrityException: Authentication tag check failed.")) {
        return true;
      }
    }
    if (containsFlag(testCase, "Pkcs15WithOaepKey")) {
        // Test vectors with the flag "Pkcs15WithOaepKey" contain an OAEP key, but the header
        // of the ciphertext has been modified to contain "alg":"RSA1_5".
        // Decryption should notice the mismatch an throw an exception indicating the error.
        // The current implementation tries to decrypt using PKCS #1.5 padding.
        // Since the PKCS #1.5 decryption is broken, it is therefore also possible to break
        // ciphertexts when the receiver uses RSA-OAEP keys.
        //
        // TODO(bleichen): expectedExceptionsOaep needs to be adjusted once the underlying bug has
        //   been fixed. Currently the following exceptions are being thrown:
        //   * org.jose4j.lang.JoseException: javax.crypto.AEADBadTagException: Tag mismatch!
        //     thrown when the ciphertext contains an invalid PKCS #1 padding
        //     or thrown when the ciphertext contains valid PKCS #1 padding and valid key size.
        //   * org.jose4j.lang.JoseException: Invalid key for AES/GCM/NoPadding
        //     thrown wehn the ciphertext contains a valid PKCS #1 v1.5 padding but an invalid key.
        //   The test currently expects that a random key is being generated when the padding is
        //   incorrect. Better would be to compare the algorithms in the key with the algorithm in
        //   the header and throw an exception before trying to decrypt.
        String[] expectedExceptionsOaep =
            new String[] {
              // Exception thrown when using jdk11
              "org.jose4j.lang.JoseException: javax.crypto.AEADBadTagException: Tag mismatch!",
              // Exception thrown when unsing jdk20
              "org.jose4j.lang.JoseException: javax.crypto.AEADBadTagException: Tag mismatch"
            };
        return checkKnownException(ex, expectedExceptionsOaep);
    }
    return true;
  }

  @Test
  public void jsonWebEncryptionTestVector() {
    // Housekeeping to make sure the implementation class wires things correctly.
    assertThat(allTestNames).containsAtLeastElementsIn(getSuppressedTests());

    String privateJwk = testGroup.getAsJsonObject("private").toString();
    String jwe = testCase.get("jwe").getAsString();
    boolean expectedResult = testCase.get("result").getAsString().equals("valid");

    String expectedPlaintextHex = expectedResult ? testCase.get("pt").getAsString() : "";
    boolean result = performDecryption(jwe, privateJwk, expectedResult, expectedPlaintextHex);
    if (getSuppressedTests().contains(testName)) {
      // Inverting the assertion helps uncover tests that are needlessly suppressed.
      assertWithMessage("This test appears to be needlessly suppressed").that(result).isFalse();
      // The test fails but is suppressed.
      TestUtil.skipTest("Suppressed test still fails");
    } else {
      assertThat(result).isTrue();
    }
  }

  private static boolean containsFlag(JsonObject testCase, String flag) {
    for (var flagTestCase : testCase.getAsJsonArray("flags")) {
      if (flag.equals(flagTestCase.getAsString())) {
        return true;
      }
    }
    return false;
  }

  /**
   * Tries to decrypt a ciphertext
   *
   * @param compactJwe the ciphertext
   * @param decryptionJwk the decrypting key
   * @param expectedResult true if encryption should pass, false otherwise
   * @param expectedPlaintext the expected plaintext in hexadecimal format if decryption succeeds.
   * @return true if the test passed, false if it failed.
   */
  public boolean performDecryption(
      String compactJwe, String decryptionJwk, boolean expectedResult, String expectedPlaintext) {
    JsonWebEncryption decrypter = new JsonWebEncryption();

    try {
      decrypter.setCompactSerialization(compactJwe);
      // jose.4.j blocks RSA1_5 by default.
      decrypter.setAlgorithmConstraints(AlgorithmConstraints.NO_CONSTRAINTS);
      JsonWebKey parsedKey = JsonWebKey.Factory.newJwk(decryptionJwk);
      Key key;
      if (parsedKey instanceof PublicJsonWebKey) {
        key = ((PublicJsonWebKey) parsedKey).getPrivateKey();
      } else {
        key = parsedKey.getKey();
      }
      decrypter.setKey(key);
      String ptHex = TestUtil.bytesToHex(decrypter.getPlaintextBytes());
      if (ptHex.equals(expectedPlaintext)) {
        return true;
      }
      logger.atInfo().log(
          "Decryption returned wrong plaintext.\n"
              + "testName:%s\n"
              + "jwe: %s\n"
              + "jwk: %s\n"
              + "expected:%s\n"
              + "got:%s",
          testName, compactJwe, decryptionJwk, expectedPlaintext, ptHex);
      return false;
    } catch (JoseException e) {
      if (!checkException(e)) {
        logger.atInfo().withCause(e).log(
            "Decryption contains a padding oracle.\ntestName:%s\njwe: %s\njwk: %s",
            testName, compactJwe, decryptionJwk);
         return false;
      }
      // Prints stack trace if decryption is expected to succeed, doesn't print the stack trace if
      // decryption is expected to fail.
      if (expectedResult) {
        logger.atInfo().withCause(e).log(
            "Decryption was unsuccessful.\ntestName:%s\njwe: %s\njwk: %s",
            testName, compactJwe, decryptionJwk);
        return false;
      }
      // NOTE(bleichen): Even though an exception is expected here it may still be interesting
      //   to compare the actual exception with the expected exception to find more subtle
      //   problems. Logging the full stack trace would add too much clutter to the logs.
      logger.atInfo().log("Decryption failed as expected. testName: %s with %s", testName, e);
      return true;
    } catch (RuntimeException e) {
      // Exceptions other than JoseExceptions are unexpected.
      // They can either be a misconfiguration of the test or a bug in Jose4j.
      logger.atInfo().withCause(e).log(
          "Unexpected exception.\ntestName:%s\njwe: %s\njwk: %s",
          testName, compactJwe, decryptionJwk);
      // This is always a test failure.
      return false;
    }
  }
}
