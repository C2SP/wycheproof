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
package com.google.security.wycheproof.nimbusjose;

import static com.google.common.truth.Truth.assertThat;
import static com.google.common.truth.Truth.assertWithMessage;

import com.google.common.collect.ImmutableSet;
import com.google.common.flogger.GoogleLogger;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.security.wycheproof.JsonUtil;
import com.google.security.wycheproof.TestUtil;
import com.google.testing.testsize.MediumTest;
import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEDecrypter;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.crypto.AESDecrypter;
import com.nimbusds.jose.crypto.DirectDecrypter;
import com.nimbusds.jose.crypto.ECDHDecrypter;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.jwk.JWK;
import java.security.NoSuchAlgorithmException;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameter;
import org.junit.runners.Parameterized.Parameters;

// TODO(bleichen): tests are incomplete
//    * add more test vectors for direct encryption
//    * there are no tests for timing differences when using padding attacks.
//    * nimbus-jose adds some nonstandard algorithms: secp256k1, ECDH-1PU, EDDSA

/** Tests for <a href="https://tools.ietf.org/html/rfc7516">JSON Web Encryption RFC</a>. */
@MediumTest
@RunWith(Parameterized.class)
public class NimbusJoseJweTest {

  private static ImmutableSet<String> allTestNames;

  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  private ImmutableSet<String> getSuppressedTests() {
    return ImmutableSet.of(
        // NimbusJose does not compare the algorithm in the header with the algorithm in the key.
        // As a result AES-GCM keys can be used with AES-KW and vice versa.
        "jwe_aes_GcmKeyUsedWithKw_tcId106",
        "jwe_aes_KwKeyUsedWithGcm_tcId107",
        "jwe_aes_GcmKeyUsedWithKw_tcId108",
        "jwe_aes_KwKeyUsedWithGcm_tcId109",
        // NimbusJose does not check the algorithm in RSA keys.
        // As a result it is possible to encrypt with RSA-PKCS #1 even if the key is an RSA-OAEP
        // key. Hence RSA-PKCS #1 oracles in the underlying provider would be exploitable.
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
   * Checks exceptions against padding attacks.
   *
   * <p>Checks if an exception deviates from the expected result. Test vectors with certain flags
   * have been constructed to check for padding oracles. For these test vectors we expect that the
   * library returns the same exceptions so that distinct padding errors are not distinguishable.
   * The current test runs each test vector individually. Hence it is not possible to collect all
   * test vectors thrown and compare them with each other. Eventually the test should be rewritten
   * to deal with this situation. Currently the exceptions thrown by jose4j are hard-coded into this
   * function. Hard coding the exceptions has the disadvantage that tests will fail with new
   * versions.
   *
   * @param ex the exceptions thrown for this test vector
   * @return false if an unexpected exception was thrown
   */
  private boolean checkException(Exception ex) {
    // Tests for PKCS #1 oracles.
    if (containsFlag(testCase, "ModifiedPkcs15Padding")) {
      // If the padding has been modified then NimbusJose typically throws one of the following
      // exceptions. If trying to decrypt a modified ciphertext throws another exception then
      // this may allow a PKCS #1 oracle.
      String[] expectedExceptionsPkcs15 =
          new String[] {
            // Exception thrown when using jdk11
            "com.nimbusds.jose.JOSEException: AES/GCM/NoPadding decryption failed: Tag mismatch!",
            // Exception thrown when unsing jdk20
            "com.nimbusds.jose.JOSEException: AES/GCM/NoPadding decryption failed: Tag mismatch",
          };
      return checkKnownException(ex, expectedExceptionsPkcs15);
    }
    // Tests for PKCS #5 padding oracles.
    // Ciphertexts with modified PKCS #5 paddings should not be distinguishable from
    // ciphertexts with valid PKCS #5 padding. The typical way to detect such modifications
    // is to check the HMAC before decrypting the ciphertext. Some libraries do decryption
    // and HMAC verification in the wrong order (see e.g., CVE-2021-29443)
    // Test test expects correct verification. Hence all test vectors with this flag should throw
    // "com.nimbusds.jose.JOSEException: MAC check failed" (or any other indistinguishable
    // exception in future versions).
    if (containsFlag(testCase, "Pkcs5Padding")) {
      String[] expectedExceptionsPkcs5 =
          new String[] {"com.nimbusds.jose.JOSEException: MAC check failed"};
      return checkKnownException(ex, expectedExceptionsPkcs5);
    }
    if (containsFlag(testCase, "Pkcs15WithOaepKey")) {
      // Test vectors with the flag "Pkcs15WithOaepKey" contain an OAEP key, but the header
      // of the ciphertext has been modified to contain "alg":"RSA1_5".
      // Decryption should notice the mismatch an throw an exception indicating the error.
      // The current implementation tries to decrypt using PKCS #1.5 padding.
      // Since the PKCS #1.5 decryption is broken, it is therefore also possible to break
      // ciphertexts when the receiver uses RSA-OAEP keys.
      //
      // The test expects to see an indistinguishable exception. The exception can of course
      // change between versions.
      String[] expectedExceptionsOaep =
          new String[] {
            // Exception thrown when using jdk11
            "com.nimbusds.jose.JOSEException: AES/GCM/NoPadding decryption failed: Tag mismatch!",
            // Exception thrown when unsing jdk20
            "com.nimbusds.jose.JOSEException: AES/GCM/NoPadding decryption failed: Tag mismatch",
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
   * Returns a decrypter for a given key.
   *
   * Generally it is a good practice to select the type of the decrypter based on the key type and
   * not select the decrypter based on the algorithm in the header, since in the later case type
   * confusion attacks may be more likely to succeed. Hence this method requires that the "alg"
   * field in the key is set (which is another good practice). All test vectors for this test
   * contain only keys with the "alg" field set. The motivation is that libraries should be
   * encouraged to reject ambiguous keys and that such a behavior should certainly not be
   * prevented with weak test cases.
   *
   * @param key the JWK for which a decrypter is constructed.
   * @return the decrypter
   * @throws NoSuchAlgorithmException if the algorithm in the key is missing or not supported.
   */
  private JWEDecrypter getDecrypter(JWK key) throws NoSuchAlgorithmException, JOSEException {
    Algorithm alg = key.getAlgorithm();
    if (alg == null) {
      // We assume that every key has the alg field set.
      throw new NoSuchAlgorithmException("Key has no algorithm");
    }
    switch (alg.getName()) {
      case "A128KW":
      case "A192KW":
      case "A256KW":
      case "A128GCMKW":
      case "A192GCMKW":
      case "A256GCMKW":
        return new AESDecrypter(key.toOctetSequenceKey());
      // direct encryption
      case "A128GCM":
      case "A192GCM":
      case "A256GCM":
      case "A128CBC-HS256":
      case "A192CBC-HS384":
      case "A256CBC-HS512":
        return new DirectDecrypter(key.toOctetSequenceKey());
      case "RSA1_5":
      case "RSA-OAEP":
      case "RSA-OAEP-256":
        return new RSADecrypter(key.toRSAKey());
      case "ECDH-ES":
      case "ECDH-ES+A128KW":
      case "ECDH-ES+A192KW":
      case "ECDH-ES+A256KW":
      case "ECDH-ES+A128GCMKW":
      case "ECDH-ES+A192GCMKW":
      case "ECDH-ES+A256GCMKW":
        return new ECDHDecrypter(key.toECKey());
      default:
        throw new NoSuchAlgorithmException(alg.getName());
    }
  }

  /**
   * Tries to decrypt a ciphertext
   *
   * @param compactJwe the ciphertext
   * @param decryptionJwk the decrypting key
   * @param expectedResult true if decryption should succeed, false otherwise
   * @param expectedPlaintext the expected plaintext in hexadecimal format if decryption succeeds.
   * @return true if the test passed, false if it failed.
   */
  public boolean performDecryption(
      String compactJwe, String decryptionJwk, boolean expectedResult, String expectedPlaintext) {
    try {
      JWEObject jwe = JWEObject.parse(compactJwe);
      JWK decryptionKey = JWK.parse(decryptionJwk);
      JWEDecrypter decrypter = getDecrypter(decryptionKey);
      jwe.decrypt(decrypter);
      String payload = TestUtil.bytesToHex(jwe.getPayload().toBytes());
      if (!expectedResult) {
        logger.atInfo().log(
            "Malformed ciphertext decrypted.\n"
                + "testName:%s\n"
                + "jwe: %s\n"
                + "jwk: %s\n"
                + "got:%s",
            testName, compactJwe, decryptionJwk, payload);
        return false;
      }
      if (payload.equals(expectedPlaintext)) {
        return true;
      }
      logger.atInfo().log(
          "Decryption returned wrong plaintext.\n"
              + "testName:%s\n"
              + "jwe: %s\n"
              + "jwk: %s\n"
              + "expected:%s\n"
              + "got:%s",
          testName, compactJwe, decryptionJwk, expectedPlaintext, payload);
      return false;
    } catch (ParseException | JOSEException e) {
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
    } catch (Exception e) {
      // Exceptions other than JOSEExceptions or ParseException are unexpected.
      // They can either be a misconfiguration of the test or a bug in Jose4j.
      logger.atInfo().withCause(e).log(
          "Unexpected exception.\ntestName:%s\njwe: %s\njwk: %s",
          testName, compactJwe, decryptionJwk);
      // This is always a test failure.
      return false;
    }
  }
}
