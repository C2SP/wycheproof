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
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
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

/** Tests for <a href="https://tools.ietf.org/html/rfc7515">JSON Web Signature RFC</a> */
@MediumTest
@RunWith(Parameterized.class)
public class NimbusJoseJwsTest {

  private static ImmutableSet<String> allTestNames;

  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  private ImmutableSet<String> getSuppressedTests() {
    return ImmutableSet.of(
        // The following test vectors contain cases where the key contains an algorithm
        // different from the algorithm used for the actual signature. Such signatures
        // should be rejected. NimbusJose does not compare the algorithms and accepts
        // the signatures.
        "ps512_UsingRS256_tcId332",
        "ps512_UsingRS384_tcId334",
        "ps512_UsingRS512_tcId336",
        "ps512_UsingPS256_tcId338",
        "ps512_UsingPS384_tcId340",
        // RFC 7515, Section 5.2 appears to specify that white space and characters other than
        // the base64 characters are not allowed in the base64 encoding.
        // (Note that white space is explicitly allowed in the JSON encoding).
        // The following test vectors contain white space and other invalid characters in the
        // base64 encoding:
        "base64_rejectsSpacesInMac_tcId360",
        "base64_rejectsInvalidCharacterInsertedInMac_tcId361",
        "base64_rejectsInvalidCharacterInsertedInMac_tcId362",
        "base64_spacesInHeader_tcId365",
        "base64_invalidCharactersInHeader_tcId366",
        "base64_invalidBase64Padding_tcId367",
        "base64_spacesInPayload_tcId368",
        "base64_invalidCharactersInPayload_tcId369",
        "base64_invalidBase64PaddingInPayload_tcId370",
        "base64_InvalidCharacterInPayload_tcId371",
        "base64_InvalidCharacterInsertedInHeader_tcId372",
        "base64_InvalidCharacterInsertedInPayload_tcId373",
        "base64_MacOfIncorrectlyEncodedMessage_tcId375");
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
    JsonObject test = JsonUtil.getTestVectors("json_web_signature_test.json");

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

  private JWSVerifier getVerifier(JWK key) throws JOSEException, NoSuchAlgorithmException {
    Algorithm alg = key.getAlgorithm();
    if (alg == null) {
      // This code requires verification key algorithm to create algorithm specific verifiers.
      throw new NoSuchAlgorithmException("Verification key has no algorithm");
    }
    switch (alg.getName()) {
      case "HS256":
      case "HS384":
      case "HS512":
        return new MACVerifier(key.toOctetSequenceKey());
      case "ES256":
      case "ES384":
      case "ES521":
        return new ECDSAVerifier(key.toECKey());
      case "RS256":
      case "RS384":
      case "RS512":
      case "PS256":
      case "PS384":
      case "PS512":
        return new RSASSAVerifier(key.toRSAKey());
      default:
        throw new NoSuchAlgorithmException(alg.getName());
    }
  }

  @Test
  public void jsonWebSignatureTestVector() {
    // Housekeeping to make sure the implementation class wires things correctly.
    assertThat(allTestNames).containsAtLeastElementsIn(getSuppressedTests());

    // Verification is done with the public key if it exists (or the secret key if not).
    String verificationJwk;
    if (testGroup.has("public")) {
      verificationJwk = testGroup.getAsJsonObject("public").toString();
    } else {
      verificationJwk = testGroup.getAsJsonObject("private").toString();
    }
    String jws = testCase.get("jws").getAsString();
    boolean expectedResult = testCase.get("result").getAsString().equals("valid");
    boolean passed = performVerification(jws, verificationJwk, expectedResult);

    if (getSuppressedTests().contains(testName)) {
      if (passed) {
        // Inverting the assertion helps uncover tests that are needlessly suppressed.
        assertWithMessage("This test appears to be needlessly suppressed").fail();
      } else {
        // The test fails but is suppressed.
        TestUtil.skipTest("Suppressed test still fails");
      }
    } else {
      assertThat(passed).isTrue();
    }
  }

  /**
   * Performs a verification of a payload with the given key.
   *
   * @param compactJws the signature or MAC in compact form
   * @param verificationJwk the verification key. This can either be a public key or a symmetric
   *     key.
   * @param expectedResult true if the signature or MAC are valid
   * @return true if the test passed.
   */
  public boolean performVerification(
      String compactJws, String verificationJwk, boolean expectedResult) {
    try {
      JWSObject jws = JWSObject.parse(compactJws);
      JWK key = JWK.parse(verificationJwk);
      JWSVerifier verifier = getVerifier(key);
      return expectedResult == jws.verify(verifier);
      // The following exceptions are expected:
      // java.text.ParseException: for example if the header is not proper JSON.
      // com.nimbusds.jose.JOSEException: thrown by Nimbus-Jose.
      // java.security.NoSuchAlgorithmException: thrown by the test for unsupported algorithms.
    } catch (ParseException | JOSEException | NoSuchAlgorithmException e) {
      if (expectedResult) {
        logger.atInfo().withCause(e).log(
            "Verification failed for %s.\njws: %s\njwk: %s", testName, compactJws, verificationJwk);
        return false;
      } else {
        // Verification failed as expected. We still want to see the exception,
        // but not the stack trace.
        logger.atInfo().log("Verification failed as excpected for %s.\nwith %s", testName, e);
        return true;
      }
    } catch (RuntimeException e) {
      logger.atInfo().withCause(e).log(
          "Verification failed with unexpected exception for %s.\njws: %s\njwk: %s",
          testName, compactJws, verificationJwk);
      // We expect that the library checks for malformed input and throws a
      // checked exception. Getting anything other than the documented exceptions
      // is always a failure.
      return false;
    }
  }
}
