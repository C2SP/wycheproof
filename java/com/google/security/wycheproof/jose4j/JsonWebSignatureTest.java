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
import java.util.ArrayList;
import java.util.List;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jws.JsonWebSignature;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameter;
import org.junit.runners.Parameterized.Parameters;

/** Tests for <a href="https://tools.ietf.org/html/rfc7515">JSON Web Signature RFC</a> */
@MediumTest
@RunWith(Parameterized.class)
public class JsonWebSignatureTest {

  private static ImmutableSet<String> allTestNames;

  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  private ImmutableSet<String> getSuppressedTests() {
    return ImmutableSet.of(
        // jose4j verifies signatures using the algorithm specified in the jws header.
        // The algorithm specified in the key is ignored.
        "ps512_UsingRS256_tcId332",
        "ps512_UsingRS384_tcId334",
        "ps512_UsingRS512_tcId336",
        "ps512_UsingPS256_tcId338",
        "ps512_UsingPS384_tcId340",
        // Signature verification with key that are restricted to "use": "enc"
        // or "key_ops": "encrypt" should fail.
        // The latest release of jose4j from Feb. 8 2023 adds more
        // restrictions. It appears that the following cases should be covered.
        "rsa_encryption_rejectWrongUse_tcId353",
        "ec_key_for_encryption_rejectWrongUse_tcId354",
        "rsa_encryption_rejectWrongKeyOps_tcId355",
        "ec_key_for_encryption_rejectWrongKeyOps_tcId356",
        // JWS requires that base64 encodings do not include white space and other
        // extra characters. However, JSON objects can include whitespace (see
        // Example 3.3 in RFC 7515).
        // There are several cases where jose4j accepts malformed base64 encodings.
        // One consequence of the bug is that jose4j suffers from signature
        // malleability: an attacker who is given a valid signature can generate
        // additional signatures for the same payload.
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
        "base64_MacOfIncorrectlyEncodedMessage_tcId375"
    );
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

  @Test
  public void jsonWebSignatureTestVector() {
    // Housekeeping to make sure the implementation class wires things correctly.
    assertThat(allTestNames).containsAtLeastElementsIn(getSuppressedTests());

    String privateJwk = testGroup.getAsJsonObject("private").toString();
    JsonObject publicJwk = testGroup.getAsJsonObject("public");

    String jws = testCase.get("jws").getAsString();
    boolean expectedResult = testCase.get("result").getAsString().equals("valid");

    // Verification is done with the public key if it exists (or the secret key if not).
    String verificationJwk = publicJwk == null ? privateJwk : publicJwk.toString();
    boolean result = performVerification(jws, verificationJwk);

    if (getSuppressedTests().contains(testName)) {
      // Inverting the assertion helps uncover tests that are needlessly suppressed.
      assertWithMessage("This test appears to be needlessly suppressed")
          .that(result)
          .isEqualTo(!expectedResult);
      // The test fails but is suppressed.
      TestUtil.skipTest("Suppressed test still fails");
    } else {
      assertThat(result).isEqualTo(expectedResult);
    }
  }

  /**
   * Returns whether or not the payload verifies with the given key.
   *
   * @param compactJws the signature or MAC in compact form
   * @param verificationJwk the verification key. This can either be a public key or a symmetric
   *     key.
   */
  public boolean performVerification(String compactJws, String verificationJwk) {
    JsonWebSignature verifier = new JsonWebSignature();

    try {
      verifier.setCompactSerialization(compactJws);
      JsonWebKey parsedKey = JsonWebKey.Factory.newJwk(verificationJwk);
      verifier.setKey(parsedKey.getKey());
      return verifier.verifySignature();
    } catch (Exception e) {
      logger.atInfo().withCause(e).log(
          "Verification was unsuccessful.\njws: %s\njwk: %s", compactJws, verificationJwk);
      return false;
    }
  }

}
