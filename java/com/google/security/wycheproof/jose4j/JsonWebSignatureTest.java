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
import com.google.common.collect.Iterables;
import com.google.common.flogger.GoogleLogger;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.security.wycheproof.JsonUtil;
import com.google.security.wycheproof.TestUtil;
import com.google.testing.testsize.MediumTest;
import java.util.ArrayList;
import java.util.List;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.JsonWebKeySet;
import org.jose4j.jwk.VerificationJwkSelector;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.lang.JoseException;
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
        "ec_key_for_encryption_rejectWrongKeyOps_tcId356"
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

    String jws = getFlattenedString(testCase, "jws");
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

  /** Reads the JWS/JWE field either in compact or JSON serialization form. */
  private static String getFlattenedString(JsonObject jsonObject, String fieldName) {
    JsonElement element = jsonObject.get(fieldName);
    if (element.isJsonPrimitive()) {
      // This is a compact representation of the JWE/JWS.
      return element.getAsString();
    }
    // This is a JSON representation of the JWE/JWS.
    return element.toString();
  }

  /** Adds keys to a JSON Web Keyset. */
  private static String addToKeyset(String keys) {
    String keysetTemplate = "{\"keys\": [%s]}";
    return String.format(keysetTemplate, keys);
  }

  /**
   * Returns whether or not the payload verifies with any of the given keys.
   *
   * @implNote this method shouldn't allow any exceptions that indicate unverifiable payloads to
   *     escape. Instead, the implementation should catch any such exceptions and return false
   */
  public boolean performKeysetVerification(String compactJws, String verificationKeyset) {
    JsonWebSignature verifier = new JsonWebSignature();

    try {
      verifier.setCompactSerialization(compactJws);
      JsonWebKeySet parsedKeyset = new JsonWebKeySet(verificationKeyset);

      VerificationJwkSelector jwkSelector = new VerificationJwkSelector();
      JsonWebKey usedVerificationKey;
      try {
        usedVerificationKey = jwkSelector.select(verifier, parsedKeyset.getJsonWebKeys());
      } catch (JoseException e) {
        throw new SecurityException("Verification key selection failed", e);
      }
      if (usedVerificationKey == null) {
        // The key selector would have caused this to fail but let's pretend we weren't using it.
        // This code isn't set up to work with keysets that don't select a key (so throw).
        usedVerificationKey = Iterables.getOnlyElement(parsedKeyset.getJsonWebKeys());
      }

      verifier.setKey(usedVerificationKey.getKey());
      return verifier.verifySignature();
    } catch (Exception e) {
      logger.atInfo().withCause(e).log(
          "Verification was unsuccessful.\njws: %s\njwk: %s", compactJws, verificationKeyset);
      return false;
    }
  }

  /**
   * Returns whether or not the payload verifies with the given key.
   *
   * @implNote this method shouldn't allow any exceptions that indicate unverifiable payloads to
   *     escape. Instead, the implementation should catch any such exceptions and return false
   * @implNote this method is implemented by deferring to {@link #performKeysetVerification} (with a
   *     1-element keyset)
   */
  public boolean performVerification(String compactJws, String verificationJwk) {
    return performKeysetVerification(compactJws, addToKeyset(verificationJwk));
  }
}
