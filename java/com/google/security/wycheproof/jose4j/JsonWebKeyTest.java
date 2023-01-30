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
import org.jose4j.jwk.JsonWebKeySet;
import org.jose4j.jwk.VerificationJwkSelector;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.lang.JoseException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameter;
import org.junit.runners.Parameterized.Parameters;

/**
 * Tests for <a href="https://tools.ietf.org/html/rfc7517">JSON Web Key RFC</a>
 *
 * <p>The test checks key validation in jose4j. For example the following issues
 * are tested:
 *
 * <ul>
 *   <li>The key size of RSA keys must be at least 2048 bits. Specified in RFC 7518
 *   <li>e must not be 1. This is totally insecure but did happend before (CVE-2011-4121)
 *   <li>It would be nice if ROCA keys were rejected.
 *   <li>The key size of HMAC keys must be at least as big as the HMAC digest.
 * </ul>
 */
@MediumTest
@RunWith(Parameterized.class)
public class JsonWebKeyTest {

  private static ImmutableSet<String> allTestNames;

  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  private ImmutableSet<String> getSuppressedTests() {
    return ImmutableSet.of(
        // jose.4.j doesn't care if you mix inappropriate keys.
        "jws_mixedSymmetryKeyset_rejectsValid_tcId1",
        // TODO(bleichen): determine if there is an expected behavior for keysets
        //   with duplicate keys.
        // RFC 7517 Section 4.5 defines kids. It says that kids should be distinct,
        // but that keysets with duplicate kids are acceptable if the keys can
        // be distinguished by "kty".
        // This test vector contains two keys with the same kid. The first key
        // is valid an verifies the MAC.
        "jws_duplicate_kid_rejectsDuplicateKid_tcId4",
        // jose.4.j does some simple key validation. For example it rejects
        // 1024 bit RSA keys and keys with public exponent e = 1.
        // This test vector contains an RSA key with the ROCA vulnerability.
        // Nothing checks for such weak keys during the verification process.
        "jws_rsa_roca_key_rejectsKeyWithRocaVulnerability_tcId7");
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
  public static List<Object[]> produceTestCases() throws Exception {
    JsonObject test = JsonUtil.getTestVectors("json_web_key_test.json");

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
  public void jsonWebKeyTestVector() {
    // Housekeeping to make sure the implementation class wires things correctly.
    assertThat(allTestNames).containsAtLeastElementsIn(getSuppressedTests());

    String privateJwk = testGroup.getAsJsonObject("private").toString();
    JsonObject publicJwk = testGroup.getAsJsonObject("public");
    String verificationJwk = publicJwk == null ? privateJwk : publicJwk.toString();

    String jws = getFlattenedString(testCase, "jws");
    boolean expectedResult = testCase.get("result").getAsString().equals("valid");
    boolean result = performKeysetVerification(jws, verificationJwk);

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
      verifier.setKey(usedVerificationKey.getKey());
      return verifier.verifySignature();
    } catch (Exception e) {
      logger.atInfo().withCause(e).log(
          "Verification was unsuccessful.\njws: %s\njwk: %s", compactJws, verificationKeyset);
      return false;
    }
  }
}
